use crate::identity::{did_key_to_bytes, IdentityError, LocalIdentity};
use chaperone_protocol::handshake as proto_handshake;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use hkdf::Hkdf;
use sha2::Sha256;
use std::error::Error;
use std::fmt;
use x25519_dalek::{PublicKey, StaticSecret};

pub type SessionKey = [u8; 32];

#[derive(Debug, Clone)]
pub enum HandshakeError {
    InvalidSignature,
    IdentityError(IdentityError),
    SerializationError(String),
    Other(String),
}

impl fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSignature => write!(f, "Invalid signed prekey signature"),
            Self::IdentityError(e) => write!(f, "Identity error: {}", e),
            Self::SerializationError(msg) => write!(f, "Serialization error: {}", msg),
            Self::Other(msg) => write!(f, "Handshake error: {}", msg),
        }
    }
}

impl Error for HandshakeError {}

impl From<IdentityError> for HandshakeError {
    fn from(e: IdentityError) -> Self {
        Self::IdentityError(e)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakeInit {
    pub identity_key: [u8; 32], // X25519 public
    pub signed_prekey: [u8; 32],
    pub signed_prekey_sig: [u8; 64], // Ed25519 signature over signed_prekey, using Bob's signing key
    pub ephemeral_key: [u8; 32],
}

impl TryFrom<proto_handshake::HandshakeInit> for HandshakeInit {
    type Error = HandshakeError;

    fn try_from(proto: proto_handshake::HandshakeInit) -> Result<Self, Self::Error> {
        let identity_key = proto.identity_key.try_into().map_err(|_| {
            HandshakeError::SerializationError("Invalid identity_key length".to_string())
        })?;
        let signed_prekey = proto.signed_prekey.try_into().map_err(|_| {
            HandshakeError::SerializationError("Invalid signed_prekey length".to_string())
        })?;
        let signed_prekey_sig = proto.signed_prekey_sig.try_into().map_err(|_| {
            HandshakeError::SerializationError("Invalid signed_prekey_sig length".to_string())
        })?;
        let ephemeral_key = proto.ephemeral_key.try_into().map_err(|_| {
            HandshakeError::SerializationError("Invalid ephemeral_key length".to_string())
        })?;

        Ok(Self {
            identity_key,
            signed_prekey,
            signed_prekey_sig,
            ephemeral_key,
        })
    }
}

impl From<HandshakeInit> for proto_handshake::HandshakeInit {
    fn from(core: HandshakeInit) -> Self {
        Self {
            identity_key: core.identity_key.to_vec(),
            signed_prekey: core.signed_prekey.to_vec(),
            signed_prekey_sig: core.signed_prekey_sig.to_vec(),
            ephemeral_key: core.ephemeral_key.to_vec(),
        }
    }
}

/// Initiates a classical X3DH-style key agreement with a remote party.
///
/// Computes:
/// - DH1 = DH(IK_A, SPK_B)
/// - DH2 = DH(EK_A, IK_B)
/// - DH3 = DH(EK_A, SPK_B)
///
/// Then combines these shared secrets via HKDF-SHA256.
pub fn initiate(
    local: &LocalIdentity,
    remote_identity_key: [u8; 32],
    remote_signed_prekey: [u8; 32],
) -> (HandshakeInit, SessionKey) {
    let local_priv_ik = local
        .load_agreement_key()
        .expect("Failed to load local identity agreement key");
    let local_pub_ik = PublicKey::from(&local_priv_ik);
    let local_pub_ik_bytes = local_pub_ik.to_bytes();

    // Generate ephemeral key pair
    let mut ephemeral_entropy = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut ephemeral_entropy);
    let ephemeral_secret = StaticSecret::from(ephemeral_entropy);
    let ephemeral_pub = PublicKey::from(&ephemeral_secret);
    let ephemeral_pub_bytes = ephemeral_pub.to_bytes();

    // Prepare public keys for DH
    let remote_ik_pub = PublicKey::from(remote_identity_key);
    let remote_spk_pub = PublicKey::from(remote_signed_prekey);

    // Compute DH operations
    let dh1 = local_priv_ik.diffie_hellman(&remote_spk_pub);
    let dh2 = ephemeral_secret.diffie_hellman(&remote_ik_pub);
    let dh3 = ephemeral_secret.diffie_hellman(&remote_spk_pub);

    // Combine via HKDF-SHA256
    let mut ikm = [0u8; 96];
    ikm[0..32].copy_from_slice(dh1.as_bytes());
    ikm[32..64].copy_from_slice(dh2.as_bytes());
    ikm[64..96].copy_from_slice(dh3.as_bytes());

    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut session_key = [0u8; 32];
    hk.expand(b"chaperone-x3dh-session-key", &mut session_key)
        .expect("HKDF expansion is guaranteed to succeed for 32-byte output");

    let init = HandshakeInit {
        identity_key: local_pub_ik_bytes,
        signed_prekey: remote_signed_prekey,
        signed_prekey_sig: [0u8; 64], // Set to zero; caller will populate from B's prekey bundle
        ephemeral_key: ephemeral_pub_bytes,
    };

    (init, session_key)
}

/// Responds to a classical X3DH-style key agreement.
///
/// Verifies the signature on the prekey, then computes:
/// - DH1 = DH(SPK_B, IK_A)
/// - DH2 = DH(IK_B, EK_A)
/// - DH3 = DH(SPK_B, EK_A)
///
/// Then derives the identical SessionKey.
pub fn respond(local: &LocalIdentity, init: &HandshakeInit) -> Result<SessionKey, HandshakeError> {
    // 1. Verify the signature on B's signed prekey using B's public signing key.
    // B's public signing key is parsed from Bob's local.did_key.
    let signing_pubkey_bytes = did_key_to_bytes(&local.did_key)?;
    let verifying_key = VerifyingKey::from_bytes(&signing_pubkey_bytes)
        .map_err(|e| HandshakeError::Other(e.to_string()))?;

    let signature = Signature::from_bytes(&init.signed_prekey_sig);
    verifying_key
        .verify(&init.signed_prekey, &signature)
        .map_err(|_| HandshakeError::InvalidSignature)?;

    // 2. Load private agreement key (IK_B) and private prekey (SPK_B).
    let local_priv_ik = local.load_agreement_key()?;
    let local_priv_spk = local.load_signed_prekey()?;

    // Prepare Alice's public keys
    let alice_pub_ik = PublicKey::from(init.identity_key);
    let alice_pub_ek = PublicKey::from(init.ephemeral_key);

    // Compute DH operations
    let dh1 = local_priv_spk.diffie_hellman(&alice_pub_ik);
    let dh2 = local_priv_ik.diffie_hellman(&alice_pub_ek);
    let dh3 = local_priv_spk.diffie_hellman(&alice_pub_ek);

    // Combine via HKDF-SHA256
    let mut ikm = [0u8; 96];
    ikm[0..32].copy_from_slice(dh1.as_bytes());
    ikm[32..64].copy_from_slice(dh2.as_bytes());
    ikm[64..96].copy_from_slice(dh3.as_bytes());

    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut session_key = [0u8; 32];
    hk.expand(b"chaperone-x3dh-session-key", &mut session_key)
        .expect("HKDF expansion is guaranteed to succeed for 32-byte output");

    Ok(session_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::get_keychain;
    use std::collections::HashMap;

    fn backup_keychain() -> HashMap<String, String> {
        let keychain = get_keychain();
        let mut backup = HashMap::new();
        for key in &[
            "chaperone-signing-key",
            "chaperone-agreement-key",
            "chaperone-identity-metadata",
            "chaperone-signed-prekey",
        ] {
            if let Ok(val) = keychain.get_password(key, "default") {
                backup.insert(key.to_string(), val);
            }
        }
        backup
    }

    fn restore_keychain(backup: &HashMap<String, String>) {
        let keychain = get_keychain();
        keychain.reset();
        for (key, val) in backup {
            keychain.set_password(key, "default", val).unwrap();
        }
    }

    #[test]
    fn test_classical_x3dh_agreement_success() {
        // 1. Setup Bob
        get_keychain().reset();
        let bob_seed = [2u8; 32];
        let bob_identity = LocalIdentity::bootstrap_with_seed(bob_seed).unwrap();
        let (bob_prekey_pub, bob_prekey_sig) =
            bob_identity.generate_and_save_signed_prekey().unwrap();
        let bob_identity_pub = bob_identity.public_agreement_key().unwrap();

        let bob_backup = backup_keychain();

        // 2. Setup Alice
        get_keychain().reset();
        let alice_seed = [1u8; 32];
        let alice_identity = LocalIdentity::bootstrap_with_seed(alice_seed).unwrap();

        // Alice initiates
        let (mut init, alice_session_key) =
            initiate(&alice_identity, bob_identity_pub, bob_prekey_pub);
        init.signed_prekey_sig = bob_prekey_sig;

        // 3. Bob responds
        restore_keychain(&bob_backup);
        let bob_session_key = respond(&bob_identity, &init).unwrap();

        // Assert session keys match
        assert_eq!(alice_session_key, bob_session_key);
    }

    #[test]
    fn test_x3dh_tamper_detection() {
        // Setup Bob
        get_keychain().reset();
        let bob_seed = [2u8; 32];
        let bob_identity = LocalIdentity::bootstrap_with_seed(bob_seed).unwrap();
        let (bob_prekey_pub, bob_prekey_sig) =
            bob_identity.generate_and_save_signed_prekey().unwrap();
        let bob_identity_pub = bob_identity.public_agreement_key().unwrap();
        let bob_backup = backup_keychain();

        // Setup Alice
        get_keychain().reset();
        let alice_seed = [1u8; 32];
        let alice_identity = LocalIdentity::bootstrap_with_seed(alice_seed).unwrap();
        let (mut original_init, alice_session_key) =
            initiate(&alice_identity, bob_identity_pub, bob_prekey_pub);
        original_init.signed_prekey_sig = bob_prekey_sig;

        // Verify that modifying any single byte of HandshakeInit causes failure or non-matching key
        let serialize_and_test_tamper = |modified_init: &HandshakeInit| -> bool {
            restore_keychain(&bob_backup);
            match respond(&bob_identity, modified_init) {
                Ok(bob_session_key) => bob_session_key != alice_session_key,
                Err(_) => true, // Clean failure is accepted
            }
        };

        // 1. Tamper identity_key
        for i in 0..32 {
            let mut tampered = original_init.clone();
            tampered.identity_key[i] ^= 0xff;
            assert!(
                serialize_and_test_tamper(&tampered),
                "Tampering identity_key at byte {} went undetected!",
                i
            );
        }

        // 2. Tamper signed_prekey
        for i in 0..32 {
            let mut tampered = original_init.clone();
            tampered.signed_prekey[i] ^= 0xff;
            assert!(
                serialize_and_test_tamper(&tampered),
                "Tampering signed_prekey at byte {} went undetected!",
                i
            );
        }

        // 3. Tamper signed_prekey_sig
        for i in 0..64 {
            let mut tampered = original_init.clone();
            tampered.signed_prekey_sig[i] ^= 0xff;
            assert!(
                serialize_and_test_tamper(&tampered),
                "Tampering signed_prekey_sig at byte {} went undetected!",
                i
            );
        }

        // 4. Tamper ephemeral_key
        for i in 0..32 {
            let mut tampered = original_init.clone();
            tampered.ephemeral_key[i] ^= 0xff;
            assert!(
                serialize_and_test_tamper(&tampered),
                "Tampering ephemeral_key at byte {} went undetected!",
                i
            );
        }
    }

    #[test]
    fn test_x3dh_forged_signature_rejected() {
        // Setup Bob
        get_keychain().reset();
        let bob_seed = [2u8; 32];
        let bob_identity = LocalIdentity::bootstrap_with_seed(bob_seed).unwrap();
        let (bob_prekey_pub, _bob_prekey_sig) =
            bob_identity.generate_and_save_signed_prekey().unwrap();
        let bob_identity_pub = bob_identity.public_agreement_key().unwrap();
        let bob_backup = backup_keychain();

        // Setup Alice
        get_keychain().reset();
        let alice_seed = [1u8; 32];
        let alice_identity = LocalIdentity::bootstrap_with_seed(alice_seed).unwrap();
        let (mut init, _alice_session_key) =
            initiate(&alice_identity, bob_identity_pub, bob_prekey_pub);
        // Alice forged signature (or all zeros, which is invalid)
        init.signed_prekey_sig = [0x55u8; 64];

        // Bob responds, signature check must fail
        restore_keychain(&bob_backup);
        let result = respond(&bob_identity, &init);
        assert!(
            matches!(result, Err(HandshakeError::InvalidSignature)),
            "Forged signature did not fail with InvalidSignature! Got {:?}",
            result
        );
    }

    #[test]
    fn test_protobuf_wire_format_roundtrip() {
        use chaperone_protocol::prost::Message;

        let original = HandshakeInit {
            identity_key: [0x11; 32],
            signed_prekey: [0x22; 32],
            signed_prekey_sig: [0x33; 64],
            ephemeral_key: [0x44; 32],
        };

        // Convert core to proto
        let proto: proto_handshake::HandshakeInit = original.clone().into();

        // Encode to bytes
        let mut buf = Vec::new();
        proto.encode(&mut buf).unwrap();

        // Decode from bytes
        let decoded_proto = proto_handshake::HandshakeInit::decode(&buf[..]).unwrap();

        // Convert proto back to core
        let decoded: HandshakeInit = decoded_proto.try_into().unwrap();

        assert_eq!(original, decoded);
    }
}
