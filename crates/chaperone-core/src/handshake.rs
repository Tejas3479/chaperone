use crate::identity::{did_key_to_bytes, IdentityError, LocalIdentity};
use chaperone_protocol::handshake as proto_handshake;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use std::error::Error;
use std::fmt;
use x25519_dalek::{PublicKey, StaticSecret};

use ml_kem::{
    kem::{Decapsulate, Encapsulate, KeyExport},
    FromSeed, MlKem768,
};
use ml_kem::kem::EncapsulationKey;

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
    pub signed_prekey_sig: [u8; 64], // Ed25519 signature over (signed_prekey || pq_prekey) if present
    pub ephemeral_key: [u8; 32],
    pub pq_kem_ciphertext: Option<Vec<u8>>,
    pub capabilities: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakeResponse {
    pub ephemeral_key: [u8; 32],
    pub pq_kem_ciphertext_ack: Option<Vec<u8>>,
    pub capabilities: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    pub key: SessionKey,
    pub is_classical_only: bool,
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

        let pq_kem_ciphertext = proto.pq_kem_ciphertext.filter(|v| !v.is_empty());

        Ok(Self {
            identity_key,
            signed_prekey,
            signed_prekey_sig,
            ephemeral_key,
            pq_kem_ciphertext,
            capabilities: proto.capabilities,
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
            pq_kem_ciphertext: core.pq_kem_ciphertext,
            capabilities: core.capabilities,
        }
    }
}

impl TryFrom<proto_handshake::HandshakeResponse> for HandshakeResponse {
    type Error = HandshakeError;

    fn try_from(proto: proto_handshake::HandshakeResponse) -> Result<Self, Self::Error> {
        let ephemeral_key = proto.ephemeral_key.try_into().map_err(|_| {
            HandshakeError::SerializationError("Invalid ephemeral_key length".to_string())
        })?;

        let pq_kem_ciphertext_ack = proto.pq_kem_ciphertext_ack.filter(|v| !v.is_empty());

        Ok(Self {
            ephemeral_key,
            pq_kem_ciphertext_ack,
            capabilities: proto.capabilities,
        })
    }
}

impl From<HandshakeResponse> for proto_handshake::HandshakeResponse {
    fn from(core: HandshakeResponse) -> Self {
        Self {
            ephemeral_key: core.ephemeral_key.to_vec(),
            pq_kem_ciphertext_ack: core.pq_kem_ciphertext_ack,
            capabilities: core.capabilities,
        }
    }
}

/// Initiates a classical or hybrid PQXDH-style key agreement with a remote party.
pub fn initiate(
    local: &LocalIdentity,
    remote_identity_key: [u8; 32],
    remote_signed_prekey: [u8; 32],
    remote_pq_prekey: Option<[u8; 1184]>,
    local_supports_pq: bool,
) -> (HandshakeInit, Session) {
    let local_priv_ik = local
        .load_agreement_key()
        .expect("Failed to load local identity agreement key");
    let local_pub_ik = PublicKey::from(&local_priv_ik);
    let local_pub_ik_bytes = local_pub_ik.to_bytes();

    // Generate ephemeral key pair for X25519
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

    // Capability negotiation
    let pq_negotiated = local_supports_pq && remote_pq_prekey.is_some();

    let mut capabilities = Vec::new();
    if local_supports_pq {
        capabilities.push("PQ_MLKEM_768".to_string());
    }

    let mut ikm = Vec::new();
    ikm.extend_from_slice(dh1.as_bytes());
    ikm.extend_from_slice(dh2.as_bytes());
    ikm.extend_from_slice(dh3.as_bytes());

    let mut pq_kem_ciphertext = None;
    if pq_negotiated {
        if let Some(ref_pub_key_bytes) = remote_pq_prekey {
            // Load remote public key
            if let Ok(ek) = EncapsulationKey::<MlKem768>::new(
                ref_pub_key_bytes.as_slice().try_into().unwrap(),
            ) {
                let (ct, shared_secret) = ek.encapsulate();
                pq_kem_ciphertext = Some(ct.to_vec());
                ikm.extend_from_slice(shared_secret.as_slice());
            }
        }
    }

    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut session_key = [0u8; 32];
    hk.expand(b"chaperone-x3dh-session-key", &mut session_key)
        .expect("HKDF expansion is guaranteed to succeed for 32-byte output");

    let init = HandshakeInit {
        identity_key: local_pub_ik_bytes,
        signed_prekey: remote_signed_prekey,
        signed_prekey_sig: [0u8; 64], // Caller must populate Bob's signature
        ephemeral_key: ephemeral_pub_bytes,
        pq_kem_ciphertext,
        capabilities,
    };

    let session = Session {
        key: session_key,
        is_classical_only: !pq_negotiated,
    };

    (init, session)
}

/// Responds to a hybrid or classical X3DH key agreement.
pub fn respond(
    local: &LocalIdentity,
    init: &HandshakeInit,
    local_supports_pq: bool,
) -> Result<(HandshakeResponse, Session), HandshakeError> {
    // 1. Verify the signature on B's signed prekey using B's public signing key.
    let signing_pubkey_bytes = did_key_to_bytes(&local.did_key)?;
    let verifying_key = VerifyingKey::from_bytes(&signing_pubkey_bytes)
        .map_err(|e| HandshakeError::Other(e.to_string()))?;

    let signature = Signature::from_bytes(&init.signed_prekey_sig);

    // If Bob has generated a PQ prekey, Bob expects the signature to cover both classical and PQ prekeys.
    let bob_has_pq = local.load_signed_prekey_pq().is_ok();
    let mut signed_data = Vec::new();
    signed_data.extend_from_slice(&init.signed_prekey);

    if bob_has_pq {
        if let Ok(dk) = local.load_signed_prekey_pq() {
            let ek = dk.encapsulation_key();
            let ek_bytes = ek.to_bytes();
            signed_data.extend_from_slice(ek_bytes.as_slice());
        }
    }

    // Try verifying the composite/signed prekey data
    let mut verified = verifying_key.verify(&signed_data, &signature).is_ok();

    // Fallback to classical-only prekey verification (BU-202 compatibility)
    if !verified {
        verified = verifying_key
            .verify(&init.signed_prekey, &signature)
            .is_ok();
    }

    if !verified {
        return Err(HandshakeError::InvalidSignature);
    }

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

    // Negotiate PQ
    let alice_supports_pq = init.capabilities.iter().any(|c| c == "PQ_MLKEM_768");
    let pq_negotiated = local_supports_pq
        && bob_has_pq
        && alice_supports_pq
        && init.pq_kem_ciphertext.is_some();

    let mut ikm = Vec::new();
    ikm.extend_from_slice(dh1.as_bytes());
    ikm.extend_from_slice(dh2.as_bytes());
    ikm.extend_from_slice(dh3.as_bytes());

    let mut pq_kem_ciphertext_ack = None;
    if pq_negotiated {
        if let Some(ref ct_bytes) = init.pq_kem_ciphertext {
            if let Ok(dk) = local.load_signed_prekey_pq() {
                if let Ok(ct_arr) = ct_bytes.as_slice().try_into() {
                    let shared_secret = dk.decapsulate(ct_arr);
                    ikm.extend_from_slice(shared_secret.as_slice());

                    // Generate ACK as SHA-256 hash of ciphertext
                    let mut hasher = Sha256::new();
                    hasher.update(ct_bytes);
                    pq_kem_ciphertext_ack = Some(hasher.finalize().to_vec());
                }
            }
        }
    }

    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut session_key = [0u8; 32];
    hk.expand(b"chaperone-x3dh-session-key", &mut session_key)
        .expect("HKDF expansion is guaranteed to succeed for 32-byte output");

    // Bob's response capabilities
    let mut response_capabilities = Vec::new();
    if local_supports_pq && bob_has_pq {
        response_capabilities.push("PQ_MLKEM_768".to_string());
    }

    let bob_pub_ik_bytes = local.public_agreement_key().unwrap_or([0u8; 32]);

    let response = HandshakeResponse {
        ephemeral_key: bob_pub_ik_bytes,
        pq_kem_ciphertext_ack,
        capabilities: response_capabilities,
    };

    let session = Session {
        key: session_key,
        is_classical_only: !pq_negotiated,
    };

    Ok((response, session))
}

/// Finalizes the handshake on the initiator's (Alice's) side.
/// Detects downgrade attacks and derives the downgraded key if Bob did not support PQ.
pub fn finalize_initiator(
    alice_supports_pq: bool,
    remote_pq_prekey: Option<[u8; 1184]>,
    provisional_session: &Session,
    response: &HandshakeResponse,
    dh1: &[u8],
    dh2: &[u8],
    dh3: &[u8],
) -> Result<Session, HandshakeError> {
    let bob_supports_pq = response.capabilities.iter().any(|c| c == "PQ_MLKEM_768");
    let pq_negotiated = alice_supports_pq && remote_pq_prekey.is_some() && bob_supports_pq;

    if provisional_session.is_classical_only && pq_negotiated {
        return Err(HandshakeError::Other(
            "Negotiation state mismatch: hybrid session established when classical expected"
                .to_string(),
        ));
    }

    if !provisional_session.is_classical_only && !pq_negotiated {
        // Bob downgraded/does not support PQ. Alice must downgrade to classical key!
        let mut ikm = Vec::new();
        ikm.extend_from_slice(dh1);
        ikm.extend_from_slice(dh2);
        ikm.extend_from_slice(dh3);

        let hk = Hkdf::<Sha256>::new(None, &ikm);
        let mut session_key = [0u8; 32];
        hk.expand(b"chaperone-x3dh-session-key", &mut session_key)
            .expect("HKDF expansion is guaranteed to succeed for 32-byte output");

        return Ok(Session {
            key: session_key,
            is_classical_only: true,
        });
    }

    Ok(provisional_session.clone())
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
            "chaperone-signed-prekey-pq",
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
    fn test_mlkem_kat_vectors() {
        // 1. Setup seed (0..64)
        let mut seed = [0u8; 64];
        for i in 0..64 {
            seed[i] = i as u8;
        }

        // Generate keys
        let (dk, ek) = MlKem768::from_seed(seed.as_slice().try_into().unwrap());
        let ek_bytes = ek.to_bytes();
        let dk_bytes = dk.to_bytes();

        // Verify keygen matches reference values
        assert_eq!(
            &ek_bytes[..16],
            &[41, 138, 161, 13, 66, 60, 141, 218, 6, 157, 2, 188, 89, 230, 205, 240]
        );
        assert_eq!(
            &dk_bytes[..16],
            &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
        );

        // 2. Perform deterministic encapsulation with m = 100..132
        let mut m = [0u8; 32];
        for i in 0..32 {
            m[i] = (i + 100) as u8;
        }

        let (ct, shared_secret_sender) = ek
            .encapsulate_deterministic(m.as_slice().try_into().unwrap());

        // Verify generated ciphertext and shared secret
        assert_eq!(
            &ct[..16],
            &[215, 175, 104, 248, 216, 77, 193, 171, 120, 52, 163, 186, 145, 190, 85, 131]
        );
        assert_eq!(
            shared_secret_sender.as_slice(),
            &[
                197, 167, 65, 16, 193, 88, 172, 186, 249, 192, 29, 235, 134, 250, 108, 193, 12,
                20, 83, 63, 237, 165, 75, 236, 31, 221, 0, 13, 97, 240, 126, 78
            ]
        );

        // Decapsulate
        let shared_secret_receiver = dk.decapsulate(&ct);
        assert_eq!(shared_secret_sender, shared_secret_receiver);
    }

    #[test]
    fn test_hybrid_handshake_success() {
        // 1. Setup Bob (PQ Capable)
        get_keychain().reset();
        let bob_seed = [2u8; 32];
        let bob_identity = LocalIdentity::bootstrap_with_seed(bob_seed).unwrap();
        let (bob_prekey_pub, bob_prekey_sig, bob_pq_pub) =
            bob_identity.generate_and_save_signed_prekey().unwrap();
        let bob_identity_pub = bob_identity.public_agreement_key().unwrap();

        let bob_backup = backup_keychain();

        // 2. Setup Alice (PQ Capable)
        get_keychain().reset();
        let alice_seed = [1u8; 32];
        let alice_identity = LocalIdentity::bootstrap_with_seed(alice_seed).unwrap();

        // Alice initiates hybrid
        let (mut init, alice_provisional) = initiate(
            &alice_identity,
            bob_identity_pub,
            bob_prekey_pub,
            Some(bob_pq_pub),
            true, // Alice supports PQ
        );
        init.signed_prekey_sig = bob_prekey_sig;

        // Verify Alice derived hybrid
        assert!(!alice_provisional.is_classical_only);

        // 3. Bob responds
        restore_keychain(&bob_backup);
        let (response, bob_session) = respond(
            &bob_identity,
            &init,
            true, // Bob supports PQ
        )
        .unwrap();

        assert!(!bob_session.is_classical_only);

        // Alice finalizes
        let alice_priv_ik = alice_identity.load_agreement_key().unwrap();
        let remote_spk_pub = PublicKey::from(bob_prekey_pub);
        let dh1 = alice_priv_ik.diffie_hellman(&remote_spk_pub);
        // finalize
        let alice_finalized = finalize_initiator(
            true,
            Some(bob_pq_pub),
            &alice_provisional,
            &response,
            dh1.as_bytes(),
            &[0u8; 32], // dummy EK_A / IK_B DH
            dh1.as_bytes(), // dummy EK_A / SPK_B DH
        )
        .unwrap();

        assert_eq!(alice_finalized.key, bob_session.key);
        assert!(!alice_finalized.is_classical_only);
    }

    #[test]
    fn test_classical_negotiation_downgrade() {
        // Bob is classical-only (no PQ support)
        get_keychain().reset();
        let bob_seed = [2u8; 32];
        let bob_identity = LocalIdentity::bootstrap_with_seed(bob_seed).unwrap();
        // Generates prekey (which includes both but we won't pass remote_pq_prekey to Alice)
        let (bob_prekey_pub, bob_prekey_sig, _bob_pq_pub) =
            bob_identity.generate_and_save_signed_prekey().unwrap();
        let bob_identity_pub = bob_identity.public_agreement_key().unwrap();
        let bob_backup = backup_keychain();

        // Alice is PQ Capable
        get_keychain().reset();
        let alice_seed = [1u8; 32];
        let alice_identity = LocalIdentity::bootstrap_with_seed(alice_seed).unwrap();

        // Alice initiates (but Bob's PQ key is None)
        let (mut init, alice_provisional) = initiate(
            &alice_identity,
            bob_identity_pub,
            bob_prekey_pub,
            None, // Bob doesn't have/Alice doesn't know Bob's PQ key
            true, // Alice supports PQ
        );
        init.signed_prekey_sig = bob_prekey_sig;

        // Alice provisional must be classical-only
        assert!(alice_provisional.is_classical_only);

        // Bob responds (with local_supports_pq = false)
        restore_keychain(&bob_backup);
        let (response, bob_session) = respond(
            &bob_identity,
            &init,
            false, // Bob does NOT support PQ
        )
        .unwrap();

        assert!(bob_session.is_classical_only);
        assert_eq!(alice_provisional.key, bob_session.key);

        // Alice finalizes
        let dh_dummy = [0u8; 32];
        let alice_finalized = finalize_initiator(
            true,
            None,
            &alice_provisional,
            &response,
            dh_dummy.as_slice(),
            dh_dummy.as_slice(),
            dh_dummy.as_slice(),
        )
        .unwrap();

        assert_eq!(alice_finalized.key, bob_session.key);
        assert!(alice_finalized.is_classical_only);
    }

    #[test]
    fn test_x3dh_tamper_detection() {
        // Setup Bob
        get_keychain().reset();
        let bob_seed = [2u8; 32];
        let bob_identity = LocalIdentity::bootstrap_with_seed(bob_seed).unwrap();
        let (bob_prekey_pub, bob_prekey_sig, bob_pq_pub) =
            bob_identity.generate_and_save_signed_prekey().unwrap();
        let bob_identity_pub = bob_identity.public_agreement_key().unwrap();
        let bob_backup = backup_keychain();

        // Setup Alice
        get_keychain().reset();
        let alice_seed = [1u8; 32];
        let alice_identity = LocalIdentity::bootstrap_with_seed(alice_seed).unwrap();
        let (mut original_init, alice_provisional) = initiate(
            &alice_identity,
            bob_identity_pub,
            bob_prekey_pub,
            Some(bob_pq_pub),
            true,
        );
        original_init.signed_prekey_sig = bob_prekey_sig;

        // Verify that modifying any single byte of HandshakeInit causes failure or non-matching key
        let serialize_and_test_tamper = |modified_init: &HandshakeInit| -> bool {
            restore_keychain(&bob_backup);
            match respond(&bob_identity, modified_init, true) {
                Ok((_, bob_session)) => bob_session.key != alice_provisional.key,
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
        let (bob_prekey_pub, _bob_prekey_sig, bob_pq_pub) =
            bob_identity.generate_and_save_signed_prekey().unwrap();
        let bob_identity_pub = bob_identity.public_agreement_key().unwrap();
        let bob_backup = backup_keychain();

        // Setup Alice
        get_keychain().reset();
        let alice_seed = [1u8; 32];
        let alice_identity = LocalIdentity::bootstrap_with_seed(alice_seed).unwrap();
        let (mut init, _alice_session) = initiate(
            &alice_identity,
            bob_identity_pub,
            bob_prekey_pub,
            Some(bob_pq_pub),
            true,
        );
        // Alice forged signature (or all zeros, which is invalid)
        init.signed_prekey_sig = [0x55u8; 64];

        // Bob responds, signature check must fail
        restore_keychain(&bob_backup);
        let result = respond(&bob_identity, &init, true);
        assert!(
            matches!(result, Err(HandshakeError::InvalidSignature)),
            "Forged signature did not fail with InvalidSignature! Got {:?}",
            result
        );
    }

    #[test]
    fn test_protobuf_wire_format_roundtrip() {
        use chaperone_protocol::prost::Message;

        let original_init = HandshakeInit {
            identity_key: [0x11; 32],
            signed_prekey: [0x22; 32],
            signed_prekey_sig: [0x33; 64],
            ephemeral_key: [0x44; 32],
            pq_kem_ciphertext: Some(vec![0x55; 1088]),
            capabilities: vec!["PQ_MLKEM_768".to_string()],
        };

        // Convert core to proto init
        let proto_init: proto_handshake::HandshakeInit = original_init.clone().into();

        // Encode to bytes
        let mut buf_init = Vec::new();
        proto_init.encode(&mut buf_init).unwrap();

        // Decode from bytes
        let decoded_proto_init = proto_handshake::HandshakeInit::decode(&buf_init[..]).unwrap();

        // Convert proto back to core
        let decoded_init: HandshakeInit = decoded_proto_init.try_into().unwrap();

        assert_eq!(original_init, decoded_init);

        let original_response = HandshakeResponse {
            ephemeral_key: [0xaa; 32],
            pq_kem_ciphertext_ack: Some(vec![0xbb; 32]),
            capabilities: vec!["PQ_MLKEM_768".to_string()],
        };

        // Convert core to proto response
        let proto_res: proto_handshake::HandshakeResponse = original_response.clone().into();

        // Encode to bytes
        let mut buf_res = Vec::new();
        proto_res.encode(&mut buf_res).unwrap();

        // Decode from bytes
        let decoded_proto_res = proto_handshake::HandshakeResponse::decode(&buf_res[..]).unwrap();

        // Convert proto back to core
        let decoded_res: HandshakeResponse = decoded_proto_res.try_into().unwrap();

        assert_eq!(original_response, decoded_res);
    }
}
