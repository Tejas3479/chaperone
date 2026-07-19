use crate::identity::LocalIdentity;
use bs58;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::error::Error;
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

pub type Ed25519Keypair = SigningKey;

thread_local! {
    pub static LAST_GENERATED_KEY: RefCell<Option<SigningKey>> = const { RefCell::new(None) };
}

/// Retrieves and clears the last generated signing key from thread-local storage.
/// Used primarily for testing key rotation chains.
pub fn take_last_generated_key() -> Option<SigningKey> {
    LAST_GENERATED_KEY.with(|lk| lk.borrow_mut().take())
}

#[derive(Debug, Clone)]
pub enum RotationError {
    EmptyChain,
    InvalidGenesisEpoch(u32),
    NonSequentialEpoch { expected: u32, actual: u32 },
    InvalidPublicKey(u32, String),
    SignatureVerificationFailed(u32, String),
    IdentityConversionError(String),
}

impl fmt::Display for RotationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyChain => write!(f, "Rotation chain is empty"),
            Self::InvalidGenesisEpoch(epoch) => {
                write!(f, "Invalid genesis record epoch: {} (expected 0)", epoch)
            }
            Self::NonSequentialEpoch { expected, actual } => write!(
                f,
                "Non-sequential epoch sequence: expected {}, got {}",
                expected, actual
            ),
            Self::InvalidPublicKey(epoch, msg) => {
                write!(f, "Invalid public key at epoch {}: {}", epoch, msg)
            }
            Self::SignatureVerificationFailed(epoch, msg) => write!(
                f,
                "Signature verification failed at epoch {}: {}",
                epoch, msg
            ),
            Self::IdentityConversionError(msg) => write!(f, "Identity conversion error: {}", msg),
        }
    }
}

impl Error for RotationError {}

// Custom Serde serialization helper for [u8; 64] to handle array sizes > 32
mod big_array {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(bytes: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        bytes[..].serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        let v = Vec::<u8>::deserialize(deserializer)?;
        if v.len() != 64 {
            return Err(serde::de::Error::custom(format!(
                "Expected 64 bytes for signature, got {}",
                v.len()
            )));
        }
        let mut array = [0u8; 64];
        array.copy_from_slice(&v);
        Ok(array)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RotationRecord {
    pub epoch: u32,
    pub new_pubkey: [u8; 32], // Ed25519 public key for the new epoch

    #[serde(with = "big_array")]
    pub signed_by_previous_key: [u8; 64], // Ed25519 signature, signed by the PREVIOUS epoch's private key

    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RotationChain {
    records: Vec<RotationRecord>, // epoch 0 created at bootstrap, per BU-101
}

impl RotationChain {
    /// Creates the epoch-0 record from a LocalIdentity.
    pub fn genesis(identity: &LocalIdentity) -> Self {
        let pubkey = did_key_to_bytes(&identity.did_key)
            .expect("Invalid LocalIdentity did_key in genesis initialization");

        let record = RotationRecord {
            epoch: 0,
            new_pubkey: pubkey,
            signed_by_previous_key: [0u8; 64],
            timestamp: identity.created_at,
        };

        Self {
            records: vec![record],
        }
    }

    /// Generates a new keypair, signs the transition using the previous signing key,
    /// and pushes the new RotationRecord to the chain.
    pub fn rotate(
        &mut self,
        previous_signing_key: &Ed25519Keypair,
    ) -> Result<&RotationRecord, RotationError> {
        let last_record = self.records.last().ok_or(RotationError::EmptyChain)?;
        let next_epoch = last_record.epoch + 1;

        // 1. Generate a new keypair
        let mut seed = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut seed);
        let new_key = SigningKey::from_bytes(&seed);
        let new_pubkey = new_key.verifying_key().to_bytes();

        // 2. Capture timestamp
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| RotationError::IdentityConversionError(e.to_string()))?
            .as_secs();

        // 3. Construct signing message payload
        let mut msg = Vec::with_capacity(4 + 32 + 8);
        msg.extend_from_slice(&next_epoch.to_be_bytes());
        msg.extend_from_slice(&new_pubkey);
        msg.extend_from_slice(&timestamp.to_be_bytes());

        // 4. Sign the message with previous_signing_key
        let signature = previous_signing_key.sign(&msg);
        let signed_by_previous_key = signature.to_bytes();

        // 5. Save the newly generated key to thread-local storage for testing retrieval
        LAST_GENERATED_KEY.with(|lk| {
            lk.borrow_mut().replace(new_key);
        });

        // 6. Push to chain
        let record = RotationRecord {
            epoch: next_epoch,
            new_pubkey,
            signed_by_previous_key,
            timestamp,
        };
        self.records.push(record);

        Ok(self.records.last().unwrap())
    }

    /// Walks every record starting from epoch 0, validating each transition's signature
    /// against the prior epoch's public key.
    pub fn verify_chain(&self) -> Result<(), RotationError> {
        if self.records.is_empty() {
            return Err(RotationError::EmptyChain);
        }

        // Validate epoch 0 is indeed genesis
        if self.records[0].epoch != 0 {
            return Err(RotationError::InvalidGenesisEpoch(self.records[0].epoch));
        }

        // Validate subsequent transitions sequentially
        for i in 1..self.records.len() {
            let prev = &self.records[i - 1];
            let curr = &self.records[i];

            if curr.epoch != prev.epoch + 1 {
                return Err(RotationError::NonSequentialEpoch {
                    expected: prev.epoch + 1,
                    actual: curr.epoch,
                });
            }

            let verifying_key = VerifyingKey::from_bytes(&prev.new_pubkey)
                .map_err(|e| RotationError::InvalidPublicKey(curr.epoch, e.to_string()))?;

            let signature = Signature::from_bytes(&curr.signed_by_previous_key);

            // Construct expected signed payload
            let mut msg = Vec::with_capacity(4 + 32 + 8);
            msg.extend_from_slice(&curr.epoch.to_be_bytes());
            msg.extend_from_slice(&curr.new_pubkey);
            msg.extend_from_slice(&curr.timestamp.to_be_bytes());

            verifying_key.verify(&msg, &signature).map_err(|e| {
                RotationError::SignatureVerificationFailed(curr.epoch, e.to_string())
            })?;
        }

        Ok(())
    }

    /// Returns a slice of the records in the rotation chain.
    pub fn records(&self) -> &[RotationRecord] {
        &self.records
    }

    /// Returns a mutable reference to the list of records in the rotation chain.
    /// Used for simulating tampering in testing environments.
    pub fn records_mut(&mut self) -> &mut Vec<RotationRecord> {
        &mut self.records
    }
}

/// Helper function to parse did_key back to raw public key bytes.
fn did_key_to_bytes(did_key: &str) -> Result<[u8; 32], RotationError> {
    if !did_key.starts_with("did:key:z") {
        return Err(RotationError::IdentityConversionError(
            "Invalid did:key prefix".into(),
        ));
    }
    let encoded = &did_key["did:key:z".len()..];
    let decoded = bs58::decode(encoded)
        .into_vec()
        .map_err(|e| RotationError::IdentityConversionError(e.to_string()))?;

    if decoded.len() != 34 {
        return Err(RotationError::IdentityConversionError(format!(
            "Invalid decoded did:key length: {} (expected 34)",
            decoded.len()
        )));
    }
    if decoded[0] != 0xed || decoded[1] != 0x01 {
        return Err(RotationError::IdentityConversionError(format!(
            "Invalid multicodec did:key prefix: [0x{:x}, 0x{:x}]",
            decoded[0], decoded[1]
        )));
    }

    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&decoded[2..]);
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Digest;

    #[test]
    fn test_synthetic_5_epoch_chain_passes() {
        crate::identity::get_keychain().reset();
        // 1. Bootstrap genesis identity
        let seed = [42u8; 32];
        let identity = LocalIdentity::bootstrap_with_seed(seed).unwrap();

        // 2. Derive the initial signing key from the seed to match bootstrap logic
        let mut hasher = sha2::Sha256::new();
        hasher.update(seed);
        hasher.update(b"chaperone-signing-key");
        let signing_seed: [u8; 32] = hasher.finalize().into();
        let initial_key = SigningKey::from_bytes(&signing_seed);

        // 3. Initialize chain
        let mut chain = RotationChain::genesis(&identity);
        assert_eq!(chain.records().len(), 1);
        assert_eq!(chain.records()[0].epoch, 0);

        // 4. Perform 5 sequential rotations
        let mut current_key = initial_key;
        for i in 1..=5 {
            let record = chain.rotate(&current_key).unwrap();
            assert_eq!(record.epoch, i);

            // Retrieve the newly generated key
            current_key = take_last_generated_key().unwrap();
        }

        assert_eq!(chain.records().len(), 6);

        // 5. Verify the full chain
        assert!(chain.verify_chain().is_ok());
    }

    #[test]
    fn test_tampered_pubkey_fails_correct_epoch() {
        crate::identity::get_keychain().reset();
        let seed = [1u8; 32];
        let identity = LocalIdentity::bootstrap_with_seed(seed).unwrap();

        let mut hasher = sha2::Sha256::new();
        hasher.update(seed);
        hasher.update(b"chaperone-signing-key");
        let signing_seed: [u8; 32] = hasher.finalize().into();
        let initial_key = SigningKey::from_bytes(&signing_seed);

        let mut chain = RotationChain::genesis(&identity);
        let mut current_key = initial_key;
        for _ in 1..=5 {
            chain.rotate(&current_key).unwrap();
            current_key = take_last_generated_key().unwrap();
        }

        // Tamper with the public key of epoch 3
        chain.records_mut()[3].new_pubkey[0] ^= 0xFF;

        // Verify chain should fail and identify epoch 3 (whose signature check failed
        // because the payload hash changed) or epoch 4 (which is checked using epoch 3's tampered key).
        // Since we tampered with epoch 3's new_pubkey, checking epoch 3's signature against epoch 2's verifying key
        // will fail because the signature signed the original new_pubkey.
        match chain.verify_chain() {
            Err(RotationError::SignatureVerificationFailed(epoch, _)) => {
                assert_eq!(epoch, 3);
            }
            other => panic!("Expected SignatureVerificationFailed(3), got {:?}", other),
        }
    }

    #[test]
    fn test_forged_rotation_record_fails() {
        crate::identity::get_keychain().reset();
        let seed = [2u8; 32];
        let identity = LocalIdentity::bootstrap_with_seed(seed).unwrap();

        let mut hasher = sha2::Sha256::new();
        hasher.update(seed);
        hasher.update(b"chaperone-signing-key");
        let signing_seed: [u8; 32] = hasher.finalize().into();
        let initial_key = SigningKey::from_bytes(&signing_seed);

        let mut chain = RotationChain::genesis(&identity);
        let mut current_key = initial_key;
        for _ in 1..=5 {
            chain.rotate(&current_key).unwrap();
            current_key = take_last_generated_key().unwrap();
        }

        // Forge the signature of epoch 3 by replacing it with a signature from a completely random key
        let mut random_seed = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut random_seed);
        let random_key = SigningKey::from_bytes(&random_seed);

        let mut msg = Vec::new();
        msg.extend_from_slice(&3u32.to_be_bytes());
        msg.extend_from_slice(&chain.records()[3].new_pubkey);
        msg.extend_from_slice(&chain.records()[3].timestamp.to_be_bytes());

        let forged_sig = random_key.sign(&msg);
        chain.records_mut()[3].signed_by_previous_key = forged_sig.to_bytes();

        // Verify chain must reject epoch 3 because it was not signed by epoch 2's key
        match chain.verify_chain() {
            Err(RotationError::SignatureVerificationFailed(epoch, _)) => {
                assert_eq!(epoch, 3);
            }
            other => panic!("Expected SignatureVerificationFailed(3), got {:?}", other),
        }
    }
}
