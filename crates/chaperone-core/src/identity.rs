use bs58;
use ed25519_dalek::SigningKey;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::sync::Mutex;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};
use x25519_dalek::StaticSecret;

#[derive(Debug, Clone)]
pub enum IdentityError {
    KeychainUnavailable(String),
    AlreadyBootstrapped,
    CorruptExistingIdentity(String),
    NotBootstrapped,
}

impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KeychainUnavailable(msg) => write!(f, "Keychain unavailable: {}", msg),
            Self::AlreadyBootstrapped => write!(f, "Identity is already bootstrapped"),
            Self::CorruptExistingIdentity(msg) => write!(f, "Corrupt existing identity: {}", msg),
            Self::NotBootstrapped => write!(f, "Identity has not been bootstrapped yet"),
        }
    }
}

impl Error for IdentityError {}

pub trait KeychainBackend: Send + Sync {
    fn set_password(
        &self,
        service: &str,
        username: &str,
        password: &str,
    ) -> Result<(), IdentityError>;
    fn get_password(&self, service: &str, username: &str) -> Result<String, IdentityError>;
    fn delete_password(&self, service: &str, username: &str) -> Result<(), IdentityError>;
    fn reset(&self) {}
}

#[derive(Default)]
pub struct RealKeychainBackend;

impl KeychainBackend for RealKeychainBackend {
    fn set_password(
        &self,
        service: &str,
        username: &str,
        password: &str,
    ) -> Result<(), IdentityError> {
        let entry = keyring::Entry::new(service, username)
            .map_err(|e| IdentityError::KeychainUnavailable(e.to_string()))?;
        entry
            .set_password(password)
            .map_err(|e| IdentityError::KeychainUnavailable(e.to_string()))?;
        Ok(())
    }

    fn get_password(&self, service: &str, username: &str) -> Result<String, IdentityError> {
        let entry = keyring::Entry::new(service, username)
            .map_err(|e| IdentityError::KeychainUnavailable(e.to_string()))?;
        entry.get_password().map_err(|e| match e {
            keyring::Error::NoEntry => IdentityError::NotBootstrapped,
            _ => IdentityError::KeychainUnavailable(e.to_string()),
        })
    }

    fn delete_password(&self, service: &str, username: &str) -> Result<(), IdentityError> {
        let entry = keyring::Entry::new(service, username)
            .map_err(|e| IdentityError::KeychainUnavailable(e.to_string()))?;
        match entry.delete_credential() {
            Ok(_) => Ok(()),
            Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(IdentityError::KeychainUnavailable(e.to_string())),
        }
    }
}

pub struct MockKeychainBackend {
    store: Mutex<HashMap<(String, String), String>>,
}

impl Default for MockKeychainBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl MockKeychainBackend {
    pub fn new() -> Self {
        Self {
            store: Mutex::new(HashMap::new()),
        }
    }
}

impl KeychainBackend for MockKeychainBackend {
    fn set_password(
        &self,
        service: &str,
        username: &str,
        password: &str,
    ) -> Result<(), IdentityError> {
        let mut store = self.store.lock().unwrap();
        store.insert(
            (service.to_string(), username.to_string()),
            password.to_string(),
        );
        Ok(())
    }

    fn get_password(&self, service: &str, username: &str) -> Result<String, IdentityError> {
        let store = self.store.lock().unwrap();
        store
            .get(&(service.to_string(), username.to_string()))
            .cloned()
            .ok_or(IdentityError::NotBootstrapped)
    }

    fn delete_password(&self, service: &str, username: &str) -> Result<(), IdentityError> {
        let mut store = self.store.lock().unwrap();
        store.remove(&(service.to_string(), username.to_string()));
        Ok(())
    }

    fn reset(&self) {
        let mut store = self.store.lock().unwrap();
        store.clear();
    }
}

pub struct DynamicKeychainBackend {
    real: RealKeychainBackend,
    mock: MockKeychainBackend,
}

impl Default for DynamicKeychainBackend {
    fn default() -> Self {
        Self {
            real: RealKeychainBackend,
            mock: MockKeychainBackend::new(),
        }
    }
}

impl DynamicKeychainBackend {
    fn active_backend(&self) -> &dyn KeychainBackend {
        if std::env::var("CHAPERONE_MOCK_KEYCHAIN").is_ok() || cfg!(test) {
            &self.mock
        } else {
            &self.real
        }
    }
}

impl KeychainBackend for DynamicKeychainBackend {
    fn set_password(
        &self,
        service: &str,
        username: &str,
        password: &str,
    ) -> Result<(), IdentityError> {
        self.active_backend()
            .set_password(service, username, password)
    }

    fn get_password(&self, service: &str, username: &str) -> Result<String, IdentityError> {
        self.active_backend().get_password(service, username)
    }

    fn delete_password(&self, service: &str, username: &str) -> Result<(), IdentityError> {
        self.active_backend().delete_password(service, username)
    }

    fn reset(&self) {
        self.active_backend().reset()
    }
}

static KEYCHAIN_BACKEND: OnceLock<DynamicKeychainBackend> = OnceLock::new();

pub fn get_keychain() -> &'static dyn KeychainBackend {
    KEYCHAIN_BACKEND.get_or_init(DynamicKeychainBackend::default)
}

#[derive(Clone, Serialize, Deserialize)]
pub struct LocalIdentity {
    pub did_key: String,     // "did:key:z6Mk..." multibase-encoded Ed25519 pubkey
    pub created_at: u64,     // unix timestamp
    pub rotation_epoch: u32, // starts at 0, see BU-106
}

impl fmt::Debug for LocalIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalIdentity")
            .field("did_key", &self.did_key)
            .field("created_at", &self.created_at)
            .field("rotation_epoch", &self.rotation_epoch)
            .finish()
    }
}

impl fmt::Display for LocalIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "LocalIdentity {{ did_key: {}, created_at: {}, rotation_epoch: {} }}",
            self.did_key, self.created_at, self.rotation_epoch
        )
    }
}

impl LocalIdentity {
    /// Bootstraps a brand new identity, using a real random entropy seed.
    pub fn bootstrap() -> Result<Self, IdentityError> {
        let mut seed = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut seed);
        Self::bootstrap_with_seed(seed)
    }

    /// Bootstraps a brand new identity deterministically using a fixed 32-byte seed.
    pub fn bootstrap_with_seed(seed: [u8; 32]) -> Result<Self, IdentityError> {
        let keychain = get_keychain();

        // Check if already bootstrapped
        if keychain
            .get_password("chaperone-signing-key", "default")
            .is_ok()
        {
            return Err(IdentityError::AlreadyBootstrapped);
        }

        // Derive keys
        let (signing_seed, agreement_seed) = derive_seeds(&seed);

        // Ed25519 signing key
        let signing_key = SigningKey::from_bytes(&signing_seed);
        let ed25519_pub = signing_key.verifying_key();
        let ed25519_priv_bytes = signing_key.to_bytes();

        // X25519 agreement key
        let agreement_key = StaticSecret::from(agreement_seed);
        let x25519_priv_bytes = agreement_key.to_bytes();

        // Construct did:key
        let did_key = bytes_to_did_key(&ed25519_pub.to_bytes());

        // Write both private keys to the OS keychain (base58 encoded)
        let signing_b58 = bs58::encode(ed25519_priv_bytes).into_string();
        let agreement_b58 = bs58::encode(x25519_priv_bytes).into_string();

        keychain.set_password("chaperone-signing-key", "default", &signing_b58)?;
        keychain.set_password("chaperone-agreement-key", "default", &agreement_b58)?;

        // Write metadata
        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| IdentityError::CorruptExistingIdentity(e.to_string()))?
            .as_secs();
        let rotation_epoch = 0;

        let metadata_str = format!("{},{}", created_at, rotation_epoch);
        keychain.set_password("chaperone-identity-metadata", "default", &metadata_str)?;

        Ok(Self {
            did_key,
            created_at,
            rotation_epoch,
        })
    }

    /// Loads the currently bootstrapped identity if it exists.
    pub fn get_current() -> Result<Self, IdentityError> {
        let keychain = get_keychain();

        // Load signing key
        let signing_b58 = keychain.get_password("chaperone-signing-key", "default")?;
        let signing_bytes = bs58::decode(signing_b58)
            .into_vec()
            .map_err(|e| IdentityError::CorruptExistingIdentity(e.to_string()))?;
        if signing_bytes.len() != 32 {
            return Err(IdentityError::CorruptExistingIdentity(
                "Invalid signing key length".into(),
            ));
        }
        let mut signing_priv_bytes = [0u8; 32];
        signing_priv_bytes.copy_from_slice(&signing_bytes);

        let signing_key = SigningKey::from_bytes(&signing_priv_bytes);
        let ed25519_pub = signing_key.verifying_key();
        let did_key = bytes_to_did_key(&ed25519_pub.to_bytes());

        // Load metadata
        let metadata_str = keychain.get_password("chaperone-identity-metadata", "default")?;
        let parts: Vec<&str> = metadata_str.split(',').collect();
        if parts.len() != 2 {
            return Err(IdentityError::CorruptExistingIdentity(
                "Invalid metadata format".into(),
            ));
        }
        let created_at = parts[0]
            .parse::<u64>()
            .map_err(|e| IdentityError::CorruptExistingIdentity(e.to_string()))?;
        let rotation_epoch = parts[1]
            .parse::<u32>()
            .map_err(|e| IdentityError::CorruptExistingIdentity(e.to_string()))?;

        Ok(Self {
            did_key,
            created_at,
            rotation_epoch,
        })
    }
}

fn derive_seeds(seed: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let mut hasher = Sha256::new();
    hasher.update(seed);
    hasher.update(b"chaperone-signing-key");
    let signing_seed: [u8; 32] = hasher.finalize().into();

    let mut hasher = Sha256::new();
    hasher.update(seed);
    hasher.update(b"chaperone-agreement-key");
    let agreement_seed: [u8; 32] = hasher.finalize().into();

    (signing_seed, agreement_seed)
}

fn bytes_to_did_key(pubkey: &[u8; 32]) -> String {
    let mut bytes = Vec::with_capacity(34);
    bytes.push(0xed);
    bytes.push(0x01);
    bytes.extend_from_slice(pubkey);
    let encoded = bs58::encode(bytes).into_string();
    format!("did:key:z{}", encoded)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_seed_produces_same_did_key() {
        get_keychain().reset();
        let seed = [42u8; 32];
        let identity_1 = LocalIdentity::bootstrap_with_seed(seed).unwrap();

        // Clear mock keychain to allow second bootstrap
        get_keychain().reset();
        let identity_2 = LocalIdentity::bootstrap_with_seed(seed).unwrap();

        assert_eq!(identity_1.did_key, identity_2.did_key);
        assert!(identity_1.did_key.starts_with("did:key:z6Mk"));
    }

    #[test]
    fn random_seeds_produce_different_did_keys() {
        get_keychain().reset();
        let identity_1 = LocalIdentity::bootstrap().unwrap();

        get_keychain().reset();
        let identity_2 = LocalIdentity::bootstrap().unwrap();

        assert_ne!(identity_1.did_key, identity_2.did_key);
    }

    #[test]
    fn private_key_never_appears_in_debug_or_display() {
        get_keychain().reset();
        let identity = LocalIdentity::bootstrap().unwrap();

        let debug_str = format!("{:?}", identity);
        let display_str = format!("{}", identity);

        // Ensure no private key bytes or secret materials are printed
        assert!(!debug_str.contains("private"));
        assert!(!debug_str.contains("secret"));
        assert!(!display_str.contains("private"));
        assert!(!display_str.contains("secret"));

        // Ensure only public fields are present
        assert!(debug_str.contains("did_key"));
        assert!(debug_str.contains("created_at"));
        assert!(debug_str.contains("rotation_epoch"));
    }
}
