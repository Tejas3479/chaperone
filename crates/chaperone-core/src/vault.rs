use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use rand::RngCore;
use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::rand::{SecureRandom, SystemRandom};
use sha2::Sha256;
use sqlx::sqlite::SqliteConnectOptions;
use sqlx::SqlitePool;
use std::error::Error;
use std::fmt;
use std::path::Path;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

pub const ARGON2_M_COST: u32 = 19456;
pub const ARGON2_T_COST: u32 = 2;
pub const ARGON2_P_COST: u32 = 1;

#[derive(Debug)]
pub enum CryptoError {
    Argon2(String),
    Aead(String),
    Other(String),
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Argon2(e) => write!(f, "Argon2 error: {}", e),
            Self::Aead(e) => write!(f, "AEAD error: {}", e),
            Self::Other(e) => write!(f, "Cryptographic error: {}", e),
        }
    }
}

impl Error for CryptoError {}

#[derive(Debug)]
pub enum VaultError {
    Database(sqlx::Error),
    Migration(sqlx::migrate::MigrateError),
    InvalidPath,
    NotFound,
    Crypto(CryptoError),
    Other(String),
}

impl fmt::Display for VaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Database(e) => write!(f, "Database error: {}", e),
            Self::Migration(e) => write!(f, "Migration error: {}", e),
            Self::InvalidPath => write!(f, "Invalid database path"),
            Self::NotFound => write!(f, "Credential not found"),
            Self::Crypto(e) => write!(f, "Cryptographic error: {}", e),
            Self::Other(msg) => write!(f, "Vault error: {}", msg),
        }
    }
}

impl Error for VaultError {}

impl From<sqlx::Error> for VaultError {
    fn from(err: sqlx::Error) -> Self {
        Self::Database(err)
    }
}

impl From<sqlx::migrate::MigrateError> for VaultError {
    fn from(err: sqlx::migrate::MigrateError) -> Self {
        Self::Migration(err)
    }
}

impl From<CryptoError> for VaultError {
    fn from(err: CryptoError) -> Self {
        Self::Crypto(err)
    }
}

pub fn derive_master_key(pin: &[u8], salt: &[u8; 16]) -> Result<[u8; 32], CryptoError> {
    let params = Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, Some(32))
        .map_err(|e| CryptoError::Argon2(e.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut master_key = [0u8; 32];
    argon2
        .hash_password_into(pin, salt, &mut master_key)
        .map_err(|e| CryptoError::Argon2(e.to_string()))?;
    Ok(master_key)
}

pub fn stretch_key(master_key: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    // HKDF-Extract-and-Expand. Since master_key is high-entropy, we use None salt.
    // We expand to 64 bytes and split:
    // First 32 bytes: encryption key (for ChaCha20-Poly1305)
    // Next 32 bytes: MAC/check key (for verifying PIN correctness via secret_key_check)
    let hk = Hkdf::<Sha256>::new(None, master_key);
    let mut okm = [0u8; 64];
    hk.expand(b"chaperone-vault-stretch", &mut okm)
        .expect("HKDF expansion to 64 bytes is guaranteed to succeed");

    let mut enc_key = [0u8; 32];
    let mut mac_key = [0u8; 32];
    enc_key.copy_from_slice(&okm[0..32]);
    mac_key.copy_from_slice(&okm[32..64]);

    (enc_key, mac_key)
}

pub fn encrypt_protected_vault_key(
    stretched_key: &([u8; 32], [u8; 32]),
    vault_key: &[u8; 32],
) -> Result<(Vec<u8>, [u8; 12]), CryptoError> {
    encrypt_block(&stretched_key.0, vault_key)
}

pub fn decrypt_protected_vault_key(
    stretched_key: &([u8; 32], [u8; 32]),
    ciphertext: &[u8],
    nonce_bytes: &[u8; 12],
) -> Result<[u8; 32], CryptoError> {
    let decrypted = decrypt_block(&stretched_key.0, ciphertext, nonce_bytes)?;
    if decrypted.len() != 32 {
        return Err(CryptoError::Other(
            "Decrypted vault key has invalid length".into(),
        ));
    }
    let mut vault_key = [0u8; 32];
    vault_key.copy_from_slice(&decrypted);
    Ok(vault_key)
}

fn encrypt_block(
    key_bytes: &[u8; 32],
    plaintext: &[u8],
) -> Result<(Vec<u8>, [u8; 12]), CryptoError> {
    let rng = SystemRandom::new();
    let mut nonce_bytes = [0u8; 12];
    rng.fill(&mut nonce_bytes)
        .map_err(|e| CryptoError::Aead(e.to_string()))?;

    let unbound_key = UnboundKey::new(&aead::CHACHA20_POLY1305, key_bytes)
        .map_err(|e| CryptoError::Aead(e.to_string()))?;
    let sealing_key = LessSafeKey::new(unbound_key);
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    let mut in_out = plaintext.to_vec();
    sealing_key
        .seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
        .map_err(|e| CryptoError::Aead(e.to_string()))?;

    Ok((in_out, nonce_bytes))
}

fn decrypt_block(
    key_bytes: &[u8; 32],
    ciphertext: &[u8],
    nonce_bytes: &[u8; 12],
) -> Result<Vec<u8>, CryptoError> {
    let unbound_key = UnboundKey::new(&aead::CHACHA20_POLY1305, key_bytes)
        .map_err(|e| CryptoError::Aead(e.to_string()))?;
    let opening_key = LessSafeKey::new(unbound_key);
    let nonce = Nonce::assume_unique_for_key(*nonce_bytes);

    let mut in_out = ciphertext.to_vec();
    let decrypted = opening_key
        .open_in_place(nonce, Aad::empty(), &mut in_out)
        .map_err(|e| CryptoError::Aead(e.to_string()))?;

    Ok(decrypted.to_vec())
}

pub struct VaultStore {
    pub pool: SqlitePool,
}

impl VaultStore {
    /// Opens the SQLite database at the specified path. Creates the database and runs the migration if new.
    pub async fn open(path: &Path) -> Result<Self, VaultError> {
        let path_str = path.to_str().ok_or(VaultError::InvalidPath)?;

        // Ensure parent directories exist
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| VaultError::Other(e.to_string()))?;
        }

        let connection_string = format!("sqlite:{}", path_str);
        let options = SqliteConnectOptions::from_str(&connection_string)?
            .create_if_missing(true)
            .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
            .synchronous(sqlx::sqlite::SqliteSynchronous::Normal);

        let pool = SqlitePool::connect_with(options).await?;

        // Run migrations
        sqlx::migrate!("./migrations").run(&pool).await?;

        Ok(Self { pool })
    }

    /// Checks if the vault header is initialized
    pub async fn is_initialized(&self) -> Result<bool, VaultError> {
        let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM vault_header")
            .fetch_one(&self.pool)
            .await?;
        Ok(row.0 > 0)
    }

    /// Initializes the vault with the given PIN and returns the generated random vault key.
    pub async fn initialize_vault(&self, pin: &[u8]) -> Result<[u8; 32], VaultError> {
        let mut salt = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut salt);

        let master_key = derive_master_key(pin, &salt)?;
        let stretched = stretch_key(&master_key);

        let mut vault_key = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut vault_key);

        let (ciphertext, nonce) = encrypt_protected_vault_key(&stretched, &vault_key)?;
        let mut protected_vault_key = nonce.to_vec();
        protected_vault_key.extend_from_slice(&ciphertext);

        let check_block = b"chaperone-vault-check-bytes-3210";
        let (check_ct, check_nonce) = encrypt_block(&stretched.1, check_block)?;
        let mut secret_key_check = check_nonce.to_vec();
        secret_key_check.extend_from_slice(&check_ct);

        let kdf_params = format!(
            "m={},t={},p={},salt={}",
            ARGON2_M_COST,
            ARGON2_T_COST,
            ARGON2_P_COST,
            bs58::encode(salt).into_string()
        );

        sqlx::query(
            "INSERT INTO vault_header (schema_version, kdf_algo, kdf_params, protected_vault_key, secret_key_check) \
             VALUES ($1, $2, $3, $4, $5)"
        )
        .bind(1i64)
        .bind("argon2id")
        .bind(&kdf_params)
        .bind(&protected_vault_key)
        .bind(&secret_key_check)
        .execute(&self.pool)
        .await?;

        Ok(vault_key)
    }

    /// Unlocks the vault with the PIN and retrieves the master vault key.
    pub async fn unlock(&self, pin: &[u8]) -> Result<[u8; 32], VaultError> {
        let row: Option<(String, String, Vec<u8>, Vec<u8>)> = sqlx::query_as(
            "SELECT kdf_algo, kdf_params, protected_vault_key, secret_key_check FROM vault_header LIMIT 1"
        )
        .fetch_optional(&self.pool)
        .await?;

        let (_, kdf_params, protected_vault_key, secret_key_check) =
            row.ok_or_else(|| VaultError::Other("Vault not initialized".into()))?;

        // Parse salt
        let salt_b58 = parse_kdf_param(&kdf_params, "salt")?;
        let salt_vec = bs58::decode(salt_b58)
            .into_vec()
            .map_err(|e| VaultError::Other(e.to_string()))?;
        if salt_vec.len() != 16 {
            return Err(VaultError::Other("Invalid salt length in db".into()));
        }
        let mut salt = [0u8; 16];
        salt.copy_from_slice(&salt_vec);

        let master_key = derive_master_key(pin, &salt)?;
        let stretched = stretch_key(&master_key);

        // Verify PIN via secret key check block
        if secret_key_check.len() < 12 {
            return Err(VaultError::Other("Invalid check block length".into()));
        }
        let mut check_nonce = [0u8; 12];
        check_nonce.copy_from_slice(&secret_key_check[0..12]);
        let check_ct = &secret_key_check[12..];

        let check_bytes = decrypt_block(&stretched.1, check_ct, &check_nonce)
            .map_err(|_| VaultError::Crypto(CryptoError::Other("Incorrect PIN".into())))?;

        if check_bytes != b"chaperone-vault-check-bytes-3210" {
            return Err(VaultError::Crypto(CryptoError::Other(
                "Incorrect PIN".into(),
            )));
        }

        // Decrypt vault key
        if protected_vault_key.len() < 12 {
            return Err(VaultError::Other("Invalid protected key length".into()));
        }
        let mut vault_nonce = [0u8; 12];
        vault_nonce.copy_from_slice(&protected_vault_key[0..12]);
        let vault_ct = &protected_vault_key[12..];

        let vault_key = decrypt_protected_vault_key(&stretched, vault_ct, &vault_nonce)?;
        Ok(vault_key)
    }

    pub fn encrypt_row(
        &self,
        vault_key: &[u8; 32],
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, [u8; 12]), VaultError> {
        let (ct, nonce) = encrypt_block(vault_key, plaintext)?;
        Ok((ct, nonce))
    }

    pub fn decrypt_row(
        &self,
        vault_key: &[u8; 32],
        ciphertext: &[u8],
        nonce: &[u8; 12],
    ) -> Result<Vec<u8>, VaultError> {
        let pt = decrypt_block(vault_key, ciphertext, nonce)?;
        Ok(pt)
    }

    /// Encrypts and inserts/updates a credential.
    pub async fn insert_credential(
        &self,
        vault_key: &[u8; 32],
        id: &[u8],
        plaintext: &[u8],
    ) -> Result<(), VaultError> {
        let (ciphertext, nonce) = self.encrypt_row(vault_key, plaintext)?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| VaultError::Other(e.to_string()))?
            .as_secs() as i64;

        sqlx::query(
            "INSERT INTO credentials (id, ciphertext, nonce, created_at) \
             VALUES ($1, $2, $3, $4) \
             ON CONFLICT(id) DO UPDATE SET \
               ciphertext = excluded.ciphertext, \
               nonce = excluded.nonce, \
               created_at = excluded.created_at",
        )
        .bind(id)
        .bind(&ciphertext)
        .bind(&nonce[..])
        .bind(now)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Reads and decrypts a credential.
    pub async fn read_credential(
        &self,
        vault_key: &[u8; 32],
        id: &[u8],
    ) -> Result<Vec<u8>, VaultError> {
        let row: Option<(Vec<u8>, Vec<u8>)> =
            sqlx::query_as("SELECT ciphertext, nonce FROM credentials WHERE id = $1")
                .bind(id)
                .fetch_optional(&self.pool)
                .await?;

        match row {
            Some((ciphertext, nonce_bytes)) => {
                if nonce_bytes.len() != 12 {
                    return Err(VaultError::Other("Invalid nonce length in db".into()));
                }
                let mut nonce = [0u8; 12];
                nonce.copy_from_slice(&nonce_bytes);
                let pt = self.decrypt_row(vault_key, &ciphertext, &nonce)?;
                Ok(pt)
            }
            None => Err(VaultError::NotFound),
        }
    }
}

fn parse_kdf_param(params: &str, key: &str) -> Result<String, VaultError> {
    for part in params.split(',') {
        let kv: Vec<&str> = part.split('=').collect();
        if kv.len() == 2 && kv[0] == key {
            return Ok(kv[1].to_string());
        }
    }
    Err(VaultError::Other(format!("Missing parameter: {}", key)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile;

    #[test]
    fn test_vectors_conform_to_fixed_outputs() {
        let pin = b"supersecretpin123";
        let salt = [1u8; 16];

        let master = derive_master_key(pin, &salt).unwrap();
        assert_eq!(
            master,
            [
                38, 214, 243, 98, 109, 159, 234, 106, 8, 127, 243, 158, 113, 189, 116, 214, 34,
                201, 112, 154, 167, 87, 225, 56, 233, 105, 61, 246, 4, 166, 51, 32
            ]
        );

        let (enc, mac) = stretch_key(&master);
        assert_eq!(
            enc,
            [
                138, 226, 18, 57, 182, 6, 178, 134, 194, 187, 71, 8, 250, 52, 66, 196, 157, 6, 92,
                212, 17, 165, 224, 194, 115, 46, 137, 58, 176, 43, 221, 41
            ]
        );
        assert_eq!(
            mac,
            [
                197, 224, 40, 135, 86, 149, 149, 176, 125, 56, 128, 144, 22, 164, 120, 176, 160,
                12, 80, 83, 178, 54, 152, 174, 147, 146, 10, 183, 120, 127, 163, 41
            ]
        );
    }

    #[tokio::test]
    async fn test_unlock_with_correct_pin_succeeds() {
        let temp_dir = tempfile::tempdir().unwrap();
        let db_path = temp_dir.path().join("test_unlock_success.db");
        let store = VaultStore::open(&db_path).await.unwrap();

        let pin = b"mypassword123";
        assert!(!store.is_initialized().await.unwrap());

        // Initialize vault
        let vault_key = store.initialize_vault(pin).await.unwrap();
        assert!(store.is_initialized().await.unwrap());

        // Unlock vault
        let unlocked_key = store.unlock(pin).await.unwrap();
        assert_eq!(vault_key, unlocked_key);
    }

    #[tokio::test]
    async fn test_unlock_with_wrong_pin_fails_cleanly() {
        let temp_dir = tempfile::tempdir().unwrap();
        let db_path = temp_dir.path().join("test_unlock_fail.db");
        let store = VaultStore::open(&db_path).await.unwrap();

        let pin = b"mypassword123";
        let wrong_pin = b"wrongpassword123";

        // Initialize
        store.initialize_vault(pin).await.unwrap();

        // Unlock with wrong PIN
        let res = store.unlock(wrong_pin).await;
        assert!(res.is_err());

        // Ensure it failed cleanly with a Crypto/Other error and not a panic
        match res.unwrap_err() {
            VaultError::Crypto(_) | VaultError::Other(_) => {}
            other => panic!("Expected crypto or other error, got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_encrypt_decrypt_row_different_ciphertexts_proves_unique_nonces() {
        let temp_dir = tempfile::tempdir().unwrap();
        let db_path = temp_dir.path().join("test_row_encryption.db");
        let store = VaultStore::open(&db_path).await.unwrap();

        let vault_key = [7u8; 32];
        let plaintext = b"credential-payload-bytes";

        // Encrypt twice
        let (ct1, nonce1) = store.encrypt_row(&vault_key, plaintext).unwrap();
        let (ct2, nonce2) = store.encrypt_row(&vault_key, plaintext).unwrap();

        // Assert nonces are unique (CSPRNG generated)
        assert_ne!(nonce1, nonce2);
        // Assert ciphertexts differ because nonces differ
        assert_ne!(ct1, ct2);

        // Decrypt both back to the same plaintext
        let pt1 = store.decrypt_row(&vault_key, &ct1, &nonce1).unwrap();
        let pt2 = store.decrypt_row(&vault_key, &ct2, &nonce2).unwrap();

        assert_eq!(pt1, plaintext);
        assert_eq!(pt2, plaintext);
    }

    #[tokio::test]
    async fn test_database_round_trip_encrypted_credentials() {
        let temp_dir = tempfile::tempdir().unwrap();
        let db_path = temp_dir.path().join("test_db_round_trip.db");
        let store = VaultStore::open(&db_path).await.unwrap();

        let vault_key = [15u8; 32];
        let id = b"service-id-abc";
        let secret = b"my-extremely-secret-token";

        store
            .insert_credential(&vault_key, id, secret)
            .await
            .unwrap();
        let retrieved = store.read_credential(&vault_key, id).await.unwrap();

        assert_eq!(retrieved, secret);

        // Asserting that querying raw SQLite data yields only encrypted ciphertext
        let raw_ct: Vec<u8> =
            sqlx::query_scalar("SELECT ciphertext FROM credentials WHERE id = $1")
                .bind(&id[..])
                .fetch_one(&store.pool)
                .await
                .unwrap();

        assert_ne!(raw_ct, secret);
    }

    #[tokio::test]
    async fn sqlite_schema_conforms_exactly() {
        let temp_dir = tempfile::tempdir().unwrap();
        let db_path = temp_dir.path().join("test_schema.db");
        let store = VaultStore::open(&db_path).await.unwrap();

        // Verify columns of vault_header table
        let cols_header: Vec<(i64, String, String, i64, Option<String>, i64)> =
            sqlx::query_as("PRAGMA table_info(vault_header)")
                .fetch_all(&store.pool)
                .await
                .unwrap();

        let expected_header = vec![
            ("schema_version", "INTEGER", 1),
            ("kdf_algo", "TEXT", 1),
            ("kdf_params", "TEXT", 1),
            ("protected_vault_key", "BLOB", 1),
            ("secret_key_check", "BLOB", 1),
        ];

        assert_eq!(cols_header.len(), expected_header.len());
        for (idx, (name, ty, notnull)) in expected_header.into_iter().enumerate() {
            assert_eq!(cols_header[idx].1, name);
            assert_eq!(cols_header[idx].2, ty);
            assert_eq!(cols_header[idx].3, notnull);
        }

        // Verify columns of credentials table
        let cols_creds: Vec<(i64, String, String, i64, Option<String>, i64)> =
            sqlx::query_as("PRAGMA table_info(credentials)")
                .fetch_all(&store.pool)
                .await
                .unwrap();

        let expected_creds = vec![
            ("id", "BLOB", 0, 1),
            ("ciphertext", "BLOB", 1, 0),
            ("nonce", "BLOB", 1, 0),
            ("created_at", "INTEGER", 1, 0),
        ];

        assert_eq!(cols_creds.len(), expected_creds.len());
        for (idx, (name, ty, notnull, pk)) in expected_creds.into_iter().enumerate() {
            assert_eq!(cols_creds[idx].1, name);
            assert_eq!(cols_creds[idx].2, ty);
            assert_eq!(cols_creds[idx].3, notnull);
            assert_eq!(cols_creds[idx].5, pk);
        }
    }
}
