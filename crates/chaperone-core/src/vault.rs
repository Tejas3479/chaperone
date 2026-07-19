use sqlx::sqlite::SqliteConnectOptions;
use sqlx::{Pool, Sqlite, SqlitePool};
use std::error::Error;
use std::fmt;
use std::path::Path;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug)]
pub enum VaultError {
    Database(sqlx::Error),
    Migration(sqlx::migrate::MigrateError),
    InvalidPath,
    NotFound,
    Other(String),
}

impl fmt::Display for VaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Database(e) => write!(f, "Database error: {}", e),
            Self::Migration(e) => write!(f, "Migration error: {}", e),
            Self::InvalidPath => write!(f, "Invalid database path"),
            Self::NotFound => write!(f, "Credential not found"),
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

    /// Inserts a raw unencrypted credential (mock scaffolding for BU-102 verification).
    pub async fn insert_raw_credential(
        &self,
        id: &[u8],
        plaintext_bytes: &[u8],
    ) -> Result<(), VaultError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| VaultError::Other(e.to_string()))?
            .as_secs() as i64;
        let empty_nonce = b"";

        sqlx::query(
            "INSERT INTO credentials (id, ciphertext, nonce, created_at) \
             VALUES ($1, $2, $3, $4) \
             ON CONFLICT(id) DO UPDATE SET \
               ciphertext = excluded.ciphertext, \
               nonce = excluded.nonce, \
               created_at = excluded.created_at",
        )
        .bind(id)
        .bind(plaintext_bytes)
        .bind(empty_nonce)
        .bind(now)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Reads a raw unencrypted credential (mock scaffolding for BU-102 verification).
    pub async fn read_raw_credential(&self, id: &[u8]) -> Result<Vec<u8>, VaultError> {
        let row: Option<(Vec<u8>,)> =
            sqlx::query_as("SELECT ciphertext FROM credentials WHERE id = $1")
                .bind(id)
                .fetch_optional(&self.pool)
                .await?;

        match row {
            Some((ciphertext,)) => Ok(ciphertext),
            None => Err(VaultError::NotFound),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile;

    #[tokio::test]
    async fn migration_applies_cleanly_and_reopen_succeeds() {
        let temp_dir = tempfile::tempdir().unwrap();
        let db_path = temp_dir.path().join("test_vault.db");

        // 1. Open first time (runs migrations)
        {
            let store = VaultStore::open(&db_path).await.unwrap();
            let id = b"test-id-1";
            let secret = b"secret-payload-123";
            store.insert_raw_credential(id, secret).await.unwrap();

            let retrieved = store.read_raw_credential(id).await.unwrap();
            assert_eq!(retrieved, secret);
        }

        // 2. Re-open second time (should connect without failing or re-migrating)
        {
            let store = VaultStore::open(&db_path).await.unwrap();
            let id = b"test-id-1";
            let secret = b"secret-payload-123";
            let retrieved = store.read_raw_credential(id).await.unwrap();
            assert_eq!(retrieved, secret);
        }
    }

    #[tokio::test]
    async fn round_trip_credential_matches_exactly() {
        let temp_dir = tempfile::tempdir().unwrap();
        let db_path = temp_dir.path().join("test_round_trip.db");
        let store = VaultStore::open(&db_path).await.unwrap();

        let id = b"another-id-99";
        let secret = vec![0xaa, 0xbb, 0xcc, 0xdd, 0x00, 0xff];

        store.insert_raw_credential(id, &secret).await.unwrap();
        let retrieved = store.read_raw_credential(id).await.unwrap();
        assert_eq!(retrieved, secret);
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
            ("id", "BLOB", 1, 1),
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
