CREATE TABLE vault_header (
  schema_version INTEGER NOT NULL,
  kdf_algo TEXT NOT NULL,
  kdf_params TEXT NOT NULL,
  protected_vault_key BLOB NOT NULL,
  secret_key_check BLOB NOT NULL
);
CREATE TABLE credentials (
  id BLOB PRIMARY KEY,
  ciphertext BLOB NOT NULL,
  nonce BLOB NOT NULL,
  created_at INTEGER NOT NULL
);
