# Logging Safety & Code-Review Checklist

This document details the automated checks and the manual review checklist implemented in Chaperone (BU-201) to ensure no sensitive key material, PINs, secret keys, or credentials leak into application logs.

## Automated Guardrails

We have implemented a CI-enforced static analysis check in `crates/chaperone-core/tests/logging_static_check.rs` that automatically scans all Rust files in the workspace:
1. **Field Scan**: Identifies all structs and checks if any field contains sensitive keywords (`secret`, `private`, `privkey`, `priv_key`, `pin`, `seed`, `vault_key`, `passphrase`, `password`, `credential`).
2. **Scrubbed Check**: Asserts that any matched sensitive field is wrapped in `Scrubbed<T>` (which formats to `[SCRUBBED]` in its `Debug` implementation) or is explicitly added to the narrow whitelist.
3. **Whitelist Audit**: Ensures only public fields (like `new_pubkey`, `signed_by_previous_key`, `did_key`) are bypassed.

---

## Manual Code-Review Checklist

While the automated check catches struct field definitions, certain leaks cannot be statically verified by a simple struct scan. Developers and code reviewers must manually verify the following items before merging changes:

### 1. Direct Variable Logging
* **Check**: Ensure that local variables representing raw keys, PINs, or secret bytes are never logged directly.
* **Bad**:
  ```rust
  tracing::info!(pin = ?raw_pin, "user set pin"); // Leak!
  ```
* **Good**:
  ```rust
  tracing::info!("user set pin"); // No variables logged
  // Or:
  let scrubbed_pin = Scrubbed(raw_pin);
  tracing::info!(pin = ?scrubbed_pin, "user set pin");
  ```

### 2. Custom Format Strings
* **Check**: Ensure that custom `format!` or print statements do not output raw sensitive variables.
* **Bad**:
  ```rust
  let msg = format!("Deriving key from pin: {:?}", pin);
  ```
* **Good**:
  ```rust
  let msg = format!("Deriving key from pin: [SCRUBBED]");
  ```

### 3. Log Sinks Audit
* **Check**: Ensure that no network sinks (e.g., external telemetry, crash reporting, HTTP hooks) are configured or added to the logging subscriber.
* **Constraint**: In Stage 2, logs are strictly local and rotating only. Network sinks are out of scope and require explicit security architecture review for Stage 8.

### 4. Whitelist Additions
* **Check**: Any addition to the `whitelist` inside `logging_static_check.rs` must be reviewed to guarantee the field contains only public/non-sensitive data (e.g. public keys, signatures, creation timestamps, and IDs).
