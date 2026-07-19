#![no_main]
use libfuzzer_sys::fuzz_target;
use chaperone_core::vault::{derive_master_key, stretch_key, encrypt_protected_vault_key};

fuzz_target!(|data: &[u8]| {
    if data.len() < 32 {
        return;
    }

    let pin = &data[0..data.len() - 16];
    let mut salt = [0u8; 16];
    salt.copy_from_slice(&data[data.len() - 16..]);

    // Derive master key
    if let Ok(master) = derive_master_key(pin, &salt) {
        let stretched = stretch_key(&master);
        let vault_key = [0u8; 32];

        if let Ok((ct1, nonce1)) = encrypt_protected_vault_key(&stretched, &vault_key) {
            if let Ok((ct2, nonce2)) = encrypt_protected_vault_key(&stretched, &vault_key) {
                // Assert that nonces are never reused and ciphertexts differ
                assert_ne!(nonce1, nonce2);
                assert_ne!(ct1, ct2);
            }
        }
    }
});
