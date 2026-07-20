#![no_main]
use libfuzzer_sys::fuzz_target;

use chaperone_core::handshake::{finalize_initiator, initiate, respond, HandshakeInit, Session};
use chaperone_core::identity::LocalIdentity;
use std::sync::OnceLock;

static HARNESS_SETUP: OnceLock<(LocalIdentity, HandshakeInit, Session, [u8; 1184])> = OnceLock::new();

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    let (bob_identity, base_init, alice_provisional_session, bob_pq_pub) =
        HARNESS_SETUP.get_or_init(|| {
            // Force dynamic keychain backend to use MockKeychainBackend
            std::env::set_var("CHAPERONE_MOCK_KEYCHAIN", "1");
            // Setup Bob (PQ Capable)
            chaperone_core::identity::get_keychain().reset();
            let bob_identity = LocalIdentity::bootstrap_with_seed([2u8; 32]).unwrap();
            let (bob_prekey_pub, bob_prekey_sig, bob_pq_pub) =
                bob_identity.generate_and_save_signed_prekey().unwrap();
            let bob_identity_pub = bob_identity.public_agreement_key().unwrap();

            // Backup Bob's credentials from keychain
            let mut backup = std::collections::HashMap::new();
            let keychain = chaperone_core::identity::get_keychain();
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

            // Reset keychain and bootstrap Alice
            keychain.reset();
            let alice_identity = LocalIdentity::bootstrap_with_seed([1u8; 32]).unwrap();
            let (mut init, session) = initiate(
                &alice_identity,
                bob_identity_pub,
                bob_prekey_pub,
                Some(bob_pq_pub),
                true, // Alice supports PQ
            );
            init.signed_prekey_sig = bob_prekey_sig;

            // Restore Bob's credentials in keychain so respond() can access them
            keychain.reset();
            for (key, val) in &backup {
                keychain.set_password(key, "default", val).unwrap();
            }

            (bob_identity, init, session, bob_pq_pub)
        });

    let mut mutated_init = base_init.clone();
    let strategy = data[0] % 8;
    let payload = &data[1..];



    match strategy {
        0 => {
            // Strip PQ capability
            mutated_init.capabilities.retain(|c| c != "PQ_MLKEM_768");
        }
        1 => {
            // Strip KEM ciphertext
            mutated_init.pq_kem_ciphertext = None;
        }
        2 => {
            // Strip both
            mutated_init.capabilities.retain(|c| c != "PQ_MLKEM_768");
            mutated_init.pq_kem_ciphertext = None;
        }
        3 => {
            // Corrupt capabilities field with fuzzer strings
            mutated_init.capabilities.clear();
            if !payload.is_empty() {
                if let Ok(s) = std::str::from_utf8(payload) {
                    for chunk in s.split(',') {
                        mutated_init.capabilities.push(chunk.to_string());
                    }
                }
            }
        }
        4 => {
            // Corrupt KEM ciphertext content but keep length 1088
            if let Some(ref mut ct) = mutated_init.pq_kem_ciphertext {
                if !payload.is_empty() {
                    for (i, &byte) in payload.iter().enumerate() {
                        let idx = i % ct.len();
                        ct[idx] ^= byte;
                    }

            }
        }
        5 => {
            // Change KEM ciphertext length or replace it entirely
            mutated_init.pq_kem_ciphertext = Some(payload.to_vec());
        }
        6 => {
            // Empty capabilities with corrupted ciphertext
            mutated_init.capabilities.clear();
            if let Some(ref mut ct) = mutated_init.pq_kem_ciphertext {
                if !payload.is_empty() {
                    ct.copy_from_slice(&[0u8; 1088]);
                }
            }
        }
        7 => {
            // Claim PQ capability with empty/mutated ciphertext
            mutated_init.capabilities = vec!["PQ_MLKEM_768".to_string()];
            if let Some(ref mut ct) = mutated_init.pq_kem_ciphertext {
                if !payload.is_empty() {
                    let idx = (payload[0] as usize) % ct.len();
                    ct[idx] ^= 0x55;
                } else {
                    mutated_init.pq_kem_ciphertext = None;
                }
            }
        }
        _ => unreachable!(),
    }

    let is_mutated = mutated_init.capabilities != base_init.capabilities
        || mutated_init.pq_kem_ciphertext != base_init.pq_kem_ciphertext;

    let is_pq_stripped = !mutated_init.capabilities.contains(&"PQ_MLKEM_768".to_string())
        || mutated_init.pq_kem_ciphertext.is_none()
        || mutated_init.pq_kem_ciphertext.as_ref().map_or(true, |c| c.is_empty());

    // Call respond() under test
    match respond(bob_identity, &mutated_init, true) {
        Ok((response, bob_session)) => {
            if is_pq_stripped {
                // If the PQ leg was stripped or missing, Bob MUST negotiate classical-only
                assert!(
                    bob_session.is_classical_only,
                    "Bob negotiated PQ-hybrid despite stripped PQ leg! Capabilities: {:?}, CT: {:?}",
                    mutated_init.capabilities,
                    mutated_init.pq_kem_ciphertext
                );
            }

            // Emulate Alice loading her private agreement key to finalize
            // For a valid DH1, we can compute it using Bob's prekey pub (unmutated)
            // Alice's finalization check will verify capability agreement and reject/downgrade appropriately
            let dh_dummy = [0u8; 32];
            let alice_final_res = finalize_initiator(
                true, // Alice supports PQ
                Some(*bob_pq_pub),
                alice_provisional_session,
                &response,
                &dh_dummy,
                &dh_dummy,
                &dh_dummy,
                mutated_init.pq_kem_ciphertext.as_deref(),
            );

            if let Ok(alice_session) = alice_final_res {
                // Bob and Alice MUST agree on the session type
                assert_eq!(
                    bob_session.is_classical_only,
                    alice_session.is_classical_only,
                    "Alice and Bob mismatched on classical/hybrid status!"
                );

                if !bob_session.is_classical_only && is_mutated {
                    // If Bob negotiated hybrid despite mutation (e.g. corrupted ciphertext in strategy 4 or 7),
                    // they MUST NOT agree on the derived session key because Bob decapsulated a mutated ciphertext
                    assert_ne!(
                        bob_session.key,
                        alice_session.key,
                        "Key agreement succeeded with mutated/forged KEM ciphertext!"
                    );
                }
            }
        }
        Err(_) => {
            // Correctly rejected by Bob
        }
    }
});
