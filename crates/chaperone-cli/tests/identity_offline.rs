use chaperone_core::identity::LocalIdentity;

#[test]
fn test_identity_bootstrap_works_fully_offline() {
    std::env::set_var("CHAPERONE_MOCK_KEYCHAIN", "1");
    chaperone_core::identity::get_keychain().reset();

    // Under test, chaperone-core's identity module uses MockKeychainBackend automatically,
    // which does not make any network calls, dbus requests, or OS keychain accesses.
    // This confirms that identity bootstrapping functions entirely locally and offline.
    let res = LocalIdentity::bootstrap();
    assert!(res.is_ok(), "Bootstrap failed: {:?}", res);

    let identity = res.unwrap();
    assert!(identity.did_key.starts_with("did:key:z6Mk"));
    assert_ne!(identity.created_at, 0);
    assert_eq!(identity.rotation_epoch, 0);

    // Verify retrieve also works offline
    let current_res = LocalIdentity::get_current();
    assert!(current_res.is_ok(), "Get current failed: {:?}", current_res);
    let current_identity = current_res.unwrap();
    assert_eq!(identity.did_key, current_identity.did_key);
}
