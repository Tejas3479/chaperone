use chaperone_core::mesh_skeleton::run_skeleton_ping;

#[tokio::test]
async fn skeleton_ping_e2e() {
    let result = run_skeleton_ping().await;
    assert!(result.is_ok(), "Skeleton ping failed: {:?}", result);
}
