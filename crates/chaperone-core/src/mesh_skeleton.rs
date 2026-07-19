//! SKELETON ONLY — replaced by the real F02/F03 mesh layers in later BUs. Do not build features on top of this.

use libp2p::swarm::dummy::Behaviour as DummyBehaviour;
use libp2p::{Multiaddr, Swarm, SwarmBuilder};
use std::error::Error;

/// Bootstraps a skeleton libp2p Swarm binding to an ephemeral localhost port.
///
/// Note: The Swarm generates a new random transport-layer keypair (identity) which is
/// completely separate from our application-layer `SkeletonIdentity` (BU-004).
pub async fn bootstrap_swarm() -> Result<Swarm<DummyBehaviour>, Box<dyn Error>> {
    let mut swarm = SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_quic()
        .with_behaviour(|_key| DummyBehaviour)?
        .build();

    // Bind to an ephemeral port on loopback 127.0.0.1 using QUIC transport multiaddress.
    let listen_addr: Multiaddr = "/ip4/127.0.0.1/udp/0/quic-v1".parse()?;
    swarm.listen_on(listen_addr)?;

    Ok(swarm)
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::StreamExt;
    use libp2p::swarm::SwarmEvent;

    #[tokio::test]
    async fn swarm_binds_and_reports_address() {
        let mut swarm = bootstrap_swarm().await.expect("Failed to bootstrap swarm");
        let mut bound_address = None;

        // Poll the swarm until a NewListenAddr event fires
        for _ in 0..40 {
            // prevent infinite loop
            tokio::select! {
                event = swarm.select_next_some() => {
                    if let SwarmEvent::NewListenAddr { address, .. } = event {
                        bound_address = Some(address);
                        break;
                    }
                }
                _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => {
                    // Short sleep slice
                }
            }
        }

        let address = bound_address.expect("Did not receive NewListenAddr event");
        assert!(!address.to_string().is_empty());
        println!("Swarm successfully bound to address: {}", address);
    }
}
