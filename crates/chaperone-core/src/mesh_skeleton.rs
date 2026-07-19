//! SKELETON ONLY — replaced by the real F02/F03 mesh layers in later BUs. Do not build features on top of this.

use libp2p::request_response;
use libp2p::swarm::NetworkBehaviour;
use libp2p::swarm::SwarmEvent;
use libp2p::{Multiaddr, StreamProtocol, Swarm, SwarmBuilder};
use serde::{Deserialize, Serialize};
use std::error::Error;
use tokio::sync::oneshot;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PingRequest {
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PingResponse {
    pub message: String,
}

#[derive(NetworkBehaviour)]
pub struct SkeletonBehaviour {
    pub request_response: request_response::json::Behaviour<PingRequest, PingResponse>,
}

/// Bootstraps a skeleton libp2p Swarm binding to an ephemeral localhost port.
///
/// Note: The Swarm generates a new random transport-layer keypair (identity) which is
/// completely separate from our application-layer `SkeletonIdentity` (BU-004).
pub async fn bootstrap_swarm() -> Result<Swarm<SkeletonBehaviour>, Box<dyn Error>> {
    let mut swarm = SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_quic()
        .with_behaviour(|_key| {
            let protocols = std::iter::once((
                StreamProtocol::new("/chaperone/skeleton-ping/1.0.0"),
                request_response::ProtocolSupport::Full,
            ));
            let config = request_response::Config::default();
            SkeletonBehaviour {
                request_response: request_response::json::Behaviour::new(protocols, config),
            }
        })?
        .build();

    // Bind to an ephemeral port on loopback 127.0.0.1 using QUIC transport multiaddress.
    let listen_addr: Multiaddr = "/ip4/127.0.0.1/udp/0/quic-v1".parse()?;
    swarm.listen_on(listen_addr)?;

    Ok(swarm)
}

/// Runs a two-instance ping-pong payload exchange check.
pub async fn run_skeleton_ping() -> Result<(), Box<dyn Error>> {
    let mut swarm_a = bootstrap_swarm().await?;
    let mut swarm_b = bootstrap_swarm().await?;

    let peer_b_id = *swarm_b.local_peer_id();

    // 1. Get bound address of Swarm A
    use futures::StreamExt;
    let mut addr_a = None;
    for _ in 0..40 {
        tokio::select! {
            event = swarm_a.select_next_some() => {
                if let SwarmEvent::NewListenAddr { address, .. } = event {
                    addr_a = Some(address);
                    break;
                }
            }
            _ = tokio::time::sleep(std::time::Duration::from_millis(50)) => {}
        }
    }
    let _addr_a = addr_a.ok_or("Failed to get listen address for Swarm A")?;

    // 2. Get bound address of Swarm B
    let mut addr_b = None;
    for _ in 0..40 {
        tokio::select! {
            event = swarm_b.select_next_some() => {
                if let SwarmEvent::NewListenAddr { address, .. } = event {
                    addr_b = Some(address);
                    break;
                }
            }
            _ = tokio::time::sleep(std::time::Duration::from_millis(50)) => {}
        }
    }
    let addr_b = addr_b.ok_or("Failed to get listen address for Swarm B")?;

    // 3. Swarm A adds Swarm B's address to its routing table
    swarm_a.add_peer_address(peer_b_id, addr_b.clone());

    // 4. Spawn swarm_b event loop in the background to handle the incoming request and reply
    let (tx_result, rx_result) = oneshot::channel();
    let mut tx_result = Some(tx_result);
    let (tx_shutdown, mut rx_shutdown) = oneshot::channel::<()>();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                event = swarm_b.select_next_some() => {
                    if let SwarmEvent::Behaviour(SkeletonBehaviourEvent::RequestResponse(
                        request_response::Event::Message {
                            message: request_response::Message::Request {
                                request,
                                channel,
                                ..
                            },
                            ..
                        }
                    )) = event {
                        if request.message == "hello" {
                            let _ = swarm_b.behaviour_mut().request_response.send_response(
                                channel,
                                PingResponse { message: "world".to_string() }
                            );
                            if let Some(tx) = tx_result.take() {
                                let _ = tx.send(request.message);
                            }
                        }
                    }
                }
                _ = &mut rx_shutdown => {
                    break;
                }
                _ = tokio::time::sleep(std::time::Duration::from_secs(15)) => {
                    break;
                }
            }
        }
    });

    // 5. Send request from A
    swarm_a.behaviour_mut().request_response.send_request(
        &peer_b_id,
        PingRequest {
            message: "hello".to_string(),
        },
    );

    // 6. Poll swarm_a until we receive Response or timeout
    let mut received_response = None;
    for _ in 0..100 {
        tokio::select! {
            event = swarm_a.select_next_some() => {
                if let SwarmEvent::Behaviour(SkeletonBehaviourEvent::RequestResponse(
                    request_response::Event::Message {
                        message: request_response::Message::Response {
                            response,
                            ..
                        },
                        ..
                    }
                )) = event {
                    received_response = Some(response.message);
                    break;
                }
            }
            _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => {}
        }
    }

    // Send shutdown signal to B
    let _ = tx_shutdown.send(());

    // 7. Verify B received request
    let received_request = rx_result.await?;
    if received_request != "hello" {
        return Err("Swarm B did not receive expected request 'hello'".into());
    }

    // 8. Verify A received response
    let response_msg = received_response.ok_or("Swarm A did not receive response")?;
    if response_msg != "world" {
        return Err(format!("Swarm A received unexpected response: {}", response_msg).into());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::StreamExt;

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
