pub use prost;

pub mod handshake {
    include!(concat!(env!("OUT_DIR"), "/chaperone.protocol.rs"));
}
