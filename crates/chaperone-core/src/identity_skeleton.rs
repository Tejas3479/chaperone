//! SKELETON ONLY — replaced by the real F01 identity system in BU-101. Do not build features on top of this.

use rand::rngs::OsRng;
use rand::RngCore;

pub struct SkeletonIdentity {
    pub pubkey: [u8; 32],
}

impl SkeletonIdentity {
    pub fn generate() -> Self {
        let mut pubkey = [0u8; 32];
        OsRng.fill_bytes(&mut pubkey);
        Self { pubkey }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_generated_identities_differ() {
        let id1 = SkeletonIdentity::generate();
        let id2 = SkeletonIdentity::generate();
        assert_ne!(id1.pubkey, id2.pubkey);
    }
}
