use std::fmt;

#[derive(Clone, Copy)]
pub struct SecretKey {
    bytes: [u8; 16],
}

#[derive(Debug, PartialEq, Eq)]
pub enum SecretKeyError {
    InvalidLength,
    InvalidCharacter,
}

impl fmt::Display for SecretKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength => write!(f, "Invalid secret key length"),
            Self::InvalidCharacter => write!(f, "Invalid base32 character in secret key"),
        }
    }
}

impl std::error::Error for SecretKeyError {}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretKey")
            .field("bytes", &"<redacted>")
            .finish()
    }
}

impl fmt::Display for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<redacted>")
    }
}

impl SecretKey {
    /// Generates a new 128-bit SecretKey using OsRng.
    pub fn generate() -> Self {
        let mut rng = rand::rngs::OsRng;
        Self::generate_with_rng(&mut rng)
    }

    /// Generates a new SecretKey using a specific RngCore (primarily for testing).
    pub fn generate_with_rng<R: rand::RngCore>(rng: &mut R) -> Self {
        let mut bytes = [0u8; 16];
        rng.fill_bytes(&mut bytes);
        Self { bytes }
    }

    /// Renders the SecretKey as a Base32 string grouped in blocks of 4 characters separated by hyphens.
    pub fn to_base32(&self) -> String {
        let unpadded = data_encoding::BASE32_NOPAD.encode(&self.bytes);
        let mut formatted = String::new();
        for (i, ch) in unpadded.chars().enumerate() {
            if i > 0 && i % 4 == 0 {
                formatted.push('-');
            }
            formatted.push(ch);
        }
        formatted
    }

    /// Renders the SecretKey as raw bytes (e.g. for QR encoding).
    pub fn to_bytes(&self) -> [u8; 16] {
        self.bytes
    }

    /// Parses a SecretKey from its Base32 string representation.
    pub fn from_base32(s: &str) -> Result<Self, SecretKeyError> {
        let normalized: String = s
            .chars()
            .filter(|&c| !c.is_whitespace() && c != '-')
            .map(|c| c.to_ascii_uppercase())
            .collect();

        if normalized.len() != 26 {
            return Err(SecretKeyError::InvalidLength);
        }

        let decoded_vec = data_encoding::BASE32_NOPAD
            .decode(normalized.as_bytes())
            .map_err(|_| SecretKeyError::InvalidCharacter)?;

        if decoded_vec.len() != 16 {
            return Err(SecretKeyError::InvalidLength);
        }

        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&decoded_vec);
        Ok(Self { bytes })
    }

    /// Computes the verifier hash of the SecretKey (SHA-256).
    pub fn verifier_hash(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(self.bytes);
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }

    /// Verifies the SecretKey against a stored verifier hash.
    pub fn verify(&self, stored_hash: &[u8; 32]) -> bool {
        let current_hash = self.verifier_hash();

        // Constant-time byte array comparison to prevent timing side-channels
        let mut result = 0u8;
        for (x, y) in current_hash.iter().zip(stored_hash.iter()) {
            result |= x ^ y;
        }
        result == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    #[test]
    fn test_vectors_conform_to_fixed_outputs() {
        // Test with deterministic ChaCha8Rng seed
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(123456789);
        let sk1 = SecretKey::generate_with_rng(&mut rng);
        let sk2 = SecretKey::generate_with_rng(&mut rng);

        // Ensure generation from same seed sequence is consistent across platforms
        assert_eq!(
            sk1.to_bytes(),
            [223, 173, 236, 2, 70, 133, 226, 163, 221, 131, 225, 21, 63, 96, 43, 168]
        );
        assert_eq!(
            sk2.to_bytes(),
            [209, 91, 10, 132, 181, 244, 216, 58, 207, 186, 232, 68, 218, 185, 93, 40]
        );

        // Base32 representation grouping check
        assert_eq!(sk1.to_base32(), "36W6-YASG-QXRK-HXMD-4EKT-6YBL-VA");
        assert_eq!(sk2.to_base32(), "2FNQ-VBFV-6TMD-VT52-5BCN-VOK5-FA");
    }

    #[test]
    fn test_random_generations_differ() {
        let sk1 = SecretKey::generate();
        let sk2 = SecretKey::generate();
        assert_ne!(sk1.to_bytes(), sk2.to_bytes());
    }

    #[test]
    fn test_parse_various_base32_input_formats() {
        let sk = SecretKey::generate();
        let formatted = sk.to_base32();

        // Standard hyphenated format
        let parsed1 = SecretKey::from_base32(&formatted).unwrap();
        assert_eq!(parsed1.to_bytes(), sk.to_bytes());

        // Lowercase, space separated, and no-separator formats
        let parsed2 = SecretKey::from_base32(&formatted.to_lowercase()).unwrap();
        let parsed3 = SecretKey::from_base32(&formatted.replace('-', " ")).unwrap();
        let parsed4 = SecretKey::from_base32(&formatted.replace('-', "")).unwrap();

        assert_eq!(parsed2.to_bytes(), sk.to_bytes());
        assert_eq!(parsed3.to_bytes(), sk.to_bytes());
        assert_eq!(parsed4.to_bytes(), sk.to_bytes());

        // Invalid formats
        assert!(SecretKey::from_base32("too-short").is_err());

        // Guarantee an invalid character by replacing the first character with '8'
        let mut invalid_char_str = formatted.clone();
        invalid_char_str.replace_range(0..1, "8");
        assert!(SecretKey::from_base32(&invalid_char_str).is_err());
    }

    #[test]
    fn test_verification_hash_matching() {
        let sk = SecretKey::generate();
        let hash = sk.verifier_hash();

        // Valid key verify
        assert!(sk.verify(&hash));

        // Invalid key verify
        let other = SecretKey::generate();
        assert!(!other.verify(&hash));
    }

    #[test]
    fn test_raw_bytes_not_in_debug_or_display() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);
        let sk = SecretKey::generate_with_rng(&mut rng);
        let debug_str = format!("{:?}", sk);
        let display_str = format!("{}", sk);

        // Ensure key bytes and base32 rendering are redacted
        assert!(!debug_str.contains("QDYG"));
        assert!(!display_str.contains("QDYG"));
        assert!(debug_str.contains("<redacted>"));
        assert!(display_str.contains("<redacted>"));
    }

    #[test]
    fn test_entropy_statistical_distribution() {
        // Generate 1000 keys (16,000 bytes)
        let num_keys = 1000;
        let mut counts = [0usize; 256];
        for _ in 0..num_keys {
            let sk = SecretKey::generate();
            for &b in &sk.to_bytes() {
                counts[b as usize] += 1;
            }
        }

        // Expected frequency per byte bin is 16,000 / 256 = 62.5
        let total_bytes = (num_keys * 16) as f64;
        let expected = total_bytes / 256.0;

        // Compute Chi-squared statistic
        let mut chi_squared = 0.0;
        for &count in &counts {
            let diff = count as f64 - expected;
            chi_squared += (diff * diff) / expected;
        }

        // Degrees of freedom is 255. Critical value at alpha = 0.01 is 310.457
        assert!(
            chi_squared < 310.457,
            "Chi-squared statistic ({}) exceeded critical value for uniformity threshold!",
            chi_squared
        );
    }

    #[test]
    fn test_static_code_analysis_secretkey_does_not_derive_debug_or_display() {
        let code = include_str!("secret_key.rs");

        // Ensure no auto-deriving of Debug or Display on SecretKey
        let mut struct_found = false;
        let mut derive_before_struct = false;
        let mut lines_buffer = Vec::new();

        for line in code.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("#[derive(") {
                lines_buffer.push(trimmed.to_string());
            } else if trimmed.starts_with("pub struct SecretKey") {
                struct_found = true;
                for d in &lines_buffer {
                    if d.contains("Debug") || d.contains("Display") {
                        derive_before_struct = true;
                    }
                }
                break;
            } else {
                lines_buffer.clear();
            }
        }

        assert!(
            struct_found,
            "Could not locate SecretKey struct in source file"
        );
        assert!(
            !derive_before_struct,
            "SecretKey struct should NOT derive Debug or Display automatically!"
        );
    }
}
