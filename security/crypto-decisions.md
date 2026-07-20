# Cryptographic Decisions: AEAD Selection

This document records the design evaluation and final decision for the AEAD (Authenticated Encryption with Associated Data) implementation for Chaperone's Encrypted Local Vault (Feature F03).

## Candidates Evaluated

We evaluated two modern, production-grade cryptographic libraries in the Rust ecosystem that provide `ChaCha20-Poly1305` encryption: `ring` and `aws-lc-rs`.

### 1. `ring` (v0.17)

- **Description**: A focused, high-performance cryptography library based on BoringSSL, rewritten and exposed in Rust.
- **Platform Support**: Broad platform coverage (Windows, macOS, Linux, iOS, Android, and WASM) with heavily optimized assembly implementations.
- **Maintenance**: Mature, stable, and widely trusted. Used by core ecosystem components like `rustls` (historically) and `sct`.
- **Build Requirements**: Compiles out-of-the-box on most platforms with standard C toolchains. Does not require advanced build tools like `cmake`.
- **API Ergonomics**: Opinionated, secure-by-default API. Restricts raw pointer/key access, encouraging safe usage patterns.

### 2. `aws-lc-rs` (v1.x)

- **Description**: AWS-maintained cryptographic library for Rust based on AWS-LC (BoringSSL fork). Now the default cryptography provider for `rustls` (v0.23+).
- **Platform Support**: Extensive, with optimized assembly for major CPU architectures (x86_64, aarch64).
- **Maintenance**: Extremely active maintenance backed by AWS, with formal verification of certain primitives and FIPS-140-3 validation paths.
- **Build Requirements**: Heavily relies on `cmake`, a C compiler, and sometimes Perl to compile its underlying C/assembly sources. This adds compile-time dependencies that can fail on minimal build environments or lock down developer onboarding.
- **API Ergonomics**: Implements ring-compatible APIs as well as standard RustCrypto wrappers.

---

## Evaluation Matrix

| Criterion | `ring` | `aws-lc-rs` |
| :--- | :--- | :--- |
| **ChaCha20-Poly1305 Performance** | High | High (comparable) |
| **Dependency Bloat** | Low (already in Chaperone's workspace graph) | Medium (requires new native bindings) |
| **Build System Simplicity** | Simple (standard compiler) | Complex (requires `cmake` + C compiler) |
| **FIPS-140-3 Requirements** | Not planned for Walking Skeleton | Available (if needed later) |
| **Active Maintenance** | Stable / Maintenance Mode | High |

---

## Final Decision

We selected **`ring`** as the primary AEAD provider for the Chaperone Local Vault.

### Rationale

1. **Zero Native Build Overhead**: `aws-lc-rs` requires `cmake` to compile on Windows/Linux. Forcing this dependency would break Chaperone's "zero-config checkout-and-run" goal for new developers and simple CI runners. `ring` compiles cleanly with the standard Rust toolchain.
2. **Existing Workspace Dependency**: `ring` is already compiled and present in our Cargo workspace transitively (pulled in by our `libp2p` and transport dependencies). Reusing it directly avoids compiling a second cryptographic engine, keeping the final binary size small.
3. **API Ergonomics**: `ring`'s AEAD API enforces strict key handling, preventing developers from accidentally leaking or modifying keying material in memory, which aligns perfectly with F03's security constraints.

---

## Post-Quantum KEM Selection (Feature F04 / BU-203)

This section records the design evaluation and final decision for the Post-Quantum Key Encapsulation Mechanism (KEM) implementation for hybrid key exchange.

### Candidates Evaluated

#### 1. `ml-kem` (v0.3.2) by RustCrypto
- **Description**: Pure-Rust implementation of the Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM) standard as described in FIPS 203.
- **Platform Support**: Pure Rust. Fully portable across all targets (Windows, macOS, Linux, WebAssembly) out-of-the-box.
- **Build Requirements**: Does not require any external tools or native toolchain wrappers. Enabling the `"getrandom"` feature integrates the standard platform entropy source.
- **API Ergonomics**: Integrates cleanly with standard `kem` traits (`Kem`, `Encapsulate`, `Decapsulate`).

#### 2. `libcrux-ml-kem`
- **Description**: Formally verified implementation of ML-KEM, including AVX2/NEON vector optimizations.
- **Platform Support**: Portable Rust + target-specific optimizations.
- **Build Requirements**: Relies on more complex build configurations, potentially limiting compilation on non-standard developer setups.

### Final Decision

We selected **`ml-kem`** v0.3.2 by RustCrypto.

### Rationale

1. **Zero Native/Compilation Dependencies**: To maintain a clean, zero-config build system (especially in CI environments), we prioritize pure-Rust crates that do not require building C++ submodules or using tools like `cmake`.
2. **Standard Compatibility**: The `ml-kem` crate conforms precisely to the final FIPS 203 specification, ensuring correct wire compatibility and security bounds.
3. **Ergonomic Integration**: Its re-export of `kem` traits and straightforward API allow clean integration with our X3DH implementation.

