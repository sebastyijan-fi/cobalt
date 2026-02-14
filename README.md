# CBC — Context-Bound Container

A binary container format in which validity and meaning depend on intrinsic relational constraints among blocks. A CBC artifact is **self-validating**, **tamper-evident**, and **provenance-aware** without reliance on external sidecar files, detached signatures, or out-of-band metadata.

**Version:** 0.1.0 — **Status:** Draft

---

## Key Properties

| Property | Mechanism |
|----------|-----------|
| **Integrity** | Hash-chain commitments (Family A) bind every block to a single root |
| **Random-access verification** | Merkle tree (Family B) enables O(log n) range proofs |
| **Structural robustness** | Self-delimiting prefix codes (Family C) enable resynchronization after corruption |
| **Tamper evidence** | Any modification — bit flip, reorder, truncate — invalidates the root |
| **Provenance** | Copying produces a different root; transform receipts link old → new with signatures |

## Quick Start

```bash
# Build
cargo build --workspace

# Run all tests (78 tests)
cargo test --workspace

# Encode a file
cargo run -p cbc-cli -- encode -i myfile.pdf -o myfile.cbc --hash blake3 --families A+B

# Validate
cargo run -p cbc-cli -- validate -i myfile.cbc

# Inspect metadata
cargo run -p cbc-cli -- inspect -i myfile.cbc

# Decode (extract payload)
cargo run -p cbc-cli -- decode -i myfile.cbc -o recovered.pdf

# Transform with receipt (requires signing key)
cargo run -p cbc-cli -- keygen -o mykey --alg ed25519
cargo run -p cbc-cli -- transform -t subrange -i myfile.cbc -o subset.cbc -k mykey --start 0 --end 3
```

## Architecture

```
cobalt/
├── cbc-core/          Core format library
│   ├── bootstrap.rs   64-byte Bootstrap Segment (§5.2)
│   ├── block.rs       Block format with CRC-32C (§5.3)
│   ├── chain.rs       Family A — linear hash-chain commitments (§4.1)
│   ├── merkle.rs      Family B — Merkle tree + range proofs (§4.2)
│   ├── prefix.rs      Family C — prefix parse constraints (§4.3)
│   ├── footer.rs      Stream Footer with footer_commitment (§5.4)
│   ├── encoder.rs     Payload → CBC artifact
│   └── decoder.rs     Full validator/decoder (hard-error model, §10)
├── cbc-transform/     Transform & receipt library
│   ├── transforms.rs  Truncate, rechunk, recompress, concat, subrange
│   └── receipt.rs     ECDSA P-256 + Ed25519 signing/verification (§6)
└── cbc-cli/           Command-line interface
    └── main.rs        encode, decode, validate, inspect, transform, keygen
```

## API Usage

### Encode

```rust
use cbc_core::{EncoderConfig, HashSuite, encoder};
use cbc_core::bootstrap::FAMILY_A_BIT;

let config = EncoderConfig {
    hash_suite: HashSuite::Blake3,
    commitment_mode: FAMILY_A_BIT,
    block_payload_size: 4096,
    flags: 0,
};

let payload = std::fs::read("myfile.pdf").unwrap();
let artifact = encoder::encode_random_nonce(&config, &payload, &[]);
std::fs::write("myfile.cbc", &artifact).unwrap();
```

### Decode & Validate

```rust
use cbc_core::decoder;

let data = std::fs::read("myfile.cbc").unwrap();
let decoded = decoder::decode(&data).unwrap(); // hard error if invalid
println!("Payload: {} bytes", decoded.payload.len());
println!("Root: {}", hex::encode(decoded.chain_root));
```

### Transform with Receipt

```rust
use cbc_transform::{subrange_extract, receipt};

let key = receipt::generate_ed25519_key();
let (derived, receipt) = subrange_extract(&source_artifact, 0, 3, &key).unwrap();

// Verify receipt links source → derived
receipt::verify_receipt(&receipt, cbc_core::HashSuite::Blake3).unwrap();
```

## Algorithms

| Type | Supported |
|------|-----------|
| Hash | BLAKE3 (default), SHA-256 |
| Signature | ECDSA P-256 (mandatory), Ed25519 (optional) |

## Overhead

With default 4096-byte blocks: **48 bytes/block = 1.17% overhead**.

## License

See LICENSE file.
