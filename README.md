# CBC — Context-Bound Container

A binary container format in which validity and meaning depend on intrinsic relational constraints among blocks. A CBC artifact is **self-validating**, **tamper-evident**, and **provenance-aware** without reliance on external sidecar files, detached signatures, or out-of-band metadata.

**Version:** 0.1.0 — **Status:** Draft — **License:** MIT

---

## Key Properties

| Property | Mechanism |
| :--- | :--- |
| **Integrity** | Hash-chain commitments (Family A) bind every block to a single root |
| **Random-access verification** | Merkle tree (Family B) enables O(log n) range proofs |
| **Structural robustness** | Self-delimiting prefix codes (Family C) enable resynchronization after corruption |
| **Tamper evidence** | Any modification — bit flip, reorder, truncate — invalidates the root |
| **Provenance** | Copying produces a different root; transform receipts link old → new with signatures |
| **Use Cases** | See [USE_CASES.md](USE_CASES.md) for 10 real-world scenarios |

## Quick Start

```bash
# Build
cargo build --workspace

# Run all tests (92 tests)
cargo test --workspace

# Encode a file
cargo run -p cbc-cli -- encode -i myfile.pdf -o myfile.cbc --hash blake3 --families A+B

# Validate
cargo run -p cbc-cli -- validate -i myfile.cbc

# Inspect metadata
cargo run -p cbc-cli -- inspect -i myfile.cbc

# Decode (extract payload)
cargo run -p cbc-cli -- decode -i myfile.cbc -o recovered.pdf

# Streaming encode (constant memory)
cargo run -p cbc-cli -- stream-encode -i largefile.bin -o largefile.cbc --families A+B

# Generate a Merkle range proof
cargo run -p cbc-cli -- prove -i myfile.cbc --start 0 --end 3 -o proof.bin

# Verify a range proof
cargo run -p cbc-cli -- verify-proof -i myfile.cbc -p proof.bin

# Transform with receipt (requires signing key)
cargo run -p cbc-cli -- keygen -o mykey --alg ed25519
cargo run -p cbc-cli -- transform -t subrange -i myfile.cbc -o subset.cbc -k mykey --start 0 --end 3
```

## Architecture

```text
cobalt/
├── cbc-core/          Core format library
│   ├── bootstrap.rs   64-byte Bootstrap Segment (§5.2)
│   ├── block.rs       Block format with CRC-32C (§5.3)
│   ├── chain.rs       Family A — linear hash-chain commitments (§4.1)
│   ├── merkle.rs      Family B — Merkle tree + range proofs (§4.2)
│   ├── prefix.rs      Family C — prefix parse constraints (§4.3)
│   ├── footer.rs      Stream Footer with footer_commitment (§5.4)
│   ├── encoder.rs     Payload → CBC artifact
│   ├── decoder.rs     Full validator/decoder (hard-error model, §10)
│   └── streaming.rs   Streaming encoder/decoder (block_count=0 mode)
├── cbc-transform/     Transform & receipt library
│   ├── transforms.rs  Truncate, rechunk, recompress, concat, subrange
│   └── receipt.rs     ECDSA P-256 + Ed25519 signing/verification (§6)
└── cbc-cli/           Command-line interface
    └── main.rs        encode, decode, validate, inspect, transform, keygen,
                       prove, verify-proof, stream-encode
```

## API Usage

### Encode & Decode

```rust
use cbc_core::{EncoderConfig, HashSuite, encoder, decoder};
use cbc_core::bootstrap::FAMILY_A_BIT;

let config = EncoderConfig {
    hash_suite: HashSuite::Blake3,
    commitment_mode: FAMILY_A_BIT,
    block_payload_size: 4096,
    flags: 0,
};

let payload = std::fs::read("myfile.pdf").unwrap();
let artifact = encoder::encode_random_nonce(&config, &payload, &[]).unwrap();
std::fs::write("myfile.cbc", &artifact).unwrap();

// Decode
let decoded = decoder::decode(&artifact).unwrap();
assert_eq!(decoded.payload, payload);
```

### no_std Support

`cbc-core` supports `no_std` environments (with `alloc`). To use it in a `no_std` project, disable default features and enable the `alloc` feature:

```toml
[dependencies]
cbc-core = { version = "0.1.0", default-features = false, features = ["alloc"] }
```

> [!NOTE]
> Compression via `zstd` is only available when the `std` feature is enabled.

### Streaming Encode (One-Pass)

Cobalt supports true **one-pass streaming**. The commitment material is stable even without knowing the final block count upfront, enabling high-performance pipelines.

```rust
use cbc_core::{EncoderConfig, HashSuite, streaming::StreamingEncoder};
use cbc_core::bootstrap::FAMILY_A_BIT;

let config = EncoderConfig {
    hash_suite: HashSuite::Blake3,
    commitment_mode: FAMILY_A_BIT,
    block_payload_size: 4096,
    flags: 0,
};

let mut enc = StreamingEncoder::new(&config, [0u8; 16]);
// write_payload handles arbitrary buffer sizes and internal padding
enc.write_payload(b"arbitrary data chunk...").unwrap();
enc.write_payload(b"another chunk...").unwrap();

let artifact = enc.finalize(&[]).unwrap();
```

### Range Proofs (Selective Disclosure)

```rust
use cbc_core::merkle::{MerkleTree, RangeProof};

// Build tree and prove a range
let tree = MerkleTree::build(&params_hash, &padded_payloads, suite);
let proof = tree.prove_range(2, 5).unwrap();

// Verify proof against known root
let leaf_hashes = /* compute leaf hashes for blocks 2..=5 */;
assert!(proof.verify(&leaf_hashes, &tree.root, suite));

// Serialize for transport
let bytes = proof.encode();
let decoded_proof = RangeProof::decode(&bytes).unwrap();
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
| :--- | :--- |
| Hash | BLAKE3 (default), SHA-256 |
| Signature | ECDSA P-256 (mandatory), Ed25519 (optional) |

## Overhead

With default 4096-byte blocks: **48 bytes/block = 1.17% overhead**.

## License

MIT — see [LICENSE](LICENSE).
