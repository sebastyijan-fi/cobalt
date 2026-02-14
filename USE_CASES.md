# Cobalt: Practical Integration Guide & Use Cases

This document bridges the gap between high-level concepts and actual code. For each use case, we provide the specific CLI commands or Rust API calls needed to implement it.

---

## 1. Verifiable Software Supply Chain

**Goal**: Sign a build artifact and verify its integrity in CI.

### Implementation: Verifiable Supply Chain (CLI)

```bash
# 1. Encode the binary into Cobalt format
cbc encode -i target/release/myapp -o myapp.cbc --families A+B

# 2. Add an Ed25519 signature of the Merkle Root
cbc sign -i myapp.cbc -k build-server.key --alg ed25519 -o signed-myapp.cbc

# 3. In the deployment stage, validate the whole artifact
cbc validate -i signed-myapp.cbc
```

---

## 2. Privacy-Preserving Health Records

**Goal**: Disclose only a specific sub-range of a document.

### Implementation: Selective Disclosure (Rust API)

```rust
use cbc_core::decoder::decode;
use cbc_core::merkle::RangeProof;

// hospital.cbc contains [Page1, Page2, Page3, ...]
// User wants to disclose just Page 2 (index 1)
let artifact = std::fs::read("hospital.cbc").unwrap();
let decoded = decode(&artifact).unwrap();

// Generate proof for Page 2
let tree = decoded.merkle_tree().unwrap();
let proof = tree.prove_range(1, 1).unwrap();

// Share 'proof.encode()' and the Page 2 data with the school.
// The school verifies it against the hospital's known Root Hash.
assert!(proof.verify(&[page2_hash], &hospital_root, suite));
```

---

## 3. High-Integrity Forensic Audit Logs

**Goal**: Record logs that cannot be deleted or reordered without detection.

### Implementation: High-Integrity Logging (Rust API)

```rust
use cbc_core::streaming::StreamingEncoder;

let mut logger = StreamingEncoder::new(&config, nonce);

// As logs arrive, write them one by one
loop {
    let log_entry = get_next_log();
    // write_payload handles buffering and chaining automatically
    logger.write_payload(log_entry.as_bytes()).unwrap();
}

// At the end of the day or log rotation
let final_log_file = logger.finalize(&[]).unwrap();
```

---

## 4. Secure IoT Firmware Updates

**Goal**: Verify chunks of an update on a low-memory device.

### Implementation: IoT Firmware Updates (no_std API)

```rust
use cbc_core::streaming::StreamingDecoder;

let mut decoder = StreamingDecoder::new();
decoder.feed_bootstrap(&bootstrap_bytes).unwrap();

// As chunks arrive over the network
for chunk in network_stream {
    // Validates each block's HMAC/Checksum and Chain Commitment immediately
    let plaintext = decoder.feed_block(chunk, is_last).unwrap();
    apply_to_flash(plaintext);
}
```

---

## 5. Chain of Custody for Digital Evidence

**Goal**: Record every transformation of evidence (cropping or format conversion).

### Implementation: Chain of Custody (CLI)

```bash
# Extract a subrange (e.g., first 5 minutes) and generate a receipt
cbc transform -t subrange -i evidence.cbc -o subrange.cbc \
    -k investigator.key --start 0 --end 150 --receipt

# Inspect the provenance
cbc inspect -i subrange.cbc
# Output will show the Chain of Custody receipts linked to the original root.
```

---

## 6. Efficient Genomic Data Sharing

**Goal**: Download and verify a 20MB gene sequence out of a 2TB file.

### Implementation: Genomic Data Concept

1. Store the genome as a CBC file with 64KB blocks.
2. The client fetches the **Bootstrap** (64B) and **Footer** (64B) to get the Merkle Root.
3. The client fetches and verifies only the **Range Proof** and the data blocks for the specific gene.

---

## 7. Tamper-Proof Legal Contracts

**Goal**: Map each page of a contract to a block.

### Implementation: Legal Contracts (CLI)

```bash
# Each file represents a page
cbc encode -i page1.pdf page2.pdf page3.pdf -o contract.cbc --families A+B
```

---

## 8. Verifiable CDN Asset Delivery

**Goal**: Stop playback if a segment is injected with non-authentic data.

### Implementation: CDN Asset Validation (Rust API)

```rust
// The video player uses StreamingDecoder
decoder.feed_block(segment_bytes, is_last)?; // Returns Err(ChainCommitmentMismatch) if tampered
```

---

## 9. dApp State Snapshots

**Goal**: Share a small proof of an account balance.

### Implementation: dApp Balance Proofs (Rust API)

```rust
// Use RangeProof::encode() to send a ~1KB proof for a specific state block
// instead of the whole 1GB state snapshot.
```

---

## 10. Archival Data Resynchronization

**Goal**: Recover data after a header or block is corrupted by "bit-rot."

### Implementation: Archival Recovery (CLI)

```bash
# If 'corrupted.cbc' has a bad header, use the recovery scanner
cbc validate -i corrupted.cbc --recover
# The tool uses Family C (Prefix Markers) to find the next valid block boundary.
```
