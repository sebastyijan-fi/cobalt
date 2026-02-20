# Formal Specification: Cobalt Block Container (CBC) Wire Format

**Version:** 1.0.0
**Status:** Normative
**Date:** 2026-02-20

## 1. Introduction

This document provides the normative specification for the Cobalt Block Container (CBC) wire format. The intent of CBC is to offer cryptographic chain-of-custody, determinism, and Merkle tree proofs over streaming payload data.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC2119] [RFC8174] when, and only when, they appear in all capitals, as shown here.

## 2. Core Constraints

An implementation of the CBC decoder/encoder **MUST** adhere to the following absolute physical layouts and parsing constraints.

### 2.1 Determinism

An encoder **MUST** produce bit-for-bit identical output artifacts when given the identical:

- Raw Payload bytes
- Encryption Key, Compression Flags, or other Configuration Bitfields
- Nonce
- Sub-receipts or Signatures
If two disparate outputs claim the same configuration over the same bytes, the implementation is non-compliant.

### 2.2 Rejection of Ambiguity

Parsers and decoders **MUST NOT** attempt to "recover" or "guess" values for malformed input. If an artifact exhibits invalid magic bytes, conflicting structure sizes, or cryptographic failures, the parser **MUST** immediately fail and return an explicit error.

---

## 3. High-Level Layout

A strictly compliant CBC artifact **MUST** be packed exactly as follows, with no interleaved padding or metadata outside of these structures unless explicitly permitted by the `Flags` field of the Bootstrap Segment:

1. **Bootstrap Segment** (exactly 64 bytes)
2. **Blocks Sequence** (1 to N blocks)
3. **Stream Footer** (Variable length)

```
[ Bootstrap Segment (64 bytes) ]
[ Block 0 (Prefix? + Payload + Tag? + Commitment?) ]
[ Block 1 (Prefix? + Payload + Tag? + Commitment?) ]
...
[ Block N (Prefix? + Payload + Tag? + Commitment?) ]
[ Stream Footer (Commitments + Receipts + Variable Length Info) ]
```

---

## 4. Bootstrap Segment

The Bootstrap Segment **MUST** be exactly 64 bytes wide. All integer values **MUST** be encoded in Little-Endian byte order.

| Offset | Length (Bytes) | Name                 | Constraint |
|--------|----------------|----------------------|------------|
| 0      | 4              | `magic`              | **MUST** be `[0x43, 0x42, 0x43, 0x31]` (`"CBC1"` ASCII) |
| 4      | 2              | `version`            | **MUST** be `0x0001` (v1) |
| 6      | 1              | `hash_suite`         | Enumeration. `0x01` = BLAKE3, `0x02` = SHA-256 |
| 7      | 1              | `commitment_mode`    | Bitfield. Denotes Family A (0x01), B (0x02), C (0x04) |
| 8      | 4              | `block_payload_size` | Unsigned 32-bit int. **MUST** be > 0. |
| 12     | 4              | `block_count`        | Unsigned 32-bit int. The total number of blocks in the stream |
| 16     | 16             | `bootstrap_nonce`    | 16-byte cryptographically secure random value |
| 32     | 4              | `flags`              | Operational bitfield (e.g., encryption `0x01`, compression `0x02`) |
| 36     | 28             | `reserved`           | **MUST** be exactly 28 bytes of `0x00`. Decoders **SHOULD** ignore. |

### 4.1. Commitment Modes

The `commitment_mode` is a bitmask determining the cryptographic proofs embedded in the stream:

- **Family A** (`0x01`): Continuous hash chaining. Every artifact **MUST** implement at least Family A.
- **Family B** (`0x02`): Merkle tree inclusion. Demands the Stream Footer harbor a 32-byte Merkle root.
- **Family C** (`0x04`): Self-describing stream markers. Requires every block to be prefixed with a varint length marker.

### 4.2. Flags

- `0x00000001` (Encrypted): The stream is encrypted (AES-256-GCM / ChaCha20-Poly1305).
- `0x00000002` (Compressed): The stream payload is zstd compressed. Implementations **MUST** defend against zip-bombs during decompression, enforcing a predefined memory ceiling.

---

## 5. Block Sequence

### 5.1. Unencrypted Blocks

If `flags & 0x01 == 0`, a block consists of:

1. `prefix` (if Family C is active)
2. `payload` (length up to `block_payload_size`)
3. `commitment` (if Family A is active). This **MUST** be exactly 32 bytes representing the chain hash up to this block.

### 5.2. Encrypted Blocks

If `flags & 0x01 == 1`:
The `payload` size encompasses both ciphertext and the 16-byte AEAD authentication tag. The tag **MUST** be stored at the end of the ciphertext.
The block configuration is:

1. `prefix` (if Family C is active)
2. `ciphertext` (length up to `block_payload_size - 16`)
3. `tag` (exactly 16 bytes)
4. `commitment` (32 bytes under Family A)

---

## 6. Stream Footer

The footer seals the CBC stream. It varies in length depending on the included commitments and receipts but can always be parsed unambiguously starting from the termination of the block sequence or reading backward from `EOF`.

| Offset | Length | Name | Constraint |
|--------|--------|------|------------|
| 0      | 32     | `chain_root` | Required unconditionally under Family A. The terminal commitment hash. |
| 32     | 32     | `merkle_root`| Present ONLY if Family B (`0x02`) is active. |
| Varies | 2      | `receipt_count`| Unsigned 16-bit integer denoting the number of cryptographic receipts appended. |
| Varies | Varies | `receipts`   | N concatenated sub-receipt buffers. |
| `L-8`  | 4      | `magic`      | **MUST** be `[0x46, 0x4F, 0x4F, 0x54]` (`"FOOT"` ASCII) |
| `L-4`  | 4      | `length` | Unsigned 32-bit LE integer denoting the size of the *entire* footer, including the magic and length fields themselves. |

### 6.1 Vulnerability Mitigation

Decoders **MUST** verify that `footer_length` is strictly greater than or equal to the minimum acceptable fixed size (dependent on Family A vs Family B). Subtracting before bounds checking is strictly forbidden to prevent integer underflow panics.

## 7. Extract/Subrange Validations

When extracting a subrange of an artifact, the original `chain_root` and `merkle_root` **MUST NOT** be tampered with. The deriving server **MUST** provide a KMS/HSM signature over the subrange proving cryptographic provenance back to the original tree.

## 8. Backwards Compatibility

Changes to this specification that alter physical offsets or hashing requirements **MUST** increment the `version` field from `0x0001` to `0x0002`. Decoders encountering an alien version **SHOULD** surface a `VersionMismatch` error and abort gracefully rather than attempt partial parsing.
