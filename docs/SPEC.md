# Cobalt (CBC) Format Specification v1.0

**Status**: Stable
**Version**: 1.0
**MIME Type**: `application/x-cobalt`

## 1. Overview

Cobalt (Context-Bound Container) is a binary container format where data integrity and provenance are intrinsic to the file structure. It relies on a 64-byte **Bootstrap Segment** that commits to the entire file content via cryptographic parameters.

## 2. Bootstrap Segment (Header)

Every CBC file begins with a fixed 64-byte header. Integers are **Little Endian**.

| Offset | Size | Type | Field | Description |
| :--- | :--- | :--- | :--- | :--- |
| 0 | 4 | `[u8; 4]` | **Magic** | `0x43 0x42 0x43 0x31` ("CBC1") |
| 4 | 2 | `u16` | **Version** | Format version. Currently `1`. |
| 6 | 1 | `u8` | **HashSuite** | Hash algorithm ID (see §2.1). |
| 7 | 1 | `u8` | **CommitMode** | Enabled commitment families (see §2.2). |
| 8 | 4 | `u32` | **BlockSize** | Payload size per block (e.g., 4096). |
| 12 | 4 | `u32` | **BlockCount** | Total number of blocks. |
| 16 | 16 | `[u8; 16]` | **Nonce** | 128-bit random nonce for semantic security. |
| 32 | 4 | `u32` | **Flags** | Bit 0: Compressed, Bit 1: Encrypted. |
| 36 | 4 | `u32` | **Reserved** | Must be 0. |
| 40 | 16 | `[u8; 16]` | **ParamsMAC** | HMAC/Hash of first 40 bytes (integrity check). |
| 56 | 8 | `u64` | **Reserved** | Must be 0. |

### 2.1 Hash Suites

| ID | Algorithm | Output Size |
| :--- | :--- | :--- |
| `1` | **BLAKE3** | 32 bytes |
| `2` | **SHA-256** | 32 bytes |

### 2.2 Commitment Families (Bitmask)

| Bit | Family | Description |
| :--- | :--- | :--- |
| `0x01` | **Family A** | **Linear Chain**: Each block hashes `(prev_hash, payload)`. Mandatory. |
| `0x02` | **Family B** | **Merkle Tree**: Enables random access & range proofs. |
| `0x04` | **Family C** | **Prefix Codes**: Self-delimiting blocks for crash recovery. |

## 3. Block Structure

A CBC file consists of the Bootstrap Segment followed by `BlockCount` blocks.

Each block contains:

1. **Payload**: `BlockSize` bytes (padded with 0s if last block is partial).
2. **Authentication Tag**: Dependent on Family settings (e.g., CRC-32C, Hash).

### 3.1 Frame Format (Family C)

If Family C is enabled, each block is wrapped:

- **Prefix**: `0xAA` + `VarInt(Index)`
- **Content**: Payload
- **Suffix**: `0x55`

## 4. Trailer / Footer

After the last block, an optional footer may contain:

- **Receipts**: Signatures proving transform history.
- **Merkle Roots**: If Family B is enabled.

## 5. Security Model

- **Tamper Evidence**: Any bit change invalidates the Chain Root (Family A) or Merkle Root (Family B), which are derived from the Bootstrap Segment.
- **Provenance**: Receipts stored in the footer link `DerivedArtifact -> SourceArtifact` via ECDSA/Ed25519 signatures.
