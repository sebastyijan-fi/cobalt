# Architecture: Reliability SLOs & Determinism constraints

**Version:** 1.0.0
**Date:** 2026-02-20
**Scope:** `cbc-core` and the `cbc-server` API layer.

## 1. Core Deterministic Behavior

The fundamental property of the Cobalt Block Container is mathematical determinism. The exact same byte array run with the exact same parameters **MUST** yield the exact same SHA-256 or BLAKE3 artifact digest.

### 1.1 Anti-Panic Guarantee (Fuzzing)

- Under no circumstance is `cbc-core` permitted to crash, abort, or `panic!()` the host process, regardless of how heavily malformed or malicious the input byte array is.
- Continuous differential fuzzing (`cargo-fuzz`) is mandated as part of the Secure SDLC to assert no memory unsafety exists at the decoding boundaries.

### 1.2 Bounded Resource Utilization

- **Memory Ceiling:** A single `cbc-core::decoder` invocation must run in bounded, predictable memory. Total internal allocations must never exceed the raw chunk size + `16MB` in an uncompressed state.
- **Decompression DoS (Zip-Bomb):** To prevent an adversary from halting `cbc-server` instances, any compressed payload unpacking is rigidly halted if derived bytes exceed the ceiling of **256 MiB**.
- **CPU Halting:** Infinite loops during corrupted varint prefix reading are strictly prevented by definitive `offset < data.len()` validations.

## 2. Service Level Objectives (SLOs)

When running `cbc-server` in a production Enterprise Architecture, operators **SHOULD** target the following Service Level Objectives. If metrics fall beneath these targets, no new feature merges should proceed until reliability budgets are restored.

| Service Indicator | Objective Class | Threshold / Target | Measurement Window |
|-------------------|-----------------|--------------------|--------------------|
| **Availability**  | High            | 99.99%             | 30-Day Rolling     |
| **API Errors**    | Critical        | < 0.1% of requests | 24-Hour Rolling    |
| **Latency p95**   | Nominal         | < 150ms per 1MB    | 5-Minute Window    |
| **Latency p99**   | Tails           | < 500ms per 1MB    | 5-Minute Window    |

*Note: Latency is highly dependent on AES-GCM and BLAKE3 hardware acceleration capabilities (e.g., AES-NI instructions).*

## 3. Chaos Engineering Requirements

To validate these SLOs, chaos experiments **SHOULD** be run iteratively in staging environments.

1. **Network Partitions:** Dropping packets between `cbc-server` and `HashiCorp Vault` to ensure graceful `HTTP 500` failures without crashing the axum runtime.
2. **Corrupt Payloads:** Intentionally feeding invalid base64 and truncated gzip formats at high concurrency (`1000 RPS`) to validate memory releasing.
