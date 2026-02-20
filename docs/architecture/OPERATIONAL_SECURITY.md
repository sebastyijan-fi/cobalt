# Architecture: Operational Security Controls

**Version:** 1.0.0
**Date:** 2026-02-20
**Scope:** Production deployments of `cbc-server` and internal infrastructure.

## 1. Immutable Audit Trails

All access to `.cbc` artifacts, KMS signing requests, and extraction commands **MUST** be logged.

1. **Trace Configuration:** `cbc-server` integrates `tracing` outputting Structured JSON logs (`tracing_subscriber::fmt::json`).
2. **Forwarding:** Logs **MUST** be forwarded to an immutable Write-Once-Read-Many (WORM) log sink (e.g., AWS S3 Object Lock, Splunk, or Elasticsearch with restricted delete permissions).
3. **Retention:** Logs mapping to cryptographic derivation operations **MUST** be retained for a minimum runtime period defined by the data classification (Default: 7 years).

## 2. Network Security (mTLS / SPIFFE)

The underlying Cobalt APIs (`/api/v1/encode`, `/extract`) handle highly sensitive plaintext buffers prior to encryption and generate KMS signature requests. These endpoints **MUST NOT** be exposed to public networks without rigorous ingress defense.

- **Service Identity:** Back-end microservices invoking `cbc-server` **SHOULD** authenticate via Mutual TLS (mTLS) brokered by a service mesh (e.g., Istio, Linkerd) or short-lived SPIFFE/SPIRE certificates.
- **KMS Identity:** Communications from `cbc-server` to HashiCorp Vault **MUST** transport over TLS 1.3 with rigorous cert pinning. Vault AppRole or Kubernetes Service Account tokens should be injected dynamically without hitting local disk.

## 3. Time Synchronization

Replay attacks represent a significant vulnerability when validating digital receipts and JWT assertions.

- Enterprise nodes running `cbc-server` **MUST** enforce strict clock synchronization via `chronyd` or `ntpd`.
- Nodes drifting beyond a maximum threshold (`3000ms`) **SHOULD** be cordoned from processing KMS signatures to prevent stale token acceptance or inaccurate cryptographic timestamps (`ExtractResponse.timestamp`).

## 4. Rate Limiting and DoS Defense

While the `cbc-core` library enforces strict runtime boundaries on decompression (`256 MiB`) and parsing, the HTTP layer requires its own defense.

- **Global Budgets:** Ingress controllers or API Gateways routing to `cbc-server` **MUST** establish Token Bucket rate limiting.
- **Payload Limits:** The proxy layer **MUST** enforce a strict `ClientMaxBodySize` (e.g., `100MB`) to reject unsustainably large upload frames before they consume Rust async worker threads.
