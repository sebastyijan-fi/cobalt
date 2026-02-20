# Governance: EU-Aligned Cryptographic Policy

**Date:** 2026-02-20
**Reference:** BSI TR-02102-1 (Federal Office for Information Security)

## 1. Approved Cryptographic Algorithms and Key Sizes

The Cobalt ecosystem mandates cryptosystems compliant with **BSI TR-02102-1**. All implementations (`cbc-core`, `cbc-kms`, `cbc-server`) **MUST** use the following or explicitly error.

### 1.1 Encrypted Payloads (Symmetric)

- **AES-256-GCM** (NIST SP 800-38D / BSI IT-Grundschutz):
  - 256-bit symmetric encryption keys.
  - 96-bit randomly generated Nonces.
- **ChaCha20-Poly1305** (RFC 8439): Allowed as a fallback but AES-256-GCM is prioritized for hardware acceleration.
- 128-bit symmetric keys or ECB/CBC modes are strictly **PROHIBITED**.

### 1.2 Hash Functions (Integrity & Commitments)

- **SHA-256 / SHA-384** (FIPS 180-4).
- **BLAKE3**: Accepted for non-state actors as a performant modern alternative. Governed under BSI equivalent evaluations for cryptographic collision resistance (256-bit output).

### 1.3 Digital Signatures & Receipts (`cbc-kms`)

- **Ed25519** / **Ed448** (RFC 8032): Authorized for local or sub-range extractions where supported.
- **ECDSA** (FIPS 186-4): Limited to `secp256r1` (P-256) or `secp384r1` (P-384). `secp256k1` is strictly non-compliant outside of Web3 namespaces.
- **RSA**: Strongly **NOT RECOMMENDED**. If required for legacy CI integrations, moduli **MUST** be ≥ 3072 bits. 2048-bit RSA is outlawed for all signatures.

## 2. Key Management and Lifecycles

### 2.1 Hardware Security Modules (HSM / KMS)

All production environments performing CBC derived-artifact creation or key signing **MUST** defer off-board via the `KmsSigner` trait.

1. Local test keys (e.g., standard `.pem` loaded from disk) are restricted to development pipelines and **MUST** not have authorization rights in production clusters.
2. Signers like HashiCorp Vault Transit or AWS KMS must enforce rigid Key Provenance Attestation logs.

### 2.2 Dual Control

Operations that manipulate the root trust anchors (e.g., rotating the enterprise root key over CBC subrange signing) **SHOULD** mandate a dual-control workflow (four-eyes principle).

### 2.3 Key Rotation

- **Symmetric Keys (Data-at-Rest)**: 12-month rotation maximum.
- **Asymmetric Key Tiers (Signatures)**: 24-month rotation maximum with immediate CRL (Certificate Revocation List) triggers upon compromise.

## 3. Nonce Policy

Cryptographic implementations **MUST** enforce the following Nonce generation rules to avoid AEAD reuse vulnerabilities:

1. Nonces are securely generated via `rand::rngs::OsRng` directly from the OS Entropy pool (`/dev/urandom` equivalent).
2. If deterministic encoding is mandated (e.g., tests or specific blockchain consensus), the calling logic must explicitly acknowledge the static nonce and ensure the Key is never reused globally.

## 4. Cryptographic Agility (PQC Prep)

The ecosystem is structured with a "Suite-based" header (`0x01` BLAKE3, `0x02` SHA256) precisely to afford agility. By 2028, we anticipate an upgrade cycle to ingest Post-Quantum Cryptography (PQC) Hash-based signatures (e.g., SPHINCS+) per NIST and BSI final standardizations.

- Any future PQC signatures will introduce a breaking change to struct sizing and trigger a Semantic **MAJOR** version bump.
