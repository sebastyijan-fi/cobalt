# Governance: Compliance Mapping (GDPR, ISO 27001, NIS2)

**Version:** 1.0.0
**Date:** 2026-02-20
**Scope:** Cobalt Architectures (`cbc-core`, `cbc-kms`, `cbc-server`)

## 1. General Data Protection Regulation (GDPR)

Cobalt is architected strictly around Privacy-by-Design and Privacy-by-Default (Art. 25 GDPR). It serves as a cryptographic provenance ledger without violating data autonomy.

### 1.1 The Right to Erasure (Art. 17) & Subrange Extraction

Traditional blockchains force immutable storage of all data, conflicting with a data subject's "Right to be Forgotten."
Cobalt explicitly solves this via the **Subrange Extraction** primitive (`cbc-transform`):

1. **Redaction:** If user PII is located within Blocks 100-200 of a streaming record, an operator can extract Blocks 0-99 and Blocks 201-N.
2. **Cryptographic Continuity:** The new subranged artifact contains cryptographic proofs (Merkle paths) that validate the remaining blocks against the original `ChainRoot` and `MerkleRoot` without revealing the redacted PII.
3. **Destruction:** The original artifact containing the PII is then verifiably destroyed from active storage, satisfying Art. 17 while retaining the auditability of the surrounding data.

## 2. ISO/IEC 27001:2022 Mapping

Cobalt's Enterprise deployment satisfies the following Annex A controls:

- **A.8.24 Use of Cryptography:** Addressed by the strict adherence to BSI TR-02102-1 outlined in `CRYPTO_POLICY.md`. All data is hashed (BLAKE3/SHA-256) and optionally encrypted (AES-256-GCM) at rest.
- **A.8.4 Protection against Malware:** Addressed by the explicit anti-DoS bounds placed in the `cbc-core` decoder (preventing Zip-Bombs and OOM vectors natively at the IO layer).
- **A.8.9 Configuration Management:** Handled via the rigid CI/CD `.github/workflows/enterprise_ci.yml` pipeline enforcing deterministic builds.

## 3. NIS2 Directive Preparedness

As a supply-chain enabler for critical infrastructure, European operators utilizing Cobalt inherit out-of-the-box compliance for Art. 21 (Cybersecurity risk-management measures):

- **Supply Chain Security:** Cobalt generates automated SPDX/CycloneDX SBOMs and provides Signed Releases via the `RELEASE_PLAYBOOK.md` mandates. All downstream consumers can cryptographically verify they are running untampered binaries.
- **Incident Handling (Audit Trails):** The cryptographic guarantees over logs provided by the `Family A` (Hash Chaining) configuration provide non-repudiation for incident investigations, strictly preventing attackers from covering their tracks without invalidating the artifact root.
