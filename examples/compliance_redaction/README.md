# Scenario: GDPR Right to Erasure (Subrange Extraction)

## 👤 The Persona

**Data Privacy Officer (DPO)** at a regulated enterprise.

## 🌪️ The Challenge

A data subject (e.g., a patient or customer) formally invokes their "Right to be Forgotten" (GDPR Art. 17). Their Personally Identifiable Information (PII) is embedded within a massive, immutable audit ledger containing records for thousands of other subjects. The enterprise must explicitly destroy the requested PII without invalidating the cryptographic integrity of the surrounding financial or healthcare data.

## 🛡️ The Solution

1. **Fingerprinting**: The enterprise encodes the batch records into a Cobalt Block Container (`.cbc`), retaining the original `.cbc` as the authoritative ledger.
2. **Subrange Extraction**: Upon receiving the regulatory deletion request, the DPO utilizes Cobalt's native extraction to carve out the specific PII block.
3. **Cryptographic Continuity**: The new, redacted artifact retains Merkle proofs validating all *remaining* data against the original `ChainRoot`, even though the original artifact (and the PII) is formally destroyed from active storage.
4. **Attestation**: Auditors can computationally prove the remaining records were untouched during the redaction phase.

## 🚀 Run the Demo

```bash
./run_demo.sh
```
