# Scenario: SEC/FINRA WORM Archival (Chain of Custody)

## 👤 The Persona

**Compliance Officer** overseeing regulated financial or telecommunications data lakes.

## 🌪️ The Challenge

SEC/FINRA regulations mandate that financial broker-dealers retain records in Write-Once-Read-Many (WORM) format. Data must be completely immutable and readily auditable. If a regulatory body subpoenas records, the enterprise must provide mathematical proof that the records generated on Day 1 have not suffered bit-rot, truncation, or malicious tampering over a 7-year retention lifecycle.

## 🛡️ The Solution

1. **Ingestion**: The enterprise data lake daemon encodes raw compliance logs into a Cobalt Block Container (`.cbc`), generating an immutable **Source Root**.
2. **Signatures**: The Container's receipt is counter-signed by HashiCorp Vault.
3. **Verification**: Years later, the auditor utilizes the CLI `inspect` and `validate` commands to unequivocally prove the archived chain of custody matches the original cryptographic assertions.

## 🚀 Run the Demo

```bash
./run_demo.sh
```
