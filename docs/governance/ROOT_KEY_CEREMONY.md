# Governance: Root Key Generation Ceremony

**Version:** 1.0.0
**Date:** 2026-02-20
**Scope:** HashiCorp Vault Production Cluster (`cbc-kms`)

The Cobalt ecosystem delegates cryptographic proving/signing exclusively to HashiCorp Vault using the `cbc-enterprise-key`. To guarantee the integrity of this root of trust, the Vault initialization **MUST** be performed via an **Air-Gapped Root Key Ceremony** satisfying the definitions below (aligned with ISO 27001 / BSI TR-02102-1).

## 1. Prerequisites (The Environment)

- **Air-Gapped Workstation:** A dedicated, permanently offline laptop booting a hardened, ephemeral live Linux OS (e.g., Tails OS) containing the Vault binary for CLI initialization.
- **Physical Isolation:** The ceremony **MUST** be conducted in a secure room (e.g., a Faraday cage or windowless access-controlled facility). No recording devices or smartphones are permitted.
- **Key Custodians:** A minimum of 5 pre-authorized corporate officers MUST be physically present.

## 2. Initialization & Shamir's Secret Sharing

Vault's Master Key is never exposed in plaintext. It is cryptographically split using Shamir's Secret Sharing.
We explicitly mandate a **Threshold of 3 out of 5**.

1. Within the secure network enclave, invoke:

```bash
vault operator init -key-shares=5 -key-threshold=3
```

2. The terminal will output 5 unseal keys and 1 Initial Root Token.

## 3. Key Distribution & Escrow

1. **Immediate Purge:** The Initial Root Token **MUST** be noted, used exclusively to execute the `infra/terraform/*.tf` configurations via an isolated CI deployment, and then immediately **revoked** (`vault token revoke`).
2. **Custodian Allocation:** The 5 unseal keys are printed on physical paper or inscribed on isolated YubiKeys (PGP Encrypted).
3. **Physical Distribution:**
    - Officer A -> Key 1 (Retained in Security Safe A)
    - Officer B -> Key 2 (Retained in Security Safe B)
    - Officer C -> Key 3 (Retained in Off-site Safety Deposit Box 1)
    - Officer D -> Key 4 (Retained in Off-site Safety Deposit Box 2)
    - Officer E -> Key 5 (Retained in Escrow via Third-Party Law Firm)

## 4. Unsealing Mechanics (Four-Eyes Minimum)

If `cbc-server` undergoes a hard reboot or Vault container cycling, the vault will restart in a **Sealed** state, halting all Enterprise artifact signing capabilities.

1. An emergency incident bridge is formed.
2. A minimum of **3 separate custodians (Four-Eyes validation)** must log into the Vault orchestrator.
3. Each inputs their share explicitly: `vault operator unseal <SHARE>`.
4. Only upon the 3rd valid coordinate will Vault reconstruct the Master Key in ephemeral memory and permit `cbc-server` signing.

## 5. Attestation

Upon completion of the ceremony, a formal affidavit of generation **MUST** be signed in ink by all 5 custodians and logged within the corporate Information Security Management System (ISMS).
