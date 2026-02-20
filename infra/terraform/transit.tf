# Mount the transit secrets engine
resource "vault_mount" "transit" {
  path        = "transit"
  type        = "transit"
  description = "Cobalt Enterprise Cryptographic Transit Engine"
  
  # Operational Security: strictly enforce compliant algorithms
  options = {
    convergent_encryption = false
  }
}

# Generate the asymmetric cryptographic key used for Subrange derivation signing
resource "vault_transit_secret_backend_key" "cbc_enterprise_key" {
  backend          = vault_mount.transit.path
  name             = "cbc-enterprise-key"
  
  # Policy defined in CRYPTO_POLICY.md requires Ed25519 or RSA-4096
  type             = "ed25519"
  
  # Security Gate: Keys must never leave the HSM/Vault boundary
  exportable       = false
  allow_plaintext_backup = false
  
  # Governance Policy: Rotate every 90 days.
  auto_rotate_period = 7776000
}
