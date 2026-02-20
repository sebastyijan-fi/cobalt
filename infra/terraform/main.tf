terraform {
  required_providers {
    vault = {
      source  = "hashicorp/vault"
      version = "~> 3.23.0"
    }
  }
}

provider "vault" {
  # This relies on VAULT_ADDR and VAULT_TOKEN environment variables Set during CI
  # address = "https://vault.cobalt.internal:8200"
}
