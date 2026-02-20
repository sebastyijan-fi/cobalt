# Create the rigid AppRole for the K8s cbc-server instances
resource "vault_auth_backend" "approle" {
  type = "approle"
}

# The explicit ACL isolating the server solely to signature operations.
# Denies key export, deletion, and cross-key operations.
resource "vault_policy" "cbc_server_transit_policy" {
  name = "cbc-server-transit-policy"

  policy = <<EOT
# Allow cbc-server to sign new extraction receipts
path "transit/sign/cbc-enterprise-key" {
  capabilities = ["update"]
}

# Allow cbc-server to verify existing extraction receipts
path "transit/verify/cbc-enterprise-key" {
  capabilities = ["update", "read"]
}

# Allow cbc-server to check key versions (needed for validation)
path "transit/keys/cbc-enterprise-key" {
  capabilities = ["read"]
}

# Deny everything else explicitly
path "transit/export/*" {
  capabilities = ["deny"]
}
EOT
}

# Bind the policy to the AppRole
resource "vault_approle_auth_backend_role" "cbc_role" {
  backend        = vault_auth_backend.approle.path
  role_name      = "cbc-server-role"
  token_policies = ["default", vault_policy.cbc_server_transit_policy.name]
}
