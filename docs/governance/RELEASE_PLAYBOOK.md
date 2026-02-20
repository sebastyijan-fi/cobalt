# Governance: Release Playbook & SLSA Controls

**Date:** 2026-02-20
**Scope:** `cbc-core`, `cbc-kms`, `cbc-server`, and peripheral artifacts.

## 1. Requirement Checklist (SLSA Level 3+)

All official releases **MUST** conform to the following supply chain and operational security practices prior to distribution:

1. **Four-Eyes Approval:** The merge commit triggering the release tag `vX.Y.Z` **MUST** have a minimum of 1 approved structural PR review from a secondary maintainer.
2. **Reproducibility:** The build **MUST** happen within the isolated, automated `.github/workflows/enterprise_ci.yml` pipeline. Local developer machine releases are strictly prohibited.
3. **Audit Trails:** The GitHub action logs for the release act as our immutable audit trail.
4. **Green Test Gate:** The release pipeline assumes `cargo test`, `cargo clippy`, `cargo audit`, and *Universal Vector Conformance* tests returned exit code `0`.

## 2. Generate SBOM

An SPDX or CycloneDX Software Bill of Materials (SBOM) **MUST** be attached to every release.

- **Generation:** `cargo cyclonedx --format json --all`
- The resulting `bom.json` is distributed alongside the binary drops.

## 3. Cryptographic Provenance (Signed Artifacts)

1. Hashes of the native binaries and WASM builds **MUST** be produced via `sha256sum * > SHA256SUMS`.
2. The `SHA256SUMS` file is then GPG or HSM signed by the release manager: `gpg --detach-sign --armor SHA256SUMS`.
3. The `.asc` signature is attached to the GitHub release.

## 4. Release Notes Template

Every `vX.Z.Y` Github release should follow standard SemVer notation and adopt this structure:

```markdown
# Cobalt vX.Y.Z Release

[ Brief summary of the purpose of the release: e.g., "Performance updates" or "Critical Security Patch" ]

### 🛡 Security & Compliance
- List any CVE patches, dependencies updated, or audit findings resolved.

### 🚀 Features
- Bulletize new API functions, crypto suites, or major endpoints.

### 🚨 Breaking Changes & Migration Plan (If MAJOR bump)
- Refer to `docs/governance/MIGRATION_x_to_y.md`.
- Detail the exact scripts required to port datastores.

### 📦 Artifacts
- Attached: `bom.json` (CycloneDX SBOM)
- Attached: `SHA256SUMS` & `SHA256SUMS.asc` (Provenance)
```

## 5. Rollback Playbook

If an Enterprise deployment (e.g., `cbc-server`) faults after an upgrade:

1. Immediately invoke the Kubernetes downward API / deployment revert to the previous deterministic `SHA256` container manifest.
2. Identify whether artifacts written during the faulty window were corrupted. Use `./cbc-cli validate <folder>` across those exact files using the previous engine logic to isolate the fault domain.
3. Raise a SEV-1 incident. Write a negative test vector simulating the flaw into `tests/conformance/vectors.json`.
