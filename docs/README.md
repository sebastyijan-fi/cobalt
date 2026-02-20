# Cobalt Documentation

This directory contains the project’s long-form documentation, organized for fast navigation and clear trust boundaries.

## Start Here

- **Project overview:** [`../README.md`](../README.md)
- **Contributing guide:** [`../CONTRIBUTING.md`](../CONTRIBUTING.md)
- **Security policy:** [`../SECURITY.md`](../SECURITY.md)
- **License:** [`../LICENSE`](../LICENSE)

## Core Documents

- **Trust model:** [`TRUST_MODEL.md`](TRUST_MODEL.md)  
  Threat model, TCB boundaries, release gates, reproducibility and audit evidence expectations.

- **Specification:** [`SPEC.md`](SPEC.md)  
  CBC format and protocol-level technical specification.

- **Use cases:** [`USE_CASES.md`](USE_CASES.md)  
  Practical application scenarios and deployment patterns.

- **MIME / content typing:** [`MIME.md`](MIME.md)  
  MIME-related conventions and media-type guidance.

## Recommended Reading Order

If you’re new to the project:

1. [`../README.md`](../README.md)
2. [`TRUST_MODEL.md`](TRUST_MODEL.md)
3. [`SPEC.md`](SPEC.md)
4. [`USE_CASES.md`](USE_CASES.md)
5. [`../SECURITY.md`](../SECURITY.md)

## For Auditors and Security Reviewers

Use this sequence:

1. [`TRUST_MODEL.md`](TRUST_MODEL.md) (scope + claims)
2. [`SPEC.md`](SPEC.md) (protocol behavior)
3. [`../SECURITY.md`](../SECURITY.md) (reporting + disclosure process)
4. Reproducibility and release evidence from repository release artifacts

## Notes

- Root-level files are intentionally minimal; detailed narrative docs live under `docs/`.
- If a document changes project guarantees or trust claims, it should be reflected in release notes.