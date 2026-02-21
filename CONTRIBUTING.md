# Contributing to Cobalt

Thanks for contributing to Cobalt. This guide explains how to set up your environment, propose changes, and keep quality/security standards high.

---

## 1) Before You Start

- Read the project overview in `README.md`
- Read the docs index in `docs/README.md`
- Review trust and security expectations:
  - `docs/TRUST_MODEL.md`
  - `SECURITY.md`
- For format-level changes, review:
  - `docs/SPEC.md`
  - `docs/MIME.md`

If your change affects trust-critical behavior, call that out explicitly in your PR.

---

## 2) Repository Layout

- `cbc-core/` — core format library (trust-critical)
- `cbc-transform/` — transform + receipt logic (partly trust-critical)
- `cbc-cli/` — CLI and operational UX surface
- `cbc-wasm/` — WebAssembly bindings
- `cbc-py/` / `cbc-node/` — language bindings
- `docs/` — specifications, trust model, and supporting documentation
- `security_tests/` — security-focused test utilities
- `examples/` — example data/workflows

---

## 3) Development Setup

### Requirements

- Rust toolchain compatible with workspace settings
- `cargo` and standard Rust tooling
- Docker (optional, for reproducibility checks)

### Build and Test

> **Binary naming:** The `cbc-cli` package installs a binary named **`cbc`**.

```bash
# Fastest path: build only the CLI
cargo build -p cbc-cli
# Binary at: target/debug/cbc

# Full workspace build + test
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
cargo check -p cbc-core --no-default-features --features alloc
```

If you change parser/decoder logic, run additional fuzz or adversarial tests where applicable.

---

## 4) Contribution Workflow

1. Create a branch from the default branch.
2. Make a focused change (one topic per PR when possible).
3. Add or update tests.
4. Update docs for behavior/spec/CLI changes.
5. Ensure all checks pass locally.
6. Open a PR with a clear description and risk notes.

---

## 5) Pull Request Expectations

Every PR should include:

- **What changed** (concise summary)
- **Why** (motivation/problem)
- **Scope** (affected crates/modules)
- **Testing performed** (commands + results)
- **Docs impact** (which docs were updated)
- **Security/trust impact** (especially for `cbc-core` / crypto / validation)

### Required for trust-critical changes

If your PR touches trust-critical paths, include:

- Threat/attack surface impact statement
- Backward compatibility notes
- Any dependency changes and rationale
- Notes on whether release verification/audit outputs are affected

---

## 6) Coding Standards

- Keep code simple, explicit, and testable.
- Prefer small functions with clear invariants.
- Avoid panics in library code for expected error paths.
- Return typed errors with actionable messages.
- Preserve `no_std` support in `cbc-core`.

For API-breaking changes, include migration notes in PR description and update docs accordingly.

---

## 7) Testing Guidance

Minimum baseline:

- Unit/integration tests for new behavior
- Regression tests for bug fixes
- Negative tests for validation and parsing edge cases

When relevant:

- Property-based tests (e.g., roundtrip/invariant checks)
- Fuzzing for parser/decoder changes
- Cross-crate integration tests for CLI/transform interactions

---

## 8) Documentation Requirements

Update docs whenever behavior changes:

- User-facing behavior: `README.md`
- Trust/security assumptions: `docs/TRUST_MODEL.md` and/or `SECURITY.md`
- Format semantics: `docs/SPEC.md`
- Content typing/conventions: `docs/MIME.md`
- Practical scenarios: `docs/USE_CASES.md`

Also keep `docs/README.md` accurate when adding or moving docs.

---

## 9) Commit and Review Hygiene

- Use descriptive commit messages.
- Keep commits logically grouped.
- Avoid mixing refactors with behavior changes unless necessary.
- Resolve review comments with context (what changed and why).

For sensitive changes, prefer at least two reviewers.

---

## 10) Security Reporting

Do **not** open public issues for vulnerabilities.

Follow `SECURITY.md` for private reporting and disclosure handling.

---

## 11) License

By contributing, you agree your contributions are licensed under the project’s MIT License (`LICENSE`).
