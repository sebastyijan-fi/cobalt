# Cobalt Trust Model

Status: Draft  
Scope: `cbc-core`, trust-critical paths in `cbc-transform`, release process, and distributed artifacts (`cbc`, `cbc-wasm`)

---

## 1) Purpose and Security Promise

For sovereignty- and trust-critical use, Cobalt’s promise is:

> The released binary does what we claim and nothing else, and you can verify that independently.

This document defines:
- what threats we defend against,
- which components are in-scope for strict trust claims,
- what controls are required,
- what evidence is published,
- and what gates must pass before release.

---

## 2) Trust Boundaries (TCB)

## 2.1 TCB-A (Strictly Audited)
Components where high-assurance claims are made:

- `cbc-core` (format parsing, validation, commitment logic, integrity checks)
- Trust-critical cryptographic and receipt verification paths in `cbc-transform`
  - signature verification
  - receipt linkage verification
  - key-handling code paths used during verification workflows

Claims for TCB-A:
- deterministic/reproducible builds,
- low-level inspectability (disassembly / import & syscall surfaces),
- strict review and dependency controls,
- evidence-backed release gates.

## 2.2 Non-TCB (Operational Surface)
Components not covered by strict binary-level trust claims:

- `cbc-cli` UX/integration surface (progress UI, watchers, convenience features)
- packaging and optional integrations
- language bindings (`cbc-py`, `cbc-node`) unless explicitly listed in release scope

Non-TCB code is still tested and reviewed, but not held to the same evidentiary standard as TCB-A unless explicitly promoted.

## 2.3 WASM Distribution Scope
If `cbc-wasm` is released as a supported artifact, it is considered trust-relevant and must meet reproducibility and inspection requirements equivalent to native binaries for the claimed scope.

---

## 3) Threat Model

This section defines the adversaries and what we defend against.

## 3.1 In-Scope Threats

1. **Supply chain compromise**
   - malicious crate update
   - compromised transitive dependency
   - tampered base image/toolchain artifact

2. **Compromised CI or release pipeline**
   - binary differs from reviewed source
   - release artifact replacement

3. **Malicious or compromised maintainer action**
   - hidden behavior introduced in code or build scripts
   - intentional trust-boundary bypass

4. **Remote attacker via malformed inputs**
   - parser confusion
   - memory safety and logic corruption attempts
   - proof/receipt validation bypass attempts

5. **Honest implementation bugs**
   - incorrect validation logic
   - edge-case parsing failures
   - cryptographic misuse bugs

## 3.2 Partially In-Scope / Residual Risks

- compiler/toolchain backdoors (mitigated, not eliminated)
- CPU/microcode and OS-level compromise
- physical side-channel attacks
- nation-state class hardware/firmware implants

These are documented as residual risks; controls reduce but do not fully eliminate them.

---

## 4) Security Goals

1. **Artifact Integrity:** Released binaries are cryptographically bound to source and build recipe.
2. **Behavioral Transparency:** Trust-critical behavior can be inspected at binary/WASM instruction level.
3. **Cryptographic Correctness:** Signature and receipt flows use vetted primitives and safe usage patterns.
4. **Minimal Attack Surface:** Trust-critical builds include only required features and code paths.
5. **Audit Durability:** Evidence remains available and verifiable after CI artifacts expire.

---

## 5) Control Matrix (Threat → Control → Evidence → Gate)

| Threat | Control | Evidence Published | Release Gate |
|---|---|---|---|
| Supply chain compromise | Dependency pinning (`Cargo.lock`), reviewed TCB dependency policy, `cargo vet` for TCB crates | lockfile diff, vet/audit report, dependency manifest | **Required** for release |
| Toolchain/image tamper | Pinned toolchain + pinned container image digest + deterministic env vars | toolchain manifest, container digest, build recipe | **Required** |
| CI/release compromise | Rebuild-from-source verification in independent job/environment | source commit, binary hash, reproducibility log | **Required** |
| Hidden runtime behavior | Import/symbol/syscall diffing for TCB binaries | import table, symbol map, syscall report, diff summary | **Required** |
| Malicious maintainer changes | 2-person review for TCB paths + signed tags/releases | review metadata, signed tag/release metadata | **Required** |
| Parser/input attack | Fuzzing, property tests, corpus regression | fuzz summary, test logs, corpus coverage note | **Required** (minimum thresholds) |
| Crypto misuse/regression | Crypto path review checklist + known-answer tests + low-level inspection of critical symbols | crypto checklist, KAT outputs, selected disassembly excerpts | **Required** |
| Timing leakage regressions | constant-time checks (advisory on shared CI, blocking on dedicated hardware) | timing/leakage report with environment metadata | **Advisory in shared CI; Required on dedicated release runner** |
| Ephemeral evidence loss | Durable audit-bundle publication | immutable release assets + checksummed manifest | **Required** |
| WASM hidden behavior | deterministic wasm build + import/export + wasm disassembly diff | `.wasm` hash, `wasm-objdump`/`wasm2wat` outputs, host import report | **Required** when wasm is released |

---

## 6) Dependency Trust Policy

## 6.1 TCB Dependency Classes
Dependencies used in TCB-A are classified:

- **Class 1 (Critical):** crypto, parsers, serialization affecting validation/auth
- **Class 2 (Important):** utility deps used directly in trust-critical paths
- **Class 3 (Peripheral):** not reachable in trust-critical execution

## 6.2 Required Controls for Class 1/2
- locked versions in `Cargo.lock`
- `cargo vet` policy and attestations for updates
- changelog + security advisory review on bumps
- maintainer sign-off with rationale for each update
- no same-day unreviewed dependency bumps in release branches

## 6.3 Update Cadence
- Class 1: conservative cadence, explicit review windows
- urgent security fixes allowed with expedited two-reviewer approval and post-release retrospective

---

## 7) Build Reproducibility Requirements

A trust-critical release must provide deterministic build instructions and allow independent byte-level verification.

Minimum requirements:
1. pinned Rust toolchain (`rust-toolchain.toml`)
2. pinned dependency graph (`Cargo.lock`)
3. pinned container image digest for repro build environment
4. deterministic build flags (including path remapping where applicable)
5. stable `SOURCE_DATE_EPOCH`
6. documented build commands for native and wasm targets
7. resulting artifact checksums (SHA-256 at minimum)

Output requirement:
- independent rebuild must produce byte-identical artifact (or documented, bounded differences if platform constraints apply)

---

## 8) Low-Level Inspection Policy

## 8.1 Native Artifacts
For TCB release artifacts, publish:
- full or scoped disassembly for trust-critical symbols
- symbol map
- import table
- syscall surface report (or platform-equivalent call surface)
- machine-readable diff against previous release

Any newly introduced sensitive primitive (network/file/process/syscall surface in TCB binaries) requires explicit justification.

## 8.2 WASM Artifacts
For released `cbc-wasm` artifacts, publish:
- wasm binary hash
- import/export table
- textual representation (`wasm2wat`) or equivalent disassembly
- diff report against prior release
- host capability statement (what JS/host functions can be called)

---

## 9) Cryptographic Assurance Policy

Applies to Ed25519, ECDSA/P-256 flows, key derivation/handling, and auth-critical verification.

Required:
- vetted crypto libraries and safe API usage
- known-answer tests (KATs) for critical operations
- negative tests (invalid sigs, malformed receipts, replay/rebinding attempts)
- code review checklist for secret-dependent control flow and memory access
- low-level inspection of selected crypto-critical symbols per release

Constant-time checks:
- shared CI: advisory signal only
- dedicated hardware: release-blocking for tagged trust-critical releases

---

## 10) Evidence and Audit Bundle Specification

Each release publishes an `audit-bundle` containing at minimum:

1. `MANIFEST.json` (file list + SHA-256 for every entry)
2. source commit and tag metadata
3. toolchain and container digest metadata
4. reproducibility build logs
5. native artifact hashes and metadata
6. wasm artifact hashes and metadata (if distributed)
7. symbol/import/syscall reports
8. disassembly/wasm text outputs for audited scope
9. dependency audit outputs (`cargo vet` status, lockfile diff summary)
10. test/fuzz summaries and crypto checklist sign-off

Durability requirement:
- published as immutable release assets and retained long-term
- optional mirror in repository under signed tag path for redundancy

---

## 11) Release Gates

A trust-critical release is blocked unless all required gates pass:

- [ ] TCB scope declared for this release
- [ ] Dependency policy checks pass for TCB classes
- [ ] Reproducible build verification passes
- [ ] Low-level diff checks pass (or approved exceptions)
- [ ] Crypto assurance checklist complete
- [ ] Required tests/fuzz baselines pass
- [ ] Audit bundle generated, checksummed, and published durably
- [ ] Release tag/signature verification complete

Exception handling:
- exceptions must be explicit, time-bounded, and documented in release notes with risk acceptance rationale

---

## 12) Honest User-Facing Trust Statement

Recommended wording:

> You do not need to trust our source-level claims.  
> For trust-critical releases, we publish deterministic build instructions, byte-verifiable artifacts, and low-level inspection outputs for audited paths.  
> You can independently verify what code executes, what external surfaces are reachable, and whether released binaries match reviewed source.

---

## 13) Non-Goals and Limitations

Cobalt does **not** claim:
- elimination of all side-channel risk on all hardware
- immunity to compromised kernels/firmware/microcode
- perfect protection against all nation-state capabilities

Cobalt **does** claim:
- strong, independently verifiable software supply-chain integrity for declared trust scope
- transparent and durable release evidence suitable for third-party audit

---

## 14) Implementation Roadmap (Suggested)

Phase 1:
- finalize TCB scope doc
- enforce pinned toolchain/container digest
- produce basic audit bundle with hashes + build logs

Phase 2:
- add low-level diff gates (native + wasm where applicable)
- enforce dependency vetting policy for TCB dependencies
- durable publication workflow

Phase 3:
- dedicated hardware timing/leakage job for release tags
- expanded formal/property/fuzz evidence in bundle
- periodic third-party audit cadence

---

## 15) Governance

Changes to this trust model require:
- pull request with rationale,
- impact analysis on existing trust claims,
- approval by at least two maintainers,
- explicit mention in release notes if claims or scope change.