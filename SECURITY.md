# Security Policy

## Supported Versions

Cobalt currently supports security fixes for the **latest stable release** only.

| Version | Supported          |
| ------- | ------------------ |
| Latest  | :white_check_mark: |
| Older   | :x:                |

---

## Reporting a Vulnerability

If you believe you found a security issue, please report it privately.

- **Do not** open a public issue for unpatched vulnerabilities.
- Include as much detail as possible so we can reproduce and assess impact quickly.

If your report concerns trust-critical behavior, also review:

- `docs/TRUST_MODEL.md`

---

## Contact (Action Required)

If you have discovered a security vulnerability in Cobalt, please send an email to `niklas@sebastyijan.fi`.

Alternatively, you may report issues privately via GitHub Security Advisories by navigating to the "Security" tab.

---

## Recommended Report Format

Please include:

- Affected version / commit
- Impact summary
- Reproduction steps or proof of concept
- Expected vs actual behavior
- Any logs, traces, or artifacts needed to validate

If encryption is available, prefer encrypted submission for sensitive details.

---

## Response Targets

Once security intake is operational, target:

1. **Acknowledgement:** within 48 hours
2. **Triage/Severity:** within 5 business days
3. **Critical fix target:** within 14 days where feasible

These are goals, not guarantees.

---

## Disclosure Policy

- Coordinated disclosure is expected.
- Default disclosure window target: **90 days** from initial report.
- Earlier disclosure may occur after a fix is released and users have had time to update.
- Reporters are asked not to publicly disclose details before the agreed disclosure date.

---

## Integrity & Verification

Cobalt publishes reproducibility guidance and trust claims in project docs:

- `docs/TRUST_MODEL.md`

Current reproducible build container example:

- `Dockerfile.repro`

If a release artifact does not match expected verification outputs, treat it as untrusted and report it through the private security channel once configured.

---

## Scope Note

This policy applies to the Cobalt codebase and official release artifacts. Third-party wrappers, forks, and downstream packaging may have different security properties and are out of scope unless explicitly stated.
