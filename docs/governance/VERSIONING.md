# Governance: Versioning Policy

**Date:** 2026-02-20
**Scope:** `cbc-core`, `cbc-kms`, `cbc-server`, and all peripheral API wrappers.

## 1. Adherence to Semantic Versioning

The Cobalt ecosystem strictly adheres to [Semantic Versioning 2.0.0](https://semver.org/).

Given a version number `MAJOR.MINOR.PATCH`, we increment the:

1. **MAJOR** version when we make incompatible API/ABI changes or mutate the CBC wire format.
2. **MINOR** version when we add functionality in a backward-compatible manner (e.g., introducing a new Hash Suite option that doesn't break old parsers).
3. **PATCH** version when we make backward-compatible bug fixes or security patches (e.g., bounding decompression limits).

## 2. Deprecation Windows

Enterprise clients require stability. Features, endpoints, and configuration flags slated for removal **MUST** undergo a formal deprecation period.

### 2.1 API Endpoints (`cbc-server`)

Removing or functionally altering a REST endpoint requires a minimum **6-month deprecation window**. The endpoint must return a `Deprecation` HTTP header indicating the planned sunset date.

### 2.2 Core Rust Libraries (`cbc-core`)

Removing public structs, traits, or functions requires the item to be decorated with `#[deprecated(since = "X.Y.Z", note = "Use Foo instead")]`. It can only be eliminated completely in the next **MAJOR** version bump.

## 3. Wire Format Compatibility matrix

- `cbc-core` **MUST** retain the ability to parse older `MAJOR` wire formats for a designated grace period (N-1), but is strictly permitted to deny parsing N-2 artifacts.
- Encoders **SHOULD** default to the most recent wire format unless a legacy compatibility flag is passed by the operator.
- Security patches applied to parsing behavior (e.g., zip-bomb protection) **MUST** apply retroactively to all compatible wire versions, not purely the modern one.

## 4. Breaking Change Protocol

Every single `MAJOR` release containing a breaking change **MUST** include:

1. A detailed entry in the `CHANGELOG.md`.
2. A formal `MIGRATION_x_to_y.md` guide detailing the mechanical steps required to upgrade system architecture.
3. If altering the underlying database or wire format, an official binary extraction/re-encoding migration script.
