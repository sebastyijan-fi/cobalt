# Contributing to Cobalt

Thank you for your interest in Cobalt! We welcome contributions from the community.

## Development Registry

- **Format Specs**: See the specification docs in `docs/spec/` (if available).
- **Core Library**: `cbc-core/`
- **CLI**: `cbc-cli/`
- **Transforms**: `cbc-transform/`

## Code Standards

- **Rust Version**: 1.73+
- **Lints**: All code must pass `cargo clippy` without warnings.
- **Tests**: All code must pass `cargo test --workspace`.
- **no_std**: `cbc-core` must maintain `no_std` compatibility. Verify with `cargo check -p cbc-core --no-default-features --features alloc`.
- **Fuzzing**: Major changes to decoding logic should be verified with `cargo-fuzz`.

## Pull Request Process

1. Fork the repository and create a branch.
2. Ensure tests and clippy pass.
3. Add tests for new features or bug fixes.
4. Submit a PR with a clear description of the changes.

## License

By contributing, you agree that your contributions will be licensed under the project's MIT License.
