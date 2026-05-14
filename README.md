# alani-release

Reproducible image builder, release manifest, SBOM, checksums, signing pipeline, artifact verification, and release evidence.

| Field | Value |
|---|---|
| Tier | MVK required |
| Owner | Release engineering team |
| Aliases | `alani-image` |
| Architectural dependencies | `alani-package`, `alani-sdk`, `alani-docs`, `alani-corpus`, `alani-config` |

## Quick start

```bash
cargo fmt -- --check
cargo test --all-features
cargo test --no-default-features
cargo check --no-default-features
cargo clippy --all-features -- -D warnings
```

## API surface

This crate is a dependency-free Rust 2021 skeleton that remains `no_std` compatible when the default `std` feature is disabled. Architectural dependencies are recorded in Cargo metadata only until neighboring repositories publish stable release-facing APIs.

- `image` defines build profiles, image formats, layouts, bundle inputs, build phases, sealed image artifacts, and fixed-capacity image build plans.
- `sbom` defines SBOM descriptors, components, license review state, relationships, generated documents, and license approval gates.
- `signing` defines checksum algorithms, digest validation, signing keys, signature proofs, verification status, and signing policies.
- `manifest` defines release artifacts, repository records, evidence items, approval gates, release policies, and fixed-capacity release manifests.

Security-sensitive paths fail closed on reserved bits, missing checksums, missing signatures, missing SBOMs, incomplete bundle evidence, license review gaps, denied rights, invalid redaction, and sealed manifests. Public records carry data classification and trace context for release and audit tooling.

Keep public API changes synchronized with `docs/repositories/alani-release.md`, Doc 42, Doc 43, Doc 50, Doc 51, and Doc 63 in `alani-spec`.
