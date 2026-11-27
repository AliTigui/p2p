# Software Bill of Materials

P2P Messenger publishes SPDX 2.3 JSON SBOMs generated from the locked Cargo
dependency graphs. The generator is `scripts/generate_sbom.py`; it uses only the
Python standard library and `cargo metadata --locked`.

## Generate locally

From the repository root:

```bash
python3 scripts/generate_sbom.py \
  --manifest-path Cargo.toml \
  --workspace-name root \
  --output sbom/root.spdx.json

python3 scripts/generate_sbom.py \
  --manifest-path fuzz/Cargo.toml \
  --workspace-name fuzz \
  --output sbom/fuzz.spdx.json
```

Both commands run fail-closed self-tests before invoking Cargo. The generated
`sbom/` directory is ignored because it is an artifact, not source.

## Record boundary

Package counts, relationship counts, and `Cargo.lock` SHA-256 digests quoted in
milestone/security records are historical pre-v3 results where presented as
final. Current post-v3 final SBOM and gate results are recorded in
`SECURITY_TESTS.md`, `PROJECT_STATUS.md`, and the final report. This document
describes the generator and its scope, not a current count or hash.

## What is recorded

Each document contains:

- every package in the corresponding locked Cargo graph;
- package name, version, declared license, crates.io download location where
  applicable, and a cargo package URL;
- workspace-relative manifest locators for local crates;
- `DESCRIBES` relationships from the document to workspace members;
- `DEPENDS_ON` relationships from Cargo's resolved graph;
- the SHA-256 digest of the exact `Cargo.lock` used.

The security workflow generates both SBOMs and checks that regeneration is
byte-for-byte identical. Release builds copy them into `dist/` as
`sbom-root.spdx.json` and `sbom-fuzz.spdx.json`, so the published `SHA256SUMS`
covers them as well.

## Determinism and privacy

The document creation time is fixed to `1970-01-01T00:00:00Z`; it is not a claim
about when the SBOM was generated. The document namespace is derived from the
workspace name and lockfile digest. Absolute checkout paths are normalized to
workspace-relative paths, and the generator rejects a document if an absolute
workspace path or dangling relationship endpoint remains. Deprecated SPDX slash
license separators such as `MIT/Apache-2.0` are normalized to `MIT OR
Apache-2.0`.

## Scope limits

- This is a source/lockfile SBOM, not a binary composition analysis. It does not
  inspect compiled artifacts, statically linked C code, vendored source, or
  runtime-loaded components.
- License strings are copied from Cargo metadata; generated SBOMs do not replace
  `cargo deny` policy enforcement or legal review.
- An SBOM does not sign the release, establish build provenance, provide
  reproducible binaries, or prove that dependencies are free of vulnerabilities.
- The fuzz SBOM describes the fuzz tool workspace and is not part of the native
  application's runtime dependency graph.
