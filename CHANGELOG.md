# Changelog

All notable changes are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
[Semantic Versioning](https://semver.org/).

## [0.1.2] - 2026-10-24

### Fixed

- `--quiet` now prints the result summary instead of suppressing it; warnings
  remain visible.
- `--verbose` now emits project and epoch diagnostics to stderr.
- A version with an embedded `-N` suffix is split into upstream version and
  Debian revision when `revision` is omitted.
- Invalid `--fail-on` values are rejected instead of silently falling back to
  `error`.

## [0.1.1] - 2026-10-24

### Fixed

- `--json` output for `build`, `inspect`, `repo`, `source` and `verify-repro`
  is now valid JSON; human progress lines are suppressed in JSON mode.
- `sbom: true` in `debsmith.yaml` now generates the CycloneDX sidecar instead of
  being ignored.
- Repository and source-package JSON results use lower camelCase keys.
- Archive readers reject absolute member paths, matching the documented
  containment rules.
- The container verification now fails when lintian reports an `E:` finding.

### Added

- Regression tests for extra control members, clearsigned `.dsc` files,
  manifest-driven SBOMs and pure JSON CLI output.

## [0.1.0] - 2026-10-24

### Added

- Deterministic `.deb` writer (ar, PAX tar, gzip/zstd/xz) with fixed ownership,
  epoch timestamps and canonical control fields.
- Streaming `.deb` reader with whole-file MD5/SHA-1/SHA-256 and payload MD5 audit.
- Strict `debsmith.yaml` manifest: payload root, files, directories, symlinks,
  permissions, conffiles, maintainer scripts, extra control members, dependency
  fields and source package settings.
- 30 Debian Policy checks with text, JSON and SARIF 2.1.0 output.
- Signed APT repository generation: `pool/` layout, `Packages{,.gz}`,
  `Release`, `InRelease` and `Release.gpg`.
- Debian `3.0 (quilt)` source packages with `.orig.tar.gz`,
  `.debian.tar.xz`, checksummed `.dsc`, optional clearsigning and a generated
  `debian/` scaffold.
- CycloneDX 1.5 SBOM sidecars with deterministic serial numbers and dependency
  graph.
- Reproducibility verifier with double builds and structural diffing.
- CLI commands: `build`, `inspect`, `lint`, `repo`, `source`, `verify-repro`,
  `version`.
- Ubuntu 24.04 container verification covering dpkg, lintian, dpkg-source,
  dpkg-buildpackage and apt.
- GitHub Actions CI matrix, packaging verification, CodeQL and GoReleaser
  configuration.
