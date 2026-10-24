# Changelog

All notable changes are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
[Semantic Versioning](https://semver.org/).

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
