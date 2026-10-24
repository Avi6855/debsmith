<div align="center">

# debsmith

**Deterministic Debian packaging, policy linting and signed APT repositories — in pure Go.**

[![CI](https://github.com/Avi6855/debsmith/actions/workflows/ci.yml/badge.svg)](https://github.com/Avi6855/debsmith/actions/workflows/ci.yml)
[![Packaging](https://github.com/Avi6855/debsmith/actions/workflows/packaging.yml/badge.svg)](https://github.com/Avi6855/debsmith/actions/workflows/packaging.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/Avi6855/debsmith)](https://goreportcard.com/report/github.com/Avi6855/debsmith)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Go 1.25+](https://img.shields.io/badge/Go-1.25%2B-00ADD8.svg)](https://go.dev)

</div>

debsmith builds Debian and Ubuntu packages from one declarative manifest. It writes
the `.deb`, audits it against Debian Policy, generates a `3.0 (quilt)` source
package, produces a CycloneDX SBOM, proves the build is reproducible and turns a
directory of artifacts into a signed APT repository.

Everything is implemented in Go. `dpkg-deb`, `ar`, `tar`, `gzip`, `xz`, `zstd`,
`gpg` and `lintian` are **not** required on the build host.

```console
$ debsmith build examples/hello --epoch 1700000000
==> Building package
  ✓ hello 1.0.0-1 (all)
    artifact: examples/hello/dist/hello_1.0.0-1_all.deb (2.1 KiB)
    sha256:   9be1e664308249a519555d7c2006a06b328710f2d15e0d551b62d66c5c6987a8
    payload:  14 files, 5 KiB installed
    epoch:    1700000000

$ debsmith lint examples/hello/dist/hello_1.0.0-1_all.deb --fail-on warning
hello 1.0.0-1 (all)

0 error(s), 0 warning(s), 0 info(s) from 30 checks
```

## Why debsmith

Debian packaging is powerful but fragmented: `dpkg-deb` for archives,
`dpkg-source` for source packages, `lintian` for policy, `apt-ftparchive` for
repositories, `gpg` for signing and a pile of shell glue to hold it together.
Reproducibility is usually an afterthought.

debsmith treats packaging as a compiler problem:

| Stage | Input | Output |
|-------|-------|--------|
| Manifest | `debsmith.yaml` + staged filesystem | validated package model |
| Archive | package model + `SOURCE_DATE_EPOCH` | deterministic `.deb` |
| Policy | `.deb` | findings, JSON or SARIF |
| Source | upstream tree + `debian/` | `.orig.tar.gz`, `.debian.tar.xz`, `.dsc` |
| Repository | `.deb` files | `Packages`, `Release`, `InRelease`, `Release.gpg` |
| Supply chain | `.deb` | CycloneDX 1.5 SBOM |
| Proof | manifest | byte-identical rebuild report |

## Features

- **Deterministic `.deb` writer** — sorted tar members, fixed `root:root`
  ownership, zeroed gzip mtimes, `SOURCE_DATE_EPOCH` timestamps and
  reproducible ar headers.
- **Three compressors** — `zstd` (default data), `gzip` (default control) and
  `xz` — plus read support for legacy `bzip2`.
- **Staged payloads** — copy a root filesystem, individual files, directories
  and symlinks; override modes per path; declare conffiles and maintainer
  scripts.
- **30 Debian Policy checks** — names, versions, maintainers, control fields,
  ownership, modes, checksums, conffiles, scripts, doc files, sections,
  dependencies and archive safety.
- **Multiple report formats** — human readable, JSON and SARIF 2.1.0 for GitHub
  code scanning.
- **Signed APT repositories** — Debian `pool/` layout, deterministic
  `Packages`/`Release`, clearsigned `InRelease` and armored `Release.gpg`.
- **Source packages** — `3.0 (quilt)` `.dsc` with MD5, SHA-1 and SHA-256
  checksums; works with `dpkg-source -x` and `dpkg-buildpackage`.
- **CycloneDX 1.5 SBOM** — deterministic serial number, payload digest and a
  dependency graph built from `Depends`/`Pre-Depends`.
- **Reproducibility verifier** — builds twice in isolated directories and
  compares bytes, then falls back to a structural diff when they differ.
- **Safe by construction** — rejects `..`, absolute escapes, duplicate paths,
  unknown control members and oversized control archives.
- **Zero shell-outs** — one static binary for Linux, macOS and Windows.

## Installation

```bash
go install github.com/Avi6855/debsmith/cmd/debsmith@latest
```

Build from source:

```bash
git clone https://github.com/Avi6855/debsmith.git
cd debsmith
make build            # bin/debsmith with version metadata
sudo mv bin/debsmith /usr/local/bin/
```

Shell completion:

```bash
debsmith completion bash > /etc/bash_completion.d/debsmith
debsmith completion zsh  > /usr/share/zsh/site-functions/_debsmith
debsmith completion fish > ~/.config/fish/completions/debsmith.fish
```

## Quick start

A complete working project lives in [`examples/hello`](examples/hello).

### 1. Manifest

```yaml
# debsmith.yaml
name: hello
version: "1.0.0"
revision: "1"
architecture: all
maintainer: "Avinash Rajendra Patil <avinashpatil6855@gmail.com>"
description: "Minimal Debian package built with debsmith"
extendedDescription: |
  A tiny, dependency-free package that demonstrates the full pipeline.
homepage: "https://github.com/Avi6855/debsmith"
section: utils
priority: optional
license: MIT

root: rootfs
permissions:
  /usr/bin/hello: "0755"
conffiles:
  - /etc/hello/hello.conf
scripts:
  postinst: packaging/postinst

source:
  upstream: src
```

### 2. Payload

```text
rootfs/
├── etc/hello/hello.conf
├── usr/bin/hello
├── usr/share/doc/hello/changelog.Debian.gz
├── usr/share/doc/hello/copyright
└── usr/share/man/man1/hello.1.gz
```

### 3. Build

```bash
debsmith build examples/hello --epoch 1700000000 --sbom
debsmith inspect examples/hello/dist/hello_1.0.0-1_all.deb --contents
debsmith lint examples/hello/dist/hello_1.0.0-1_all.deb --fail-on warning
debsmith verify-repro examples/hello --epoch 1700000000
```

```text
hello 1.0.0-1 (all)
  format:        debian-binary 2.0
  control:       gzip
  data:          zstd
  size:          2.1 KiB
  sha256:        9be1e664308249a519555d7c2006a06b328710f2d15e0d551b62d66c5c6987a8

Control:
  Package: hello
  Version: 1.0.0-1
  Architecture: all
  Maintainer: Avinash Rajendra Patil <avinashpatil6855@gmail.com>
  Installed-Size: 5
  Section: utils
  Priority: optional
  Homepage: https://github.com/Avi6855/debsmith
  Description: Minimal Debian package built with debsmith
    A tiny, dependency-free package that demonstrates the full debsmith
    pipeline: deterministic archives, Debian Policy linting, source package
    generation, SBOM output and signed APT repositories.
```

## Commands

| Command | Purpose |
|---------|---------|
| `debsmith build [dir]` | Build a binary `.deb` from `debsmith.yaml` |
| `debsmith inspect <deb>` | Show control metadata, members and payload |
| `debsmith lint <deb>...` | Run Debian Policy checks (text, JSON or SARIF) |
| `debsmith source [dir]` | Generate a `3.0 (quilt)` source package |
| `debsmith repo [dir]` | Build and optionally sign an APT repository |
| `debsmith verify-repro [dir]` | Build twice and compare the artifacts |
| `debsmith version` | Print version and build information |

Global flags: `--verbose`, `--quiet`, `--no-color`.

### build

```bash
debsmith build .                                   # dist/<name>_<ver>_<arch>.deb
debsmith build . -o /srv/packages/app.deb
debsmith build . --compression xz --control-compression gzip
debsmith build . --sbom --epoch 1700000000 --json
```

### lint

```bash
debsmith lint pkg.deb                              # exit 1 on errors
debsmith lint pkg.deb --fail-on warning            # strict CI gate
debsmith lint pkg.deb --json
debsmith lint pkg.deb --sarif > debsmith.sarif
debsmith lint --list-checks
```

### repo

```bash
debsmith repo dist                                 # pool/ + dists/stable
debsmith repo dist --suite bookworm --component main --arch amd64 --arch arm64
debsmith repo dist --sign-key ~/.config/debsmith/release.asc
```

```text
dist/
├── dists/stable/
│   ├── InRelease
│   ├── Release
│   ├── Release.gpg
│   └── main/binary-amd64/Packages{,.gz}
└── pool/main/h/hello/hello_1.0.0-1_amd64.deb
```

Client configuration:

```bash
curl -fsSL https://example.com/repo/release.asc \
  | sudo gpg --dearmor -o /usr/share/keyrings/debsmith.gpg
echo "deb [signed-by=/usr/share/keyrings/debsmith.gpg] https://example.com/repo stable main" \
  | sudo tee /etc/apt/sources.list.d/debsmith.list
sudo apt update && sudo apt install hello
```

## Manifest reference

The complete schema, defaults and validation rules are in
[`docs/manifest.md`](docs/manifest.md). Highlights:

| Field | Default | Description |
|-------|---------|-------------|
| `architecture` | host dpkg arch | target architecture or `all` |
| `revision` | `1` | Debian revision |
| `section` / `priority` | `utils` / `optional` | archive metadata |
| `compression` | `zstd` | `data.tar` compressor |
| `controlCompression` | `gzip` | `control.tar` compressor |
| `root` | — | directory tree copied into the payload |
| `files[]` | — | individual copies with optional mode |
| `directories[]` | — | explicit directories and modes |
| `symlinks[]` | — | symbolic links |
| `permissions{}` | — | per-path mode overrides |
| `conffiles[]` | — | `/etc` files managed by dpkg |
| `scripts{}` | — | `preinst`, `postinst`, `prerm`, `postrm`, `config` |
| `controlFiles{}` | — | `templates`, `triggers`, `shlibs`, `symbols` |
| `source.upstream` | — | upstream tree for `.orig.tar.gz` |
| `source.debian` | `debian` | source packaging directory |
| `sbom` | `false` | write a CycloneDX sidecar |

All modes are octal (`"0755"`). Payload paths are absolute (`/usr/bin/app`).

## Reproducible builds

debsmith is deterministic by construction:

1. Every tar member is sorted by path and written with PAX headers.
2. Ownership is forced to `uid=0, gid=0, uname=root, gname=root`.
3. Every timestamp is the build epoch (`--epoch` or `SOURCE_DATE_EPOCH`).
4. gzip headers carry no filename and a zero mtime (`OS=255`).
5. zstd runs with a single encoder goroutine and a fixed window.
6. ar headers use fixed modes, zero uid/gid and the build epoch.
7. Repository indexes are sorted and checksummed in a fixed order.
8. OpenPGP signatures are created at the build epoch, not wall-clock time.

```bash
debsmith verify-repro examples/hello --epoch 1700000000
```

```text
==> Verifying reproducibility
  ✓ reproducible: identical SHA-256 9be1e664308249a519555d7c2006a06b328710f2d15e0d551b62d66c5c6987a8
    size: 2.1 KiB
```

If two artifacts differ, `verify-repro` compares ar members and payload entries
and reports the first structural differences (mode, size, content, link
targets) instead of a bare hash mismatch.

## Debian Policy linting

30 checks cover the failures that matter most in review:

```text
$ debsmith lint hello.deb --fail-on warning
hello 1.0.0-1 (all)
  warning DSM010  mode 0666  etc/hello/hello.conf
  warning DSM016  file has no md5sums entry  usr/bin/hello

0 error(s), 2 warning(s), 0 info(s) from 30 checks
```

The full catalog is in [`docs/checks.md`](docs/checks.md) and at
`debsmith lint --list-checks`. Each finding has a stable `DSM###` code, a
severity, an optional payload path and remediation advice. `--sarif` produces a
SARIF 2.1.0 log that GitHub code scanning accepts directly.

| Area | Examples |
|------|----------|
| Control | required fields, package name, version, architecture, maintainer |
| Payload | empty package, setuid, world-writable, `/usr/local`, `/home`, `/tmp` |
| Integrity | missing md5sums, mismatched hashes, stale entries |
| Conffiles | missing payload file, path outside `/etc` |
| Scripts | missing executable bit, missing shebang |
| Documentation | missing copyright, missing changelog |
| Metadata | unknown section/priority, self-dependency, installed size |
| Archive | non-root ownership, unsafe or broken symlinks, unknown control members |

## Source packages

```bash
debsmith source examples/hello --epoch 1700000000
```

```text
examples/hello/dist/
├── hello_1.0.0.orig.tar.gz
├── hello_1.0.0-1.debian.tar.xz
└── hello_1.0.0-1.dsc
```

The `.dsc` lists MD5, SHA-1 and SHA-256 checksums for both tarballs and is
compatible with `dpkg-source`:

```bash
dpkg-source -x hello_1.0.0-1.dsc hello
cd hello && dpkg-buildpackage -b -us -uc
```

If `source.debian` is missing, debsmith generates a minimal `debian/` scaffold
(`control`, `changelog`, `copyright`, `rules`, `source/format`). For real
packages, ship your own directory; it is validated for `debian/control`,
`debian/rules` and `debian/source/format`.

Use `--sign-key` to clearsign the `.dsc` for upload.

## SBOM

```bash
debsmith build examples/hello --sbom
```

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "serialNumber": "urn:uuid:…",
  "metadata": {
    "timestamp": "2023-11-14T22:13:20Z",
    "component": {
      "type": "application",
      "name": "hello",
      "version": "1.0.0-1",
      "purl": "pkg:deb/hello@1.0.0-1?arch=all"
    }
  },
  "components": [
    { "type": "library", "name": "libc6", "version": "2.38" }
  ]
}
```

The serial number is derived from the artifact digest, so repeated builds of the
same bytes produce identical BOMs.

## Verified against the real Debian toolchain

The repository ships [`scripts/verify-container.sh`](scripts/verify-container.sh),
which runs the artifacts through dpkg, lintian, dpkg-source, dpkg-buildpackage
and apt inside Ubuntu 24.04:

```bash
docker run --rm -v "$PWD:/work" -w /work ubuntu:24.04 \
  bash scripts/verify-container.sh
```

Verified in this repository:

- `dpkg-deb --info` and `--contents` parse the archive and its modes.
- `dpkg -i` installs the package; the maintainer script runs; conffiles are
  registered; the binary works.
- `lintian` reports **0 errors** (one expected `initial-upload-closes-no-bugs`
  warning for a first upload).
- `dpkg-source -x` extracts the `.dsc`.
- `dpkg-buildpackage -b -us -uc` rebuilds a working binary package from the
  generated source package.
- `apt-get install hello=1.0.0-1` from the generated repository installs the
  exact artifact built by debsmith.

## Architecture

```text
debsmith.yaml ──▶ manifest.Load ──▶ manifest.Stage ──▶ deb.Write ──▶ .deb
                                      │                  │
                                      │                  ├──▶ policy.Lint ──▶ text/JSON/SARIF
                                      │                  ├──▶ sbom.Generate ──▶ .cdx.json
                                      │                  └──▶ repro.Compare ──▶ proof
                                      │
                                      └──▶ sourcepkg.Build ──▶ .dsc + tarballs

.deb files ──▶ aptrepo.Build ──▶ Packages / Release / InRelease / Release.gpg
```

| Package | Responsibility |
|---------|----------------|
| `internal/deb` | ar, tar, compression, control fields, deterministic writer, streaming reader |
| `internal/manifest` | YAML loading, validation, staging, control generation |
| `internal/policy` | check registry, 30 checks, text/JSON/SARIF reports |
| `internal/aptrepo` | APT indexes, pool layout, OpenPGP Release signing |
| `internal/sourcepkg` | 3.0 (quilt) source packages and `.dsc` checksums |
| `internal/sbom` | CycloneDX 1.5 generation |
| `internal/repro` | double-build verification and structural diffs |
| `internal/build` | shared pipeline used by the CLI and the verifier |
| `internal/cli` | cobra commands, exit codes and JSON output |

Design notes and the reproducibility contract are in
[`docs/architecture.md`](docs/architecture.md).

## Development

Requirements: Go 1.25+.

```bash
make build        # bin/debsmith
make test         # go test ./...
make cover        # coverage.html
make fmt vet      # formatting and static checks
make verify       # build, lint, SBOM, source package and repository
make e2e          # Ubuntu 24.04 container verification (Docker)
```

Coverage of the core packages:

```text
internal/deb        79.9%
internal/policy     87.5%
internal/sbom       82.8%
internal/sourcepkg  76.3%
internal/manifest   74.9%
internal/tarutil    75.6%
internal/repro      72.8%
internal/aptrepo    72.4%
internal/build      70.5%
internal/cli        60.9%
```

## Limitations

- debsmith packages a **staged payload**, it does not run `debhelper`; use it for
  prebuilt binaries, scripts, configuration and documentation trees.
- Source packages contain one binary stanza per manifest; multi-binary source
  packaging still belongs in `debian/control` and your `debian/rules`.
- Debug symbol packages, `Build-Ids` splitting and `dh_dwz` are not generated.
- One component per repository run (`main` by default).
- `Installed-Size` is an estimate: one KiB per file rounded up, as dpkg does.
- Maintainer scripts are stored, never executed, during packaging.
- APT `Acquire-By-Hash` is not emitted.
- Signing reads armored or binary OpenPGP private keys; passphrases come from a
  file or `DEBSMITH_GPG_PASSPHRASE`, never from a command-line argument.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). Security reports are covered by
[`SECURITY.md`](SECURITY.md).

## License

MIT — see [`LICENSE`](LICENSE).

## Author

**Avinash Rajendra Patil** — author and maintainer.

Built with [Go](https://go.dev), [Cobra](https://github.com/spf13/cobra),
[ProtonMail go-crypto](https://github.com/ProtonMail/go-crypto) and
[klauspost/compress](https://github.com/klauspost/compress).
