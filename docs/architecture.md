# Architecture

debsmith is a packaging compiler: a manifest and a staged filesystem go in,
verified Debian artifacts come out. Every stage is a pure Go package with no
process execution.

## Pipeline

```text
manifest.Load(path)
    │  YAML → Manifest, strict fields, validation, defaults
    ▼
manifest.Stage()
    │  root tree + files + directories + symlinks + permissions
    │  → []deb.File, maintainer scripts, extra control members
    ▼
build.Run()
    ├── deb.Write() ──────────▶ .deb (ar + control.tar + data.tar)
    ├── deb.Read() ───────────▶ verify round-trip
    ├── sbom.Generate() ──────▶ .deb.cdx.json
    └── sha256(artifact) ─────▶ build result
    ▼
policy.Lint() ────────────────▶ findings (text / JSON / SARIF)
    ▼
repro.Verify() ───────────────▶ two builds + structural diff
```

Repository and source package generation are separate top-level pipelines:

```text
.deb files ─▶ deb.ReadFile ─▶ pool copy + Packages + Release ─▶ OpenPGP sign

upstream/ + debian/ ─▶ tarutil.CollectDir ─▶ .orig.tar.gz + .debian.tar.xz
                                              │
                                              └──▶ .dsc checksums ─▶ clearsign
```

## Package layout

| Package | Responsibility |
|---------|----------------|
| `internal/deb` | ar reader/writer, tar assembly, compression, deb822 fields, Debian version comparison, streaming `.deb` reader |
| `internal/manifest` | strict YAML loading, defaults, validation, staging, control stanza |
| `internal/policy` | check registry, 30 checks, text/JSON/SARIF rendering |
| `internal/aptrepo` | pool layout, Packages/Release generation, OpenPGP signing |
| `internal/sourcepkg` | 3.0 (quilt) tarballs, `.dsc`, generated `debian/` scaffold |
| `internal/sbom` | CycloneDX 1.5 document and deterministic serial |
| `internal/repro` | double-build verification and structural comparison |
| `internal/build` | pipeline used by both the CLI and the verifier |
| `internal/tarutil` | deterministic tar collection with mode normalisation |
| `internal/cli` | cobra commands, exit codes, JSON output |
| `internal/ui` | zero-dependency terminal messages and colors |
| `internal/version` | build metadata injected with `-ldflags` |

## Determinism contract

Two builds of the same manifest with the same epoch and compressor must be
byte-identical. The contract is enforced by construction:

| Layer | Rule |
|-------|------|
| Manifest | staging sorted by path; explicit entries override `root`; modes normalised |
| Tar | PAX headers, sorted names, `uid/gid=0`, `uname/gname=root`, epoch mtime |
| gzip | `BestCompression`, zero `ModTime`, `OS=255`, no filename |
| zstd | single encoder goroutine, fixed window, fixed level |
| xz | standard writer, no timestamps |
| ar | fixed header width, zero uid/gid, mode `100644`, epoch mtime |
| Debian | canonical field order, sorted md5sums and conffiles |
| Repository | packages sorted by name and Debian version, indexes sorted by path |
| Release | fixed checksum block order, epoch `Date` |
| OpenPGP | signature creation time is the build epoch; RSA/EdDSA are deterministic |

`repro.Compare` does more than compare hashes: if bytes differ it lists ar
member mismatches and payload entry differences (mode, size, MD5, link target),
so a failure points at the stage that broke determinism.

## Security model

debsmith parses untrusted archives and signs release metadata.

- **Path containment** — `deb.normalizePackagePath` and `normalizeDataPath`
  reject empty paths, `..` components and NUL bytes before any write. Symlink
  targets are checked relative to the package root.
- **Bounded parsing** — control archives are capped at 64 MiB; individual
  control members at 16 MiB; `debian-binary` at 64 bytes.
- **No execution** — maintainer scripts are stored as bytes, never run.
- **Checksum verification** — `inspect --verify` recomputes MD5 for every file;
  the reader records whole-file MD5, SHA-1 and SHA-256 while streaming.
- **Signing keys** — passphrases come from a file or
  `DEBSMITH_GPG_PASSPHRASE`, never a flag value, so they stay out of the process
  list. Keys are decrypted in memory only.
- **Deterministic signatures** — signing at the build epoch avoids leaking wall
  clock time and makes `InRelease` reproducible.
- **No network** — debsmith never downloads sources or keys; it is safe to run
  in a hermetic CI job.

Decompression is inherently unbounded on output; debsmith caps compressed
control input and streams data archives. Do not run it on hostile multi-gigabyte
packages in a privileged context.

## Debian archive details

### Binary package

```text
debian-binary         "2.0\n"
control.tar.gz        ./control, ./md5sums, ./conffiles, scripts
data.tar.zst          ./ + payload
```

`Installed-Size` is the sum of `ceil(size/1024)` per regular file, minimum 1.
`md5sums` covers every regular payload file, including conffiles.

### Source package

```text
<name>_<upstream>.orig.tar.gz        <name>-<upstream>/...
<name>_<version>.debian.tar.xz       debian/...
<name>_<version>.dsc                 Format: 3.0 (quilt) + checksums
```

The epoch is stripped from filenames and `:` is encoded as `%3a`, matching
`dpkg-source`. The `.dsc` lists MD5, SHA-1 and SHA-256 for both tarballs.

### Repository

```text
pool/<component>/<prefix>/<name>/<file>.deb
dists/<suite>/<component>/binary-<arch>/Packages{,.gz}
dists/<suite>/Release
dists/<suite>/InRelease        (optional)
dists/<suite>/Release.gpg      (optional)
```

`Architecture: all` packages are repeated in every concrete architecture index.
The prefix follows Debian's pool rules (`libfoo` → `libf`, otherwise the first
letter). Index entries carry `Filename`, `Size`, `MD5sum`, `SHA1` and `SHA256`.

## Testing strategy

| Layer | Tests |
|-------|-------|
| deb | round-trip for three compressors, determinism, traversal rejection, MD5 audit, version comparison |
| manifest | defaults, unknown fields, validation matrix, staging overrides, conffile validation |
| policy | clean package, one test per check, thresholds, SARIF schema |
| aptrepo | index layout, pool copy, determinism/idempotence, signature verification |
| sourcepkg | tarball layout, checksums, scaffold, determinism |
| build | pipeline, SBOM, explicit and directory output |
| repro | reproducible run and structural diff on epoch mismatch |
| cli | build → lint → inspect JSON, SARIF, exit codes |
| e2e | Ubuntu 24.04 container: dpkg, lintian, dpkg-source, dpkg-buildpackage, apt |

## Extension points

**Add a policy check** — append a `check` to the registry in
`internal/policy/policy.go`, assign the next `DSM###` code, add a case to
`TestChecksTrigger`, and document it in `docs/checks.md`.

**Add a compressor** — extend `Compression`, `newCompressor`,
`newDecompressor`, `Ext`, and the manifest validation; add a round-trip case to
`TestWriteReadRoundTrip`.

**Add a control field** — extend `deb.Control`, `Fields`, `ParseControl` and the
known-field set; add a round-trip assertion.

**Add a command** — create `internal/cli/<name>.go`, register it in
`NewRootCommand`, keep the handler a thin wrapper, and test the JSON contract.

## Non-goals

- Running `debhelper` or arbitrary build systems.
- Replacing `dpkg` as an installer.
- A full APT server (use nginx or object storage in front of the generated tree).
- Multi-binary source packaging beyond the manifest's single binary stanza.
- Windows package output: the artifacts are Debian packages; the tool itself
  builds on Windows for convenience.
