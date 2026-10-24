# Manifest reference

`debsmith.yaml` is the single input for `build`, `source` and `verify-repro`.
Unknown fields are rejected, so typos fail fast instead of silently changing a
package.

```yaml
name: hello
version: "1.0.0"
revision: "1"
architecture: all
maintainer: "Avinash Rajendra Patil <avinashpatil6855@gmail.com>"
description: "Minimal Debian package built with debsmith"
extendedDescription: |
  A tiny package that demonstrates the pipeline.
homepage: "https://github.com/Avi6855/debsmith"
section: utils
priority: optional
license: MIT
copyright: "2026, Avinash Rajendra Patil"

root: rootfs
permissions:
  /usr/bin/hello: "0755"
conffiles:
  - /etc/hello/hello.conf
scripts:
  postinst: packaging/postinst

source:
  upstream: src
  debian: debian
```

## Top level

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `name` | string | yes | — | Binary package name. At least two characters: lowercase letters, digits, `+`, `-`, `.`; must start alphanumeric. |
| `version` | string | yes | — | Upstream version. Starts with a digit; `[A-Za-z0-9.+~:-]`. Without `revision`, may contain `-`. |
| `revision` | string | no | `1` | Debian revision. `[A-Za-z0-9.+~]`. |
| `architecture` | string | no | host dpkg arch | Target architecture (`amd64`, `arm64`, `i386`, `armhf`, …) or `all`. |
| `maintainer` | string | yes | — | `Name <email@example.com>`. |
| `description` | string | yes | — | One-line synopsis, at most 80 characters is recommended. |
| `extendedDescription` | string | no | — | Multi-line description. Blank lines become ` .` in the control file. |
| `homepage` | string | no | — | Homepage control field and source metadata. |
| `section` | string | no | `utils` | Debian archive section. |
| `priority` | string | no | `optional` | `required`, `important`, `standard`, `optional` or `extra`. |
| `license` | string | no | — | Used by the generated source copyright file. |
| `copyright` | string | no | `<year>, <maintainer>` | Copyright line for the generated source package. |
| `multiArch` | string | no | — | `same`, `foreign`, `allowed` or `no`. |
| `essential` | bool | no | `false` | Sets `Essential: yes`. |
| `compression` | string | no | `zstd` | `data.tar` compressor: `zstd`, `gzip` or `xz`. |
| `controlCompression` | string | no | `gzip` | `control.tar` compressor. |
| `sbom` | bool | no | `false` | Generate a CycloneDX sidecar when building. |
| `root` | string | no | — | Directory tree copied into the payload, relative to the manifest. |
| `files` | list | no | — | Individual file copies. |
| `directories` | list | no | — | Explicit directories, including empty ones. |
| `symlinks` | list | no | — | Symbolic links. |
| `permissions` | map | no | — | Per-path mode overrides (octal strings). |
| `conffiles` | list | no | — | Payload paths managed by dpkg as configuration files. |
| `scripts` | map | no | — | Maintainer scripts. |
| `controlFiles` | map | no | — | Additional control members. |
| `source` | object | no | — | Source package configuration. |

### Dependency fields

All are lists of Debian relations and are joined with `, `:

```yaml
preDepends: ["dpkg (>= 1.19)"]
depends: ["libc6 (>= 2.38)", "zlib1g"]
recommends: ["ca-certificates"]
suggests: ["hello-doc"]
enhances: []
breaks: ["old-hello (<< 1.0)"]
conflicts: []
replaces: ["old-hello (<< 1.0)"]
provides: ["hello"]
```

### Payload entries

```yaml
root: rootfs                 # everything below rootfs/, modes normalised

files:
  - source: build/app        # relative to the manifest
    path: /usr/bin/app
    mode: "0755"             # optional; otherwise 0644/0755 from source

directories:
  - path: /var/lib/app
    mode: "0750"

symlinks:
  - path: /usr/bin/app-cli
    target: app

permissions:
  /etc/app/app.conf: "0640"
```

Rules:

- `files[].source` may not be a directory; use `root` or `directories`.
- `files[].path`, `directories[].path`, `symlinks[].path` and `permissions` keys
  are package paths. Leading `/` is optional; `..` is rejected.
- Explicit `files`, `directories` and `symlinks` override matching entries from
  `root`; `permissions` is applied last and must reference an existing path.
- Modes are octal. `0644` and `0755` are the normalised defaults so a checkout
  on Windows and Linux produce identical archives.
- Every conffile must exist in the staged payload.

### Maintainer scripts

Allowed keys: `preinst`, `postinst`, `prerm`, `postrm`, `config`.

```yaml
scripts:
  postinst: packaging/postinst
```

Each file is embedded with mode `0755` and must start with `#!` (lint check
`DSM020`). Scripts are never executed by debsmith.

Additional control members: `templates`, `triggers`, `shlibs`, `symbols`
(mode `0644`).

## Source packages

| Field | Default | Description |
|-------|---------|-------------|
| `upstream` | — | Directory containing the upstream tree. Required by `debsmith source`. |
| `debian` | `debian` | Directory containing `control`, `rules` and `source/format`. |
| `buildDepends` | `["debhelper-compat (= 13)"]` | `Build-Depends` field in `.dsc` and generated control. |
| `standardsVersion` | `4.7.0` | `Standards-Version` field. |
| `binaries` | `[name]` | `Binary:` list in `.dsc`. |

The upstream tree must not contain `debian/`; debsmith excludes `debian/`,
`.git/`, the manifest, `.debsmith/` and a nested output directory from
`.orig.tar.gz`.

If `source.debian` does not exist, a scaffold is generated:

```text
debian/
├── changelog
├── control
├── copyright
├── rules             # mode 0755
└── source/format     # 3.0 (quilt)
```

The generated `rules` file uses `dh` with empty `dh_auto_*` overrides, so it
produces an empty package until you add an install step. Real projects should
ship their own `debian/` directory.

## Validation summary

Loading or staging fails with a list of problems when:

- a package name, version, revision, architecture or maintainer is malformed;
- the description is empty or spans multiple lines;
- `multiArch` or a compressor is unknown;
- a script or control-file key is unsupported;
- a file entry has no `source` or `path`;
- a directory or symlink entry is incomplete;
- a conffile is not in the payload;
- a `permissions` key points at a missing path;
- an unknown YAML field appears.

## Complete example

See [`examples/hello/debsmith.yaml`](../examples/hello/debsmith.yaml) and the
integration tests under `internal/build` and `internal/sourcepkg`.
