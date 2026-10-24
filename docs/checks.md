# Policy checks

`debsmith lint` runs 30 checks and assigns a stable `DSM###` code. Run
`debsmith lint --list-checks` for the same catalog on the command line.

Severities: **error** fails `--fail-on error` (the default), **warning** fails
`--fail-on warning`, **info** only fails `--fail-on info`.

| Code | Severity | Check | What it protects |
|------|----------|-------|------------------|
| DSM001 | error | `control-required-fields` | `Package`, `Version`, `Architecture`, `Maintainer` and `Description` exist |
| DSM002 | error | `package-name` | lowercase, at least two characters, allowed punctuation |
| DSM003 | error | `package-version` | dpkg-compatible version syntax |
| DSM004 | warning | `architecture` | known dpkg architecture or `all` |
| DSM005 | error | `maintainer` | `Name <email>` format |
| DSM006 | warning | `description-synopsis` | synopsis at most 80 characters |
| DSM007 | warning | `description-lines` | extended description lines at most 80 characters |
| DSM008 | error | `empty-package` | payload contains at least one file or link |
| DSM009 | error | `setuid` | no setuid/setgid payload files |
| DSM010 | warning | `world-writable` | no world-writable payload files |
| DSM011 | warning | `usr-local` | nothing installed under `/usr/local` |
| DSM012 | warning | `transient-paths` | nothing installed in `/home`, `/tmp`, `/var/tmp` |
| DSM013 | warning | `debian-dir` | no `debian/` directory in the payload |
| DSM014 | warning | `missing-md5sums` | an `md5sums` control member exists |
| DSM015 | error | `md5sum-mismatch` | declared MD5 equals payload MD5 |
| DSM016 | warning | `md5sum-coverage` | every file has a sum and every sum has a file |
| DSM017 | error | `conffile-missing` | conffiles exist in the payload |
| DSM018 | warning | `conffile-location` | conffiles live under `/etc` |
| DSM019 | error | `script-executable` | maintainer scripts have an execute bit |
| DSM020 | warning | `script-shebang` | maintainer scripts start with a shebang |
| DSM021 | warning | `copyright` | `usr/share/doc/<pkg>/copyright` exists |
| DSM022 | info | `changelog` | a Debian changelog is shipped |
| DSM023 | error | `ownership` | payload is owned by `root:root` |
| DSM024 | warning | `broken-symlink` | relative links resolve inside the package |
| DSM025 | warning | `section` | section is a known Debian archive section |
| DSM026 | warning | `priority` | priority is one of the five policy values |
| DSM027 | info | `installed-size` | `Installed-Size` is present and non-zero |
| DSM028 | warning | `self-dependency` | no package depends on itself |
| DSM029 | info | `extended-description` | an extended description is present |
| DSM030 | error | `unknown-control-member` | only known control members exist |

## Fixing findings

### DSM009 / DSM010 — modes

```yaml
permissions:
  /usr/bin/app: "0755"
  /etc/app/app.conf: "0644"
```

`debsmith` normalises source modes to `0644`/`0755`. Set explicit modes for
anything else.

### DSM017 / DSM018 — conffiles

```yaml
conffiles:
  - /etc/app/app.conf
```

The file must exist in `root` or be copied with `files`. Configuration that is
generated at runtime should not be a conffile.

### DSM019 / DSM020 — scripts

```sh
#!/bin/sh
set -e
```

Scripts are embedded as `0755`; the shebang is still required for reviewers and
for shells that do not default to `/bin/sh`.

### DSM021 / DSM022 — documentation

```text
usr/share/doc/<package>/copyright
usr/share/doc/<package>/changelog.Debian.gz
```

A gzipped changelog satisfies both `lintian` and DSM022.

### DSM024 — relative symlinks

A link such as `usr/bin/app-cli -> app` is valid. A target that resolves outside
the payload (`../../etc/shadow`) is flagged; absolute targets are allowed and
skipped because they normally point at files provided by dependencies.

### DSM030 — unknown control members

Only `templates`, `triggers`, `shlibs` and `symbols` are accepted. Other members
are usually a sign of accidental metadata leakage.

## Report formats

```bash
debsmith lint pkg.deb                    # text
debsmith lint pkg.deb --json             # array of reports
debsmith lint pkg.deb --sarif            # SARIF 2.1.0 (one artifact)
debsmith lint pkg.deb --fail-on warning  # strict gate for CI
```

Exit codes: `0` pass, `1` findings at/above the threshold or a runtime error.
Text and JSON reports include per-check counts and remediation advice.

## Relationship to lintian

debsmith does not replace lintian. It is a fast, offline gate that runs before
packaging review and in CI, with stable codes and SARIF output. The verification
container still runs lintian; on the example package it reports zero errors.
