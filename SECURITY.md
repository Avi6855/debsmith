# Security policy

## Supported versions

Security fixes land on `main` and the latest tagged release.

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting on
[github.com/Avi6855/debsmith/security/advisories](https://github.com/Avi6855/debsmith/security/advisories).
Do not open a public issue for an exploitable bug.

Include:

- affected version or commit,
- a minimal reproducer (manifest and archive if possible),
- impact: path escape, signature bypass, denial of service, key disclosure,
- whether the issue is reachable through `build`, `inspect`, `lint`, `repo` or
  `source`.

You can expect an initial response within a few days.

## Threat model

debsmith handles two kinds of untrusted input:

1. **Archives** parsed by `inspect` and `lint` (`.deb` files from third
   parties).
2. **Signing keys** provided by the operator.

### Archive parsing

- Member paths are normalised and rejected when they contain `..`, start
  outside the root or include NUL bytes.
- Symlink targets are resolved relative to the package root; links that escape
  are reported by `DSM024`.
- Control archives are limited to 64 MiB and individual control members to
  16 MiB.
- Decompression is streamed for data archives; a hostile package can still
  consume CPU or disk through legitimate decompression. Run untrusted linting
  in a sandbox with resource limits.
- Maintainer scripts are never executed.

### Signing

- Private keys are read from disk and decrypted in memory.
- Passphrases are accepted from `--passphrase-file` or
  `DEBSMITH_GPG_PASSPHRASE`, never from a command-line value that would appear
  in the process list.
- Signatures use a fixed creation time (`--epoch`) for reproducibility. Use a
  monotonic epoch for production repositories if your policy requires
  timestamp freshness.
- The repository `Release` index is the trust root; clients must pin the
  public key with `signed-by=`.

### Supply chain

- debsmith has no network access and does not download sources or keys.
- Generated SBOMs include the artifact SHA-256 and declared dependencies, not
  transitive closure.
- Verify CI artifacts with `sha256sum -c checksums.txt` from the release.

## Hardening checklist

- Run `debsmith lint --fail-on warning` before publishing.
- Sign repositories with a dedicated release key, not a personal key.
- Serve repositories over HTTPS and pin the key with `signed-by=`.
- Keep `--epoch` pinned in CI (`SOURCE_DATE_EPOCH`) for reproducible artifacts.
- Review `debsmith inspect --verify` output for unexpected control members.
