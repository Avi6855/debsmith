# Contributing

Thanks for improving debsmith. The project is maintained by
**Avinash Rajendra Patil**.

## Development setup

Requirements:

- Go 1.25 or newer
- Docker (only for the end-to-end packaging check)
- `golangci-lint` (optional, for the full lint suite)

```bash
git clone https://github.com/Avi6855/debsmith.git
cd debsmith
make build
make test
```

## Before opening a pull request

```bash
make fmt vet test
make verify        # build, lint, SBOM, source package, repository, reproducibility
```

`make e2e` runs the real Debian toolchain in an Ubuntu 24.04 container and is
required for changes that touch `internal/deb`, `internal/aptrepo`,
`internal/sourcepkg` or archive layout.

## Code style

- Standard Go formatting (`gofmt`) and import grouping (stdlib, third-party,
  `github.com/Avi6855/debsmith`).
- Errors carry context: `fmt.Errorf("stage: ...: %w", err)`.
- No shell-outs in library packages. Process execution belongs in tests and
  verification scripts only.
- Every new exported symbol has a doc comment.
- Keep functions small; the linter enforces complexity and unused code.
- Table-driven tests with `t.Parallel()` where the code is pure.

## Tests

- New behavior needs a test that fails without it.
- Package coverage targets: 70% minimum, 80%+ for parsers and writers.
- Determinism tests must compare bytes, not just metadata.
- Never weaken an assertion to make a test pass. If a golden value changes,
  explain why in the commit message.

## Adding a policy check

1. Append a `check` to the registry in `internal/policy/policy.go`.
2. Use the next `DSM###` code and document it in `docs/checks.md`.
3. Add a triggering case to `TestChecksTrigger`.
4. Keep the message actionable and include the payload path when relevant.

## Commit messages

Use an imperative subject and explain the why:

```text
Add zstd control archives for newer dpkg

Ubuntu 24.04 ships dpkg 1.22, which reads control.tar.zst. Allowing it
shrinks control archives for packages with large maintainer scripts.
```

## License

By contributing you agree that your changes are licensed under the MIT license
in [`LICENSE`](LICENSE).
