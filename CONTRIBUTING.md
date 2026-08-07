# Contributing to Goci Connect

Thank you for helping improve Goci Connect.

## Before You Start

- Search existing issues and pull requests before proposing a change.
- Open an issue before substantial API changes or new provider work.
- Report security concerns privately according to `SECURITY.md`.
- Never include real OAuth credentials, tokens, authorization codes, or personal data in tests or examples.

## Development

The module requires Go 1.23 or newer. CI exercises the minimum version and the two Go releases currently supported by the Go project.

Run the local checks from the repository root:

```sh
make fmt
make vet
make test
make test-race
make lint
make vuln
```

`make check` runs formatting verification, vet, unit tests, and linting. Install `golangci-lint` and `govulncheck` to use the corresponding targets.

Workflow actions are pinned to stable major tags and kept current through Dependabot.

Keep changes focused and idiomatic. Add tests for behavior changes, preserve concurrency safety, and ensure errors and formatted output cannot reveal sensitive values. Provider tests must use local test servers and must not call real provider services.

## Pull Requests

- Add an entry under `Unreleased` in `CHANGELOG.md` for user-facing changes.
- Add GoDoc for meaningful exported APIs.
- Keep dependencies minimal and explain new dependencies in the pull request.
- Confirm the pull request template's validation steps, or explain why a check could not run.

By participating, you agree to follow `CODE_OF_CONDUCT.md`.
