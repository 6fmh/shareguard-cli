# ShareGuard: Secret and Privacy Scanner for Git

[![CI](https://github.com/6fmh/shareguard-cli/actions/workflows/ci.yml/badge.svg)](https://github.com/6fmh/shareguard-cli/actions/workflows/ci.yml)
[![CodeQL](https://github.com/6fmh/shareguard-cli/actions/workflows/codeql.yml/badge.svg)](https://github.com/6fmh/shareguard-cli/actions/workflows/codeql.yml)
[![Latest release](https://img.shields.io/github/v/release/6fmh/shareguard-cli)](https://github.com/6fmh/shareguard-cli/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

ShareGuard is a zero-runtime-dependency Node.js CLI and GitHub Action for secret detection, privacy scanning, and file hygiene. It checks repositories, staged changes, release folders, support bundles, and other files before they are committed, published, or shared. Findings include a file, line, rule, and severity; matched values are never printed.

Use it for Git secret scanning, pre-commit security, CI/CD security, PII detection, credential detection, and SARIF-based GitHub code scanning. Scans run locally on Windows, macOS, and Linux with Node.js 20, 22, or 24.

```text
$ shareguard ./release --fail-on medium
HIGH     config/settings.js:12
         Hard-coded credential [generic-secret]

1 finding in 24 files (82 kB), 3 skipped, 4 ignored, 0 baselined, 0 errors
```

## Contents

- [Quick start](#quick-start)
- [Choose a workflow](#choose-a-workflow)
- [GitHub Action and SARIF](#github-action-and-sarif)
- [What ShareGuard detects](#what-shareguard-detects)
- [Output and exit codes](#output-and-exit-codes)
- [Configuration and baselines](#configuration-and-baselines)
- [Security and limitations](#security-and-limitations)
- [FAQ and troubleshooting](#faq-and-troubleshooting)
- [Contributing and releases](#contributing-and-releases)

## Quick start

ShareGuard is currently installed from this GitHub repository; no npm registry package is required.

```sh
npm install --global github:6fmh/shareguard-cli#v0.2.0
shareguard --version
shareguard . --fail-on high
```

The last command scans the current directory. A finding returns exit code `1`, so the same command can be used in a script or CI job. To install from a checkout instead:

```sh
git clone https://github.com/6fmh/shareguard-cli.git
cd shareguard-cli
npm test
npm link
shareguard . --fail-on high
```

## Choose a workflow

### Scan a folder or file

```sh
shareguard ./release --fail-on medium
shareguard ./support-bundle --format json --output shareguard.json
shareguard --stdin --stdin-filename settings.env < settings.env
```

`shareguard [scan] [path]` scans the current directory when no path is supplied. `--stdin` scans one stream and reports it as `stdin` unless `--stdin-filename` supplies a name. ShareGuard does not follow symlinks, skips known binary formats, and skips content above `maxFileSize` while still reporting files above `largeFileSize`.

### Check exactly what will be committed

`--staged` reads added and modified blobs from the Git index, not the working tree. This makes it suitable for a local pre-commit hook:

```sh
shareguard --staged --fail-on high --no-color
```

For a repository-local hook, create `.git/hooks/pre-commit` with:

```sh
#!/bin/sh
exec shareguard --staged --fail-on high --no-color
```

The hook requires the `shareguard` command to be on the hook's `PATH`. A normal CI scan should use a checked-out workspace instead of `--staged`, because a fresh checkout has no staged changes.

### Add a normal CI check

```yaml
name: ShareGuard

on: [push, pull_request]

permissions:
  contents: read

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: 6fmh/shareguard-cli@v0.2.0
        with:
          fail-on: high
```

Use the versioned `v0.2.0` release tag above, or pin the action to a full commit SHA in a production workflow.

## GitHub Action and SARIF

The action accepts `path`, `staged`, `fail-on`, `format`, `output`, `config`, and `baseline`. Its `sarif` output is set when `format: sarif` and `output` are both supplied. The action runs ShareGuard in the runner; it does not send source content to a ShareGuard service.

To publish findings to GitHub code scanning, grant `security-events: write`, keep the scan result available when findings fail the threshold, upload SARIF, then fail the job:

```yaml
name: ShareGuard code scanning

on: [push, pull_request]

permissions:
  contents: read
  security-events: write

jobs:
  shareguard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - id: shareguard
        continue-on-error: true
        uses: 6fmh/shareguard-cli@v0.2.0
        with:
          format: sarif
          output: shareguard.sarif
          fail-on: high
      - if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: ${{ steps.shareguard.outputs.sarif }}
      - if: steps.shareguard.outcome == 'failure'
        run: exit 1
```

SARIF 2.1 locations contain paths and line numbers, rule descriptions, severities, and fingerprints. They do not contain matched secret values or source-line previews.

## What ShareGuard detects

Rules are grouped into three categories:

- `secret`: private keys; GitHub, GitLab, AWS, Slack, Stripe, npm, SendGrid, DigitalOcean, PyPI, and Google credentials; JWTs; connection-string passwords; hard-coded credential assignments; and conservative high-entropy credential-like values.
- `privacy`: email addresses, local Windows and Unix home paths, and non-documentation IPv4 addresses.
- `hygiene`: risky filenames such as `.env`, private-key files, and credential stores, plus oversized files.

Provider-side secret scanning remains valuable for repository history and post-push detection. ShareGuard covers the earlier boundary: arbitrary folders and staged content before it enters Git, including exports, release artifacts, support bundles, and files copied between systems. Use both layers with access controls, review, and credential rotation.

For a one-off narrower scan:

```sh
shareguard . --include-rule github-token --include-rule npm-token
shareguard . --exclude-rule email-address
shareguard . --category secret
```

Rule filters can be repeated or supplied as comma-separated values. The CLI lists categories with `shareguard --help`.

## Output and exit codes

Text is the default. `--format json` emits the versioned JSON schema, and `--format sarif` emits SARIF 2.1. `--json` and `--sarif` are aliases. `--output <file>` writes the selected format without printing it to standard output.

| Exit code | Meaning |
| --- | --- |
| `0` | Scanning completed without read errors and no finding meets `--fail-on`. |
| `1` | At least one finding meets `--fail-on`. |
| `2` | Invalid input, configuration, baseline, Git state, or an unreadable scan target prevented a complete scan. |

The default threshold is `high`. Use `--fail-on low` for a strict privacy or release review, or `--fail-on critical` for a narrower blocking policy. A finding reports only its location, description, rule, severity, and fingerprint. ShareGuard never emits the matched value in text, JSON, SARIF, diagnostics, errors, or baselines.

## Configuration and baselines

Create a versioned starter configuration without overwriting an existing file:

```sh
shareguard init
```

Use `.shareguard.json` at the scan root or pass `--config <file>`:

```json
{
  "schemaVersion": 1,
  "ignore": [
    "fixtures/",
    "docs/generated/**"
  ],
  "allow": [
    {
      "rule": "email-address",
      "path": "docs/contact.md"
    }
  ],
  "maxFileSize": 2000000,
  "largeFileSize": 10000000,
  "concurrency": 8,
  "entropy": {
    "enabled": true,
    "minLength": 32,
    "threshold": 4.5
  }
}
```

Configuration is validated. `ignore` is added to the default generated/build exclusions, and `.gitignore` is honored unless `--no-gitignore` is used. `allow` entries should be narrow and specify a `rule`, `path`, or both. Patterns support `*`, `?`, `**`, trailing-directory paths, root anchoring, ordered negation, and re-included files below ignored directories. Concurrency is bounded from 1 through 64.

Baselines support incremental adoption without storing secret values:

```sh
shareguard . --write-baseline .shareguard-baseline.json
shareguard . --baseline .shareguard-baseline.json
```

A baseline contains only schema metadata and finding fingerprints. Writing one refreshes all current non-allowed findings, including findings already suppressed by the supplied baseline. Review every baseline change before committing it.

## Security and limitations

ShareGuard is a local review layer, not proof that a folder is safe to distribute. It is pattern-based and intentionally conservative: false positives and false negatives are possible. It does not inspect Git history, validate whether a credential is active, revoke credentials, or replace provider-side scanning. It skips known binary formats and oversized content, although risky filenames and large-file findings are still reported.

Scanning is local and source content is not uploaded to a ShareGuard service. Matched values are redacted from all supported output paths. If a possible credential has already been shared, remove it from the artifact, rotate it with its provider, and review repository history; do not rely on a clean follow-up scan as evidence that the credential is safe.

## FAQ and troubleshooting

### Why did `--staged` find nothing?

It scans only added and modified paths in the Git index. Stage the intended content with `git add`, and run a normal path scan when you want to inspect unstaged files or an exported folder.

### How do I handle a reviewed false positive?

Prefer a narrow `allow` entry matching the rule and path, then keep the reason in code review. Do not disable secret or entropy rules globally just to silence one finding.

### Why did the command return exit code `2`?

Exit code `2` means the scan could not complete, for example because of invalid JSON, a missing baseline, a failed Git command, or an unreadable target. The diagnostic identifies the safe path and error class without printing source content.

### Why is a large or binary file not content-scanned?

ShareGuard bounds memory and avoids known binary formats. Adjust `maxFileSize` only when the repository policy and available resources justify it; `largeFileSize` still reports oversized artifacts.

### Does ShareGuard replace GitHub secret scanning?

No. GitHub and other providers help detect secrets in repository history and after publication. ShareGuard adds local, pre-commit, and CI/CD security checks for content before it is committed or shared, including PII and risky files.

## Contributing and releases

Use Node.js 20, 22, or 24. Run `npm test`, `npm run check`, and `node src/cli.js . --fail-on low --no-color` before opening a pull request. Detection tests must construct credential-shaped data at runtime and must assert complete redaction. See [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

The current release is [v0.2.0](https://github.com/6fmh/shareguard-cli/releases/tag/v0.2.0); changes are summarized in [CHANGELOG.md](CHANGELOG.md). ShareGuard is released under the [MIT License](LICENSE).
