# ShareGuard

ShareGuard is a zero-dependency Node.js CLI that detects secrets, personal information, risky files, and oversized artifacts before a folder is shared or published. It runs locally and reports file, line, rule, and severity without emitting matched source values.

```text
$ shareguard ./release --fail-on medium
HIGH     config/settings.js:12
         Hard-coded credential [generic-secret]

1 finding in 24 files (82 kB), 3 skipped, 4 ignored, 0 baselined, 0 errors
```

## Install

ShareGuard supports Node.js 20, 22, and 24 on Windows, macOS, and Linux.

```sh
npm install --global github:6fmh/shareguard-cli
shareguard --version
```

To run from a checkout:

```sh
git clone https://github.com/6fmh/shareguard-cli.git
cd shareguard-cli
npm test
npm link
```

## Scan

```sh
shareguard
shareguard ./release --fail-on medium
shareguard scan ./release --format json
shareguard --stdin --stdin-filename settings.env < settings.env
shareguard --staged --format sarif --output shareguard.sarif
```

`shareguard [scan] [path]` scans the current directory by default. `--staged` reads added and modified content from the Git index, not the working tree, and is intended for pre-commit hooks and CI. `--stdin` reads one content stream and uses `stdin` as its reported filename unless `--stdin-filename` is set.

ShareGuard never follows symlinks. It skips known binary formats and files above `maxFileSize`, while still reporting an oversized file when it exceeds `largeFileSize`.

## Output and Exit Codes

Text is the default output. `--format json` produces the versioned JSON schema and `--format sarif` produces SARIF 2.1 for code-scanning systems. `--json` and `--sarif` are short aliases. `--output <file>` writes the selected format without printing it to standard output.

| Exit code | Meaning |
| --- | --- |
| `0` | No finding meets `--fail-on` and scanning completed without read errors. |
| `1` | At least one finding meets `--fail-on`. |
| `2` | Invalid input, configuration, baseline, Git state, or an unreadable scan target prevented a complete scan. |

The default failure threshold is `high`. Use `--fail-on low` when validating a repository configuration or privacy-sensitive export.

## Rules

ShareGuard includes high-confidence detection for private keys and provider formats including GitHub, GitLab, AWS, Slack, Stripe, npm, SendGrid, DigitalOcean, PyPI, and Google credentials. It also detects connection-string passwords, JWTs, common hard-coded credential assignments, email addresses, local home paths, and non-documentation IPv4 addresses.

Risky filenames such as `.env`, private-key files, common credential stores, and package registry configuration are reported even when content scanning is skipped. Entropy detection is conservative: it only considers credential-related lines, requires a long mixed-character value, and ignores hexadecimal strings and obvious repetition.

Control scope in a one-off scan:

```sh
shareguard . --include-rule github-token --include-rule npm-token
shareguard . --exclude-rule email-address
shareguard . --category secret
```

Available categories are `hygiene`, `privacy`, and `secret`. Rule filters can be repeated or supplied as comma-separated values.

## Configuration

Create a versioned starter file with:

```sh
shareguard init
```

`init` refuses to overwrite an existing file unless `--force` is present. A configuration file named `.shareguard.json` is loaded from the scan root, or use `--config <file>`.

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

All configuration fields are validated. `ignore` is combined with ShareGuard's default generated/build exclusions. `allow` rules must specify a narrow `rule`, `path`, or both. `.gitignore` rules are honored by default; `--no-gitignore` disables them. The matcher supports `*`, `?`, `**`, trailing-directory patterns, root-anchored paths, ordered negation, and re-included files under ignored directories.

`concurrency` is bounded from 1 through 64. It defaults to a small CPU-aware value suitable for large repositories. Disable entropy checks only when a reviewed policy requires it:

```json
{
  "entropy": {
    "enabled": false
  }
}
```

## Baselines

Baselines make incremental adoption practical without storing secret values:

```sh
shareguard . --write-baseline .shareguard-baseline.json
shareguard . --baseline .shareguard-baseline.json
```

Baseline files have `schemaVersion: 1` and contain only short SHA-256 finding fingerprints. Writing a baseline refreshes it from every current, non-allowed finding, including findings already suppressed by the supplied baseline. Review every baseline update before committing it.

## GitHub Actions

Use the included action for normal CI:

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

For GitHub code scanning, write SARIF and upload it in a later step:

```yaml
      - id: shareguard
        uses: 6fmh/shareguard-cli@v0.2.0
        with:
          format: sarif
          output: shareguard.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: ${{ steps.shareguard.outputs.sarif }}
```

The action accepts `path`, `staged`, `fail-on`, `format`, `output`, `config`, and `baseline`. Its `sarif` output is set when both `format: sarif` and `output` are provided.

Pin a release tag or commit SHA in stable production workflows.

## Security and Privacy

Findings include a location and a fingerprint, never the matched value or source-line preview. That applies to text, JSON, SARIF, baseline files, and diagnostics. Treat any potential exposure as an incident: remove it from the shared artifact, rotate it with its provider, and review repository history where appropriate.

ShareGuard is a local review layer, not proof that a folder is safe to distribute. Use it alongside provider-side secret scanning, access controls, and code review.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), and [CHANGELOG.md](CHANGELOG.md). The project is released under the [MIT License](LICENSE).
