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

1 finding in 24 files (82 kB), 3 skipped, 4 ignored, 0 suppressed, 0 baselined, 0 errors
```

## Contents

- [Quick start](#quick-start)
- [Choose a workflow](#choose-a-workflow)
- [Suppress a reviewed finding](#suppress-a-reviewed-finding)
- [GitHub Action and SARIF](#github-action-and-sarif)
- [What ShareGuard detects](#what-shareguard-detects)
- [Rule reference](#rule-reference)
- [Output and exit codes](#output-and-exit-codes)
- [Configuration and baselines](#configuration-and-baselines)
- [Security and limitations](#security-and-limitations)
- [FAQ and troubleshooting](#faq-and-troubleshooting)
- [Contributing and releases](#contributing-and-releases)

## Quick start

ShareGuard is currently installed from this GitHub repository; no npm registry package is required.

```sh
npm install --global github:6fmh/shareguard-cli#v0.4.0
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

With the [pre-commit](https://pre-commit.com) framework, add the hook to `.pre-commit-config.yaml` instead:

```yaml
repos:
  - repo: https://github.com/6fmh/shareguard-cli
    rev: v0.4.0
    hooks:
      - id: shareguard
```

### Review only the pull-request diff

`--since <ref>` scans the files added, copied, modified, or renamed since a Git reference, which keeps large repositories fast in pull-request jobs:

```sh
shareguard . --since origin/main --format github
```

The reference must resolve to a commit. Files that were deleted after the diff was computed are skipped, and `--since` cannot be combined with `--staged` or `--stdin`.

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
      - uses: actions/checkout@v7
      - uses: 6fmh/shareguard-cli@v0.4.0
        with:
          fail-on: high
```

Use the versioned `v0.4.0` release tag above, or pin the action to a full commit SHA in a production workflow.

## Suppress a reviewed finding

When a finding is intentional and a configuration `allow` entry is too broad, annotate the source instead. Suppression comments work in any text file, because ShareGuard reads them as plain text:

```js
const contact = "team@example.com" // shareguard-ignore-line email-address
// shareguard-ignore-next-line generic-secret
const sample = "password = \"not-a-real-value\""
```

- `shareguard-ignore-line` and the bare `shareguard-ignore` apply to the line they appear on.
- `shareguard-ignore-next-line` applies to the following line.
- `shareguard-ignore-file` applies to the whole file.

List rule identifiers after the directive to keep the rest of the rules active on that line. A directive with no identifier, or with an identifier that does not exist, suppresses every rule, so prefer naming the rule you reviewed. Suppressed findings are removed from every output format and counted in the summary as `suppressed`.

## GitHub Action and SARIF

The action wraps the same CLI and runs it in the runner; it does not send source content to a ShareGuard service. It defaults to `format: github`, so findings appear as inline annotations on the changed files without extra configuration, and it appends a Markdown report to the job summary.

| Input | Default | Purpose |
| --- | --- | --- |
| `path` | `.` | File or directory to scan |
| `staged` | `false` | Scan added and modified files in the Git index |
| `since` | | Scan only files changed since a Git reference |
| `fail-on` | `high` | Minimum severity that fails the action, or `none` |
| `format` | `github` | `text`, `json`, `sarif`, `github`, `markdown`, `csv`, or `junit` |
| `output` | | File that receives the primary formatted output |
| `config` | | Custom configuration file |
| `baseline` | | Baseline file of approved fingerprints |
| `include-rule` | | Scan only these rule identifiers |
| `exclude-rule` | | Disable these rule identifiers |
| `category` | | Scan only these categories |
| `concurrency` | | Bounded scan concurrency from 1 through 64 |
| `gitignore` | `true` | Honor `.gitignore` rules |
| `quiet` | `false` | Print findings without the summary line |
| `annotations` | `true` | Add inline annotations when the primary format is not `github` |
| `summary` | `true` | Append a Markdown report to the job summary |

Rule and category inputs accept comma-separated or newline-separated lists. Inputs containing a line break or a leading dash are rejected, so a workflow input cannot inject extra CLI options.

The `exit-code` output always reports the scan result (`0`, `1`, or `2`), and the `sarif` output is set when `format: sarif` and `output` are both supplied.

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
      - uses: actions/checkout@v7
      - id: shareguard
        continue-on-error: true
        uses: 6fmh/shareguard-cli@v0.4.0
        with:
          format: sarif
          output: shareguard.sarif
          fail-on: high
      - if: always()
        uses: github/codeql-action/upload-sarif@v4
        with:
          sarif_file: ${{ steps.shareguard.outputs.sarif }}
      - if: steps.shareguard.outcome == 'failure'
        run: exit 1
```

SARIF 2.1 locations contain paths and line numbers, rule descriptions, severities, and fingerprints. They do not contain matched secret values or source-line previews.

## What ShareGuard detects

Rules are grouped into three categories:

- `secret`: private keys; GitHub, GitLab, and AWS credentials; OpenAI, Anthropic, Google, OpenRouter, Groq, Hugging Face, Replicate, and Perplexity API keys; Google OAuth, Azure client, and Azure Storage secrets; Slack tokens, app tokens, and webhook URLs; Stripe, npm, RubyGems, Docker Hub, SendGrid, Mailgun, Mailchimp, DigitalOcean, PyPI, Discord, and Telegram credentials; Twilio account and API-key SIDs; HashiCorp Vault, Terraform Cloud, Doppler, Grafana, Cloudflare, Square, Shopify, Notion, Linear, Atlassian, Airtable, Supabase, Postman, Figma, New Relic, SonarQube, and Sentry credentials; JWTs; credentials embedded in URLs and connection strings; risky files such as `.env`, key stores, service-account keys, and Terraform state; hard-coded credential assignments; and conservative high-entropy credential-like values.
- `privacy`: email addresses, local Windows and Unix home paths, non-documentation IPv4 and IPv6 addresses, Luhn-valid payment card numbers, and US Social Security numbers.
- `hygiene`: backup and editor temporary files, operating system metadata files, and oversized artifacts.

Provider-side secret scanning remains valuable for repository history and post-push detection. ShareGuard covers the earlier boundary: arbitrary folders and staged content before it enters Git, including exports, release artifacts, support bundles, and files copied between systems. Use both layers with access controls, review, and credential rotation.

For a one-off narrower scan:

```sh
shareguard . --include-rule github-token --include-rule npm-token
shareguard . --exclude-rule email-address
shareguard . --category secret
```

Rule filters can be repeated or supplied as comma-separated values. `shareguard --list-rules` prints every identifier, and [docs/RULES.md](docs/RULES.md) explains each one.

## Rule reference

[docs/RULES.md](docs/RULES.md) documents every rule with its identifier, category, severity, and remediation guidance. It is generated from the rule definitions with `npm run docs`, and SARIF `helpUri` links point at the matching section, so a code-scanning alert links straight to the explanation.

To inspect the rules from a terminal:

```sh
shareguard --list-rules
shareguard --list-rules --json
```

## Output and exit codes

Text is the default. `--output <file>` writes the selected format to a file instead of standard output.

| Format | Use |
| --- | --- |
| `text` | Human review in a terminal, with color unless `--no-color` is set |
| `json` | Versioned machine-readable output (`--json` is an alias) |
| `sarif` | SARIF 2.1 for GitHub code scanning (`--sarif` is an alias) |
| `github` | Workflow annotations that mark the offending lines in a pull request |
| `markdown` | A report suited to a job summary, comment, or review note |
| `csv` | A spreadsheet-safe table, with formula-injection guards |
| `junit` | JUnit XML for test-report viewers in CI |

One scan can produce several reports. `--report <format>[:<file>]` is repeatable, and without a file the report is printed to standard output:

```sh
shareguard . --sarif --output shareguard.sarif --report markdown:summary.md --report github
```

Only one report may be written per destination, and only one report may go to standard output. `--quiet` drops the summary line from text and GitHub output.

| Exit code | Meaning |
| --- | --- |
| `0` | Scanning completed without read errors and no finding meets `--fail-on`. |
| `1` | At least one finding meets `--fail-on`. |
| `2` | Invalid input, configuration, baseline, Git state, or an unreadable scan target prevented a complete scan. |

The default threshold is `high`. Use `--fail-on low` for a strict privacy or release review, `--fail-on critical` for a narrower blocking policy, or `--fail-on none` to report findings without failing the command. A finding reports only its location, description, rule, severity, and fingerprint. ShareGuard never emits the matched value in text, JSON, SARIF, diagnostics, errors, or baselines.

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

Prefer a narrow `allow` entry matching the rule and path, or an inline `shareguard-ignore-line` comment naming the rule, then keep the reason in code review. Do not disable secret or entropy rules globally just to silence one finding.

### Why did the command return exit code `2`?

Exit code `2` means the scan could not complete, for example because of invalid JSON, a missing baseline, a failed Git command, or an unreadable target. The diagnostic identifies the safe path and error class without printing source content.

### Why is a large or binary file not content-scanned?

ShareGuard bounds memory and avoids known binary formats. Adjust `maxFileSize` only when the repository policy and available resources justify it; `largeFileSize` still reports oversized artifacts.

### Does ShareGuard replace GitHub secret scanning?

No. GitHub and other providers help detect secrets in repository history and after publication. ShareGuard adds local, pre-commit, and CI/CD security checks for content before it is committed or shared, including PII and risky files.

## Contributing and releases

Use Node.js 20, 22, or 24. Run `npm run check`, `npm test`, `npm run docs -- --check`, and `npm run selfscan` before opening a pull request. Detection tests must construct credential-shaped data at runtime and must assert complete redaction. See [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

The current release is [v0.4.0](https://github.com/6fmh/shareguard-cli/releases/tag/v0.4.0); changes are summarized in [CHANGELOG.md](CHANGELOG.md). ShareGuard is released under the [MIT License](LICENSE).
