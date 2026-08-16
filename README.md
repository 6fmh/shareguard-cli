# ShareGuard

**Catch secrets and private data before you share a folder.**

ShareGuard is a fast, zero-dependency CLI that checks source trees, support bundles, take-home projects, dotfile archives, and release folders for information that should not leave your machine.

It reports the location without printing the sensitive value.

```text
$ shareguard ./release
HIGH     config/settings.js:12
         Hard-coded credential [generic-secret]
         const password = "[REDACTED]"

1 finding in 24 files (82 kB), 3 skipped, 0 baselined
```

## Why ShareGuard

- Finds common access tokens, private keys, credentials, connection strings, JWTs, email addresses, IP addresses, and local user paths
- Flags risky filenames such as `.env`, private keys, credential stores, and package registry configs
- Redacts matched values from terminal and JSON output
- Honors `.gitignore` plus project-specific ignore and allow rules
- Creates baselines for known findings without storing the sensitive values
- Uses useful CI exit codes and structured JSON output
- Runs on Windows, macOS, and Linux with no runtime dependencies

## Quick start

Node.js 20 or newer is required.

```sh
git clone <repository-url>
cd shareguard-cli
npm link
shareguard ../folder-to-share
```

## Usage

```text
shareguard [path] [options]

--json                    Print machine-readable JSON
--config <file>           Use a custom configuration file
--baseline <file>         Ignore known finding fingerprints
--write-baseline <file>   Save current finding fingerprints
--fail-on <severity>      Exit 1 at low, medium, high, or critical
--no-gitignore            Do not use .gitignore rules
--no-color                Disable terminal colors
--version                 Print the version
--help                    Print help
```

ShareGuard exits with `0` when no findings meet the failure threshold, `1` when they do, and `2` when the scan cannot run. The default failure threshold is `high`.

## Configuration

Add `.shareguard.json` at the root of the folder being scanned:

```json
{
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
  "largeFileSize": 10000000
}
```

Allow rules can specify `rule`, `path`, or both. Keep them narrow and reviewable.

## Baselines

A baseline lets an existing project adopt ShareGuard without hiding new findings:

```sh
shareguard . --write-baseline .shareguard-baseline.json
shareguard . --baseline .shareguard-baseline.json
```

The baseline contains short SHA-256 fingerprints, not the detected values. Commit it only after reviewing every current finding.

## GitHub Actions

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
      - uses: actions/setup-node@v4
        with:
          node-version: 22
      - run: npm install --global github:OWNER/shareguard-cli
      - run: shareguard . --fail-on high --no-color
```

Replace `OWNER` with the repository owner. Pin a release tag for stable CI once the project reaches `1.0.0`.

## Detection philosophy

ShareGuard favors understandable, local checks over uploading source code to a service. High-severity rules target credential shapes and risky files. Lower-severity privacy rules are intentionally visible but do not fail the default scan.

No scanner can prove that a folder is safe to publish. Treat results as an additional review layer, rotate anything that may have been exposed, and use provider-side secret scanning where available.

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md) before submitting a change. Security reports belong in GitHub's private vulnerability reporting flow.

## License

MIT
