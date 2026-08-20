# Changelog

All notable changes to this project are documented in this file.

The latest release is [0.3.0](https://github.com/6fmh/shareguard-cli/releases/tag/v0.3.0). Release tags are used for the GitHub Action, and the release workflow attaches the matching npm package archive.

## 0.3.0

### Added

- Provider secret detection for OpenAI, Anthropic, Google OAuth client secrets, Azure client secrets, Slack app tokens and incoming webhook URLs, Discord and Telegram bot tokens, Twilio account and API-key SIDs, HashiCorp Vault, Terraform Cloud, Doppler, Grafana service-account and cloud tokens, Cloudflare, Square, Shopify, Notion, and Linear.
- Privacy detection for non-documentation IPv6 addresses.

### Fixed

- Passed the release tag and SARIF output path to workflow shells through environment variables instead of expression interpolation, removing a template-injection path.
- Replaced an uninitialized buffer allocation when decoding big-endian UTF-16 content, which could read stale heap bytes for odd-length input.
- Resolved finding line numbers with a precomputed line index, eliminating quadratic slowdown on match-dense files.

### Changed

- Broadened the Stripe rule to cover restricted keys (`rk_live`/`rk_test`) alongside secret keys.
- Tightened the JWT rule to require a `eyJ`-prefixed header and payload, reducing false positives.
- Expanded the generic hard-coded credential rule to recognize more key names (secret key, access key, passphrase, `pwd`) and unquoted values.
- Broadened the placeholder filter so common dummy and reference values (for example environment lookups and `*-here` suffixes) are not reported.
- Excluded link-local, broadcast, and multicast ranges from the IPv4 rule to reduce noise.
- Hardened the hard-coded credential rule against pathological backtracking on large inputs.
- Stopped the IPv4 rule from matching version strings such as `1.2.3.4.5`.
- Stopped the email rule from matching asset references such as `logo@2x.png`.
- Bumped the CLI and package version to `0.3.0`.

## 0.2.1

### Changed

- Improved repository onboarding, GitHub discovery metadata, workflow examples, and security documentation.
- Bumped the CLI and package version to `0.2.1`.

## 0.2.0

### Added

- SARIF 2.1 output, file output support, versioned JSON output, and documented exit codes.
- Git-index scanning with `--staged`, standard-input scanning with `--stdin`, and a safe `init` command.
- Versioned configuration validation, bounded concurrency, UTF-16 input support, diagnostics, and safer baseline refreshes.
- Rule/category selection, conservative entropy detection, and provider detection for GitLab, npm, SendGrid, DigitalOcean, and PyPI.
- A reusable GitHub Action, release workflow, issue forms, pull request template, and expanded tests.

### Changed

- Findings no longer include source-line previews, eliminating the risk of a preview exposing a second secret on the same line.
- Ignore traversal now preserves re-included paths below ignored directories.
