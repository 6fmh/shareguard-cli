# Changelog

All notable changes to this project are documented in this file.

The latest release is [0.2.0](https://github.com/6fmh/shareguard-cli/releases/tag/v0.2.0). Release tags are used for the GitHub Action, and the release workflow attaches the matching npm package archive.

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
