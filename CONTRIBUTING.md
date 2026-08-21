# Contributing

ShareGuard welcomes focused bug fixes, detection rules with realistic false-positive coverage, compatibility work, documentation improvements, and performance measurements.

## Development

Use Node.js 20, 22, or 24. ShareGuard intentionally has no runtime dependencies, so do not add a dependency for a workflow that can use the Node.js standard library.

```sh
npm run check
npm test
npm run docs -- --check
npm run selfscan
```

`npm run check` syntax-checks every file under `src`, `test`, and `scripts`. `npm run docs` regenerates [docs/RULES.md](docs/RULES.md) from the rule definitions; run it whenever a rule is added, removed, or reworded, because `--check` fails the build when the document drifts. `npm run selfscan` scans this repository at the `low` threshold and must stay clean.

Run `shareguard init` in a temporary project when changing configuration behavior. Test `--staged` against a real Git index when working outside restricted sandboxes. Keep examples and diagnostics free of credentials, personal information, and machine-specific paths.

## Detection Rules

Keep new rules high-signal. Every rule change needs detection, nearby non-match, output-redaction, and false-positive tests. Register every new test file in `test/index.js`, which is what `npm test` runs. Construct credential-shaped test input dynamically at runtime. Do not commit credentials, personal contact details, local machine paths, package archives, caches, coverage output, or generated artifacts.

Maintain the versioned configuration, JSON, SARIF, and baseline contracts. Preserve exit codes unless a documented major-version change requires otherwise.

## Pull Requests

Keep changes scoped, explain user-visible behavior, include tests and documentation, and make sure `npm run check` plus the low-threshold self-scan pass. By participating, you agree to follow the project code of conduct.

## Releases

Update the package and CLI versions together, move completed changes into the changelog, and confirm all required checks are green. Draft a GitHub release using the matching version tag. For Marketplace releases, select the Action publishing option and review its categories before publishing. The release workflow verifies the tagged source, packs the npm artifact, and attaches it to the published release. Never move or force-update an existing release tag.
