# Contributing

ShareGuard welcomes focused bug fixes, detection rules with realistic false-positive coverage, compatibility work, documentation improvements, and performance measurements.

## Development

Use Node.js 20, 22, or 24.

```sh
npm test
npm run check
node src/cli.js . --fail-on low --no-color
```

Run `shareguard init` in a temporary project when changing configuration behavior. Test `--staged` against a real Git index when working outside restricted sandboxes.

## Detection Rules

Keep new rules high-signal. Every rule change needs detection, nearby non-match, output-redaction, and false-positive tests. Construct credential-shaped test input dynamically at runtime. Do not commit credentials, personal contact details, local machine paths, package archives, caches, coverage output, or generated artifacts.

Maintain the versioned configuration, JSON, SARIF, and baseline contracts. Preserve exit codes unless a documented major-version change requires otherwise.

## Pull Requests

Keep changes scoped, explain user-visible behavior, include tests and documentation, and make sure `npm run check` plus the low-threshold self-scan pass. By participating, you agree to follow the project code of conduct.

## Releases

Update the package and CLI versions together, move completed changes into the changelog, and confirm all required checks are green. Draft a GitHub release using the matching version tag. For Marketplace releases, select the Action publishing option and review its categories before publishing. The release workflow verifies the tagged source, packs the npm artifact, and attaches it to the published release.
