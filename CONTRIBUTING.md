# Contributing

ShareGuard welcomes focused bug fixes, detection rules with realistic test cases, performance improvements, and platform compatibility work.

## Development

Requirements: Node.js 20 or newer.

```sh
npm test
node src/cli.js . --no-color
```

Keep new detection rules high-signal. Every rule should include tests for detection, redaction, and a nearby non-match. Do not commit real credentials or personal data, even in tests.

By participating, you agree to follow the project code of conduct.
