# Security Policy

## Supported Versions

Security fixes land on the latest release line. Report issues against the newest tag, and upgrade before reporting a problem found on an older one.

## Reporting a Vulnerability

Use GitHub private vulnerability reporting for security issues in ShareGuard. Include affected versions, a minimal reproduction that does not contain real secrets or personal data, impact, and a suggested remediation when available.

Do not open public issues for vulnerabilities that could expose credentials, scan results, repository contents, or bypasses that make those contents unsafe.

## Scope

ShareGuard reduces accidental disclosure; it does not guarantee a folder is safe to publish. It deliberately keeps scanning local, redacts matched values from all output formats, and avoids sending source content to external services. Use it with repository permissions, secret rotation, code review, and provider-side scanning.

## Hardening in this Repository

Workflows pin every action to a commit SHA, request the least privilege each job needs, and disable credential persistence on checkout. The GitHub Action rejects inputs containing a line break or a leading dash so a workflow input cannot inject extra CLI options, and the CLI invokes Git through argument arrays rather than a shell.
