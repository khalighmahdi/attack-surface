# Security Policy

## Responsible use
Attack Surface Scanner is an **authorized-only** reconnaissance and blue-team
monitoring toolkit. Only scan systems you own or have explicit written
permission to test. `--scope` enforces the authorization list; `--fast` /
`--redteam-safe` avoid noisy or active checks.

## Reporting a vulnerability
Please report security issues **privately** (GitHub Security Advisories or
direct email) rather than public issues.

## What counts as a vulnerability
- Unauthenticated command execution via dashboard/terminal endpoints
- Path traversal in report/template/DB endpoints
- Credential leakage in logs/reports (we scrub these before release)
- Unsafe auto-execution of red-team tools (we require operator consent by default)

## Hardening defaults
- Dashboard binds loopback by default (`--host 127.0.0.1`).
- Active checks are non-destructive (one attempt, no brute force).
- msfrpcd/sliver bind loopback by default in Docker.
