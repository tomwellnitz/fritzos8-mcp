# Security Policy

fritzos8-mcp controls a home router. Please treat security issues accordingly.

## Supported versions

| Version                        | Supported          |
|--------------------------------|--------------------|
| latest release (0.x)           | :white_check_mark: |
| older releases                 | :x:                |
| `main` (unreleased)            | best effort        |

Before 1.0.0 only the latest minor release receives fixes; please upgrade before reporting.

## Reporting a vulnerability

**Do not open a public issue, discussion or pull request.** Use GitHub's
[private vulnerability reporting](https://github.com/tomwellnitz/fritzos8-mcp/security/advisories/new)
("Security" tab → "Report a vulnerability"). Include:

- what you did, what happened and what you expected,
- the affected version or commit, the transport (stdio / HTTP / container) and enabled tiers
  (`FRITZ_ALLOW_WRITE`, `FRITZ_ALLOW_CRITICAL`, `FRITZ_ALLOW_SECRETS`),
- if relevant, the FRITZ!Box model and FRITZ!OS version.

Never include passwords, session IDs, Wi-Fi keys, tokens or unredacted box output – use placeholders or
`fritzos8-anonymize`.

What to expect:

- acknowledgement within 7 days, a first assessment within 14 days,
- a fix as a patch release, published together with a GitHub security advisory (and a CVE where appropriate),
- credit in the advisory if you want it. Please give us reasonable time to release a fix before disclosing publicly
  (coordinated disclosure, normally up to 90 days).

## Scope

In scope, for example:

- a secret (password, Wi-Fi key, PIN, SID, VPN key, token, notification URL) appearing in tool output, errors or logs,
- a way to perform a write or critical action without the corresponding tier (`FRITZ_ALLOW_WRITE` /
  `FRITZ_ALLOW_CRITICAL`) or without a valid plan token,
- bypassing the deny list of the generic TR-064 caller,
- the HTTP transport accepting requests without a valid bearer token,
- path traversal or unsafe permissions of local state files,
- supply-chain issues in this repository (workflows, release artifacts, container image).

Out of scope: vulnerabilities in FRITZ!OS itself (report those to FRITZ! GmbH), issues in third-party dependencies
without an exploitable path through this project (report them upstream), and anything that requires an attacker who
already has the box password or the bearer token.

## Security model

- **Read-only by default.** Writes need `FRITZ_ALLOW_WRITE=1` and are always read back (`verified`).
- **Critical actions** additionally need `FRITZ_ALLOW_CRITICAL=1` and go through plan → single-use token (bound to
  parameters, target and box, 5 minutes) → execute, plus a human confirmation via MCP elicitation where supported.
- **Secrets tier:** the only tool that touches a Wi-Fi key (guest QR code) needs `FRITZ_ALLOW_SECRETS=1` and writes the
  key only into a local file (mode 0600), never into a response.
- The box's **two-factor confirmation** is never bypassed.
- **Central redaction** (`redact.py`) of secrets in every output, error and log; every `/api/v0` response is redacted.
- **Credentials** only from the environment, files or the OS keychain – never from command-line arguments.
- **HTTP transport** only with a bearer token (≥ 32 characters, constant-time comparison), localhost bind by default.
- **Supply chain:** dependencies locked in `uv.lock`, GitHub Actions pinned to commit SHAs, Dependabot, CodeQL,
  pip-audit, gitleaks and OpenSSF Scorecard in CI; releases are built in GitHub Actions with build-provenance
  attestations, PyPI Trusted Publishing and container images with SBOM and provenance. Verify an artifact with
  `gh attestation verify <file-or-oci-ref> --repo tomwellnitz/fritzos8-mcp`.
