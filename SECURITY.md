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
  pip-audit, gitleaks, fuzzing (ClusterFuzzLite) and OpenSSF Scorecard in CI; releases are built in GitHub Actions
  with build-provenance attestations, PyPI Trusted Publishing and container images with SBOM and provenance (see
  below).

## Verifying release artifacts

Every release artifact is built in GitHub Actions (`.github/workflows/release.yml`) and comes with a signed
[SLSA](https://slsa.dev) build provenance (Sigstore, keyless, issued for this repository's release workflow). The
provenance is stored in GitHub's attestation store and, for the files on the GitHub release, also attached as assets:

| Release asset                                   | Provenance asset                        |
|-------------------------------------------------|-----------------------------------------|
| `fritzos8_mcp-X.Y.Z.tar.gz`, `fritzos8_mcp-X.Y.Z-py3-none-any.whl` | `fritzos8-mcp-X.Y.Z.intoto.jsonl` |
| `fritzos8-mcp-X.Y.Z.mcpb` (Claude Desktop bundle) | `fritzos8-mcp-X.Y.Z.mcpb.intoto.jsonl`  |

Each `*.intoto.jsonl` file is a Sigstore bundle (JSON Lines) containing an in-toto statement with a
`https://slsa.dev/provenance/v1` predicate. Verify with the [GitHub CLI](https://cli.github.com/) (≥ 2.49):

```bash
# online (looks the attestation up on GitHub)
gh attestation verify fritzos8-mcp-X.Y.Z.mcpb --repo tomwellnitz/fritzos8-mcp

# offline against the attached provenance file, pinned to the release workflow
gh attestation verify fritzos8_mcp-X.Y.Z-py3-none-any.whl \
  --bundle fritzos8-mcp-X.Y.Z.intoto.jsonl \
  --repo tomwellnitz/fritzos8-mcp \
  --signer-workflow tomwellnitz/fritzos8-mcp/.github/workflows/release.yml

# container image (provenance and SBOM are attached to the image in GHCR)
gh attestation verify oci://ghcr.io/tomwellnitz/fritzos8-mcp:X.Y.Z --repo tomwellnitz/fritzos8-mcp
```

A successful verification proves that the file was built from this repository by the release workflow and was not
modified afterwards. Packages on PyPI additionally carry PEP 740 attestations (shown on pypi.org). Releases up to and
including 0.2.0 have no `*.intoto.jsonl` asset; use the online command for them.
