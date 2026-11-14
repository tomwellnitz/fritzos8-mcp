# Security

| Tier | Enabled by | Behaviour |
|---|---|---|
| `read` | always | read-only tools |
| `write` | `FRITZ_ALLOW_WRITE=1` | write tools; each one reads back and reports `verified` |
| `critical` | additionally `FRITZ_ALLOW_CRITICAL=1` | only `*_plan` → token (5 min, bound to action/parameters/target) → `*_execute`; elicitation prompt if the client supports it |
| `secrets` | `FRITZ_ALLOW_SECRETS=1` | opt-in for the guest Wi-Fi QR code (key only inside the image) |

- **2FA:** if the box asks for an additional confirmation, the server reports `confirmation_required` – nothing was changed. `two_factor_status` explains the state; the server never starts or bypasses the confirmation itself.
- **Generic TR-064 caller** is read-only, with a deny list for actions that return credentials or are dangerous.
- **Redaction** of every output, error message and log line; `/api/v0` answers centrally.
- **Box protection:** throttling, short-lived cache and a circuit breaker per box.
- **Local files** (measurement series, alarms, reports) with modes 0700/0600.

Please report vulnerabilities privately – see `SECURITY.md` in the repository.
