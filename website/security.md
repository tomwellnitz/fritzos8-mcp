# Sicherheit

| Stufe | Freischaltung | Verhalten |
|---|---|---|
| `read` | immer | nur lesende Tools |
| `write` | `FRITZ_ALLOW_WRITE=1` | Schreib-Tools; jedes liest zurück und meldet `verified` |
| `critical` | zusätzlich `FRITZ_ALLOW_CRITICAL=1` | nur `*_plan` → Token (5 min, an Aktion/Parameter/Ziel gebunden) → `*_execute`; Elicitation-Rückfrage, wenn der Client sie kann |
| `secrets` | `FRITZ_ALLOW_SECRETS=1` | Opt-in für den Gast-WLAN-QR-Code (Schlüssel nur im Bild) |

- **2FA:** verlangt die Box eine Zusatzbestätigung, meldet der Server `confirmation_required` – es wurde nichts geändert. `two_factor_status` erklärt den Zustand; der Server startet oder umgeht die Bestätigung nie.
- **Generischer TR-064-Caller** nur lesend, mit Denylist für Zugangsdaten liefernde und gefährliche Actions.
- **Schwärzung** jeder Ausgabe, jeder Fehlermeldung, jedes Logs; `/api/v0`-Antworten zentral.
- **Box-Schutz:** Drosselung, Kurzzeit-Cache, Schutzschalter je Box.
- **Lokale Dateien** (Messreihe, Alarme, Protokolle) mit Rechten 0700/0600.

Sicherheitslücken bitte nicht öffentlich melden – siehe `SECURITY.md` im Repository.
