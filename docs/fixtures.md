# Community-Fixtures: Box-Antworten anonymisiert beitragen

Die Tests laufen ausschließlich gegen Mocks. Je mehr echte (anonymisierte) Antworten verschiedener Modelle und FRITZ!OS-Versionen als Fixtures vorliegen, desto besser passt der Server zu allen Boxen – und desto belastbarer wird die [Kompatibilitätsmatrix](COMPATIBILITY.md).

## 1. Antwort aufnehmen

Nur **lesende** Abfragen verwenden, z. B.:

- TR-064: Ausgabe von `tr064_call` (z. B. `service="Hosts1", action="GetGenericHostEntry", arguments={"NewIndex": 0}`) als JSON speichern.
- `/api/v0`: Ausgabe der lesenden Tools (`list_landevices`, `lan_ports`, `smarthome_overview` …) – sie ist bereits zentral geschwärzt.
- XML (AHA-Geräteliste, Anrufbeantworter-/Anrufliste, Telefonbuch): Inhalt in eine Datei kopieren.
- Ereignisprotokoll: `system_log` als Text.

## 2. Anonymisieren

```bash
fritzos8-anonymize antwort.json --kind tr064 --model "FRITZ!Box 7590" --fritzos 8.20 \
  --name tr064-Hosts1-GetGenericHostEntry -o tests/fixtures/community/7590-8.20-hosts.json
```

`--kind`: `tr064` (JSON aus TR-064), `rest` (JSON aus `/api/v0`), `aha`/`xml` (XML), `text` (Protokoll). Ohne `--kind` wird JSON als `tr064` und `<…>` als XML behandelt.

Ersetzt werden – innerhalb eines Laufs konsistent, damit Bezüge erhalten bleiben:

| Was | wird zu |
|---|---|
| MAC-Adressen | `AA:BB:CC:00:00:NN` |
| IPv4 privat / öffentlich | `192.0.2.N` / `198.51.100.N` (Masken, `0.0.0.0`, Loopback bleiben) |
| IPv6 global / link-local | `2001:db8::N` / `fe80::N` |
| Geräte-, Host-, Telefon-, Weckruf-Namen, Beschreibungen | `Gerät N` |
| SSIDs, Benutzernamen, Klarnamen | `WLAN N`, `benutzerN`, `Name N` |
| Seriennummern, UDN/UUID, IMEI/IMSI/ICCID, AINs | `SERIAL000N`, `00000000-…-00000000000N`, `12345 00000NN` |
| Rufnummern (Felder und XML) | `0301234NNNN` |
| E-Mail-Adressen, MyFRITZ!-/DynDNS-Namen | `userN@example.com`, `boxN.example.net` |
| Koordinaten, Standort/Adresse | `0` / `anonymisiert` |
| Passwörter, Schlüssel, PINs, SIDs, Tokens | `***` (zentrale Schwärzung) |

Modell, FRITZ!OS-Version, Typen, Zustände und Zahlenwerte bleiben erhalten – genau die braucht der Test.

Das Werkzeug prüft das Ergebnis anschließend auf Reste (MACs außerhalb `AA:BB:CC`, IPs außerhalb der Dokumentationsbereiche, E-Mails, AINs, DynDNS-Namen, Koordinaten) und **schreibt nichts**, solange etwas verdächtig ist. Die Zuordnung echt → Platzhalter wird nirgends gespeichert.

## 3. Von Hand prüfen

Automatik ersetzt kein Hinsehen. Vor dem Einreichen die Datei lesen und auf Folgendes achten:

- Freitexte (Protokollmeldungen, Notizen, Portfreigabe-Bezeichnungen, Vorlagen-/Routinen-Namen) mit Namen, Adressen oder Orten.
- Ungewöhnliche Felder mit Kennungen (Kundennummern, Vertragsdaten, Provider-Zugangsnamen).
- Rufnummern in Feldern, deren Name nicht nach „Nummer“ klingt.

## 4. Einreichen

1. Datei unter `tests/fixtures/community/<modell>-<fritzos>-<thema>.json` ablegen.
2. `uv run pytest tests/test_anonymize.py` – der Test `test_committed_community_fixtures_are_clean` prüft jede Datei in diesem Ordner auf Reste.
3. Pull-Request mit Modell, FRITZ!OS-Version und Anschlussart (DSL/Kabel/Glasfaser/LTE) eröffnen – Vorlage „Kompatibilität/Fixture“.

Bitte keine Rohdaten in Issues posten – nur anonymisierte Fixtures.
