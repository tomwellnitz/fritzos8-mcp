# fritzos8-mcp

MCP-Server für AVM FRITZ!Box mit **FRITZ!OS 8**: über 150 Werkzeuge für Geräte, WLAN, Telefonie, Smart Home, Diagnose, Messreihe und Alarme – für Claude und andere MCP-Clients.

- **Standardmäßig nur lesend.** Schreiben (`FRITZ_ALLOW_WRITE=1`) und kritische Aktionen (`FRITZ_ALLOW_CRITICAL=1`) müssen ausdrücklich freigeschaltet werden; kritische Aktionen laufen nur über *Plan → Token → Execute* und – wenn der Client es kann – mit einer Ja/Nein-Rückfrage an den Menschen.
- **Nie Erfolg erfinden:** jeder Schreibvorgang wird zurückgelesen (`verified`).
- **Keine Geheimnisse:** Passwörter, WLAN-Schlüssel, PINs, Tokens und SIDs werden in jeder Ausgabe und jedem Log geschwärzt.
- **Drei Schnittstellen:** TR-064 (offiziell), AHA-HTTP und Smart-Home-REST (offiziell), `/api/v0` der Web-Oberfläche (inoffiziell, nur wo nötig).

!!! note "Unabhängiges Projekt"
    Kein Produkt von AVM/FRITZ! GmbH. FRITZ!Box und FRITZ!OS sind Marken der FRITZ! GmbH.

Weiter mit dem [Schnellstart](quickstart.md).
