"""MCP prompt texts. They guide the assistant through the matching tools; they never contain
box data themselves. Placeholders: {symptom}, {box_hint}."""

from __future__ import annotations

NETZ_DOKTOR = """\
Du hilfst bei einem Netzwerkproblem an einer FRITZ!Box. Beschriebenes Symptom: {symptom}.{box_hint}

Vorgehen:
1. Rufe network_doctor (mit dem Symptom) auf – falls nicht vorhanden: wan_status, dsl_info, \
system_log (count 200), wlan_status, mesh_overview und online_monitor einzeln. Bei Aussetzern/Abbrüchen: \
erst test_my_device, dann network_doctor mit client_measurement (dessen for_network_doctor) und \
flap_check_seconds=30; für einzelne Geräte device_connection_quality, für Kabelgeräte lan_ports.
2. Fasse die Befunde nach Schweregrad zusammen (kritisch → Warnung → Hinweis). Formuliere vorsichtig \
("deutet auf …"), die Schwellwerte sind Faustregeln.
3. Gib konkrete, ungefährliche nächste Schritte (Kabel/Standort/Kanal prüfen, Provider-Störung melden \
mit den gemessenen Werten).
4. Schlage KEINE Neustarts, Neueinwahlen oder Einstellungsänderungen vor, ohne die Folgen zu nennen; \
kritische Aktionen nur über *_plan und nur nach ausdrücklicher Zustimmung.
"""

GERAETE_AUFRAEUMEN = """\
Du räumst die Geräteliste einer FRITZ!Box auf.{box_hint}

Vorgehen:
1. Optional zuerst snapshot_create (label "vor Aufräumen"), damit sich Änderungen später mit \
snapshot_diff nachvollziehen lassen.
2. devices_cleanup_report aufrufen. Zeige Löschkandidaten und Umbenennungsvorschläge als Tabelle mit \
Begründung; erkläre, dass aktive Geräte und die Box selbst nie vorgeschlagen werden.
3. Lass den Menschen auswählen. Übernimm NUR die ausgewählten Einträge in devices_cleanup_plan und zeige \
den Plan vollständig (accepted, rejected, consequence).
4. devices_cleanup_execute erst nach ausdrücklichem "ja". Berichte je Aktion; verified=false ist kein Erfolg.
5. Geräte immer per MAC ansprechen, nie per Name oder Listenposition.
"""

SICHERHEITS_CHECK = """\
Du prüfst die Sicherheit einer FRITZ!Box.{box_hint}

Vorgehen:
1. security_check aufrufen. Nenne den Score (0–100) und erkläre ihn kurz.
2. Liste jeden Befund mit Status warn/unknown samt "remediation" (Menüpfad in der FRITZ!Box-Oberfläche).
3. Ergänze bei Bedarf list_port_forwards, vpn_status, guest_wifi_status und firmware_status.
4. Ändere nichts selbst; Einstellungen wie Fernzugriff, WPS oder DNS ändert der Mensch in der \
Web-Oberfläche (teilweise mit Zusatzbestätigung).
5. Gib niemals Schlüssel, Passwörter oder PINs aus – die Tools liefern sie auch nicht.
"""
