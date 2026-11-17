# Abdeckung gegen die offiziellen AVM-Schnittstellen

Stand: 2026-11-14 (nach Stufe 10; TR-064-Zahlen mit `scripts/coverage_stats.py` aus den Zeilen gezählt) · Grundlage: die AVM/FRITZ!-Schnittstellendokumente (TR-064-Service-Beschreibungen, „Internet Gateway Device Support“ v1/v2, AHA-HTTP-Interface, Smart-Home-REST-API für FRITZ!OS 8.2 und 8.5, Technical Note Session-ID). Die Dokumente selbst liegen nur lokal unter `docs/vendor/avm/` (gitignored, AVM-Urheberrecht) – neu laden über <https://fritz.com/pages/schnittstellen>. Diese Datei enthält nur Action-/Endpunktnamen und eigene Einordnungen, keine Doku-Auszüge.

Ergebnis der Prüfung von Annahmen im Code und des Denylist-Abgleichs: [PLAN „Verifikation gegen AVM-Doku“](PLAN.md#verifikation-gegen-avm-doku).

## Legende

| Zeichen | Bedeutung |
|---|---|
| ✅ | kuratiert – ein eigenes Tool nutzt die Action (Feld-Whitelist, Rücklesen bei Schreibzugriffen) |
| 🟡 | nur generisch – lesend über `tr064_call` erreichbar (Get-Action, nicht gesperrt, zentrale Schwärzung) |
| ❌ | fehlt – schreibende Action, noch nicht gebaut (generischer Caller ist nur lesend) |
| ⛔ | bewusst gesperrt bzw. bewusst nicht gebaut – Grund in der Spalte „Abdeckung“ |

„Recht (Doku)“ ist das in der AVM-Doku genannte Benutzerrecht (App = „Eingeschränkte FRITZ!Box-Einstellungen für Apps“, Phone = Sprachnachrichten/Anrufliste, NAS, Homeauto = Smart Home, Dial = Wählhilfe); „–“ = die Doku nennt keins. Service-Namen wie fritzconnection sie verwendet (ServiceId ohne Präfix); WAN-Verbindungsdienst seit Stufe 8.0 (V-7): TR-064 `WANIPConnection1` → `WANPPPConnection1` → IGD `WANIPConn1` (ein verbundener Dienst gewinnt); nur IGD-eigene Actions laufen weiter über `WANIPConn1`. Gezählt sind die in den Dokumenten beschriebenen Actions; Boxen können je Modell/Anschlussart weniger anbieten (`tr064_list_services` zeigt den Ist-Stand).

## Zusammenfassung

| Bereich | Umfang | ✅ kuratiert | 🟡 nur generisch | ❌ fehlt | ⛔ gesperrt |
|---|---|---|---|---|---|
| TR-064 gesamt (37 Services) | 375 Actions | 151 (40,3 %) | 72 (19,2 %) | 85 (22,7 %) | 67 (17,9 %) |
| TR-064 lesend (Get*) | 201 | 113 (56,2 %) | 72 (35,8 %) | 0 | 16 (8,0 %) |
| TR-064 schreibend | 174 | 38 (21,8 %) | – | 85 (48,9 %) | 51 (29,3 %) |
| AHA-HTTP-Interface | 36 Kommandos | 16 (44 %) | 9 (25 %) indirekt¹ | 11 (31 %) | 0 |
| Smart-Home-REST FRITZ!OS 8.2 | 36 Endpunkte | 21 (58 %) | – | 13 (36 %) | 2 (6 %)² |
| Smart-Home-REST FRITZ!OS 8.5 | 52 Endpunkte | 23 (44 %) | – | 20 (38 %) | 9 (17 %)² |

¹ Werte, die ohne eigenen Befehl in `smarthome_list_devices` (getdevicelistinfos) enthalten sind. ² Nicht geplant: Zigbee-Pairing-Codes setzen (8.2/8.5), schreibende Geofencing-Endpunkte (8.5, Standortdaten) und `PUT overview/globals` (8.5, einmaliger Geofence-Schalter).

**Lesart:** 91,5 % aller lesenden TR-064-Actions sind erreichbar (49,8 % mit kuratiertem Tool, 41,8 % generisch); gesperrt sind genau die Actions, die Schlüssel, Zugangsdaten, Session-IDs oder Download-Token liefern. Schreibend ist bewusst wenig gebaut – jede Schreib-Action braucht Rücklesen, Schutzregeln und meist Plan/Execute. Smart-Home-REST: lesen über `/smarthome/overview` + Einheit, steuern über Einheit/Routine/Vorlage (Stufe 8.5), Konfiguration (Urlaub/Sommer, Umbenennen, Löschen) und Anlernen seit Stufe 10.6b; Anlegen von Gruppen/Vorlagen/Routinen und Heizpläne bleiben offen.

Zusätzlich genutzt, aber nicht TR-064: IGD-Actions (UPnP, Doku „Internet Gateway Device Support“) `X_AVM_DE_GetExternalIPv6Address` (wan_status), `X_AVM_DE_GetDNSServer`/`X_AVM_DE_GetIPv6DNSServer` (get_dns_settings) `X_AVM_DE_GetIPv6Prefix`, `X_AVM_DE_GetDsliteStatus` und `WANIPv6FirewallControl:GetFirewallStatus` (system_transparency, ipv6_firewall_status), `WANIPv6FirewallControl:AddPinhole`/`UpdatePinhole`/`DeletePinhole` (ipv6_pinhole_* – critical, Stufe 10.6), `GetAddonInfos` im IGD-Dienst `WANCommonIFC1` (64-bit-Volumenzähler, online_monitor, V-6) und die IGD-Service-ID `WANIPConn1` als letzter Fallback des WAN-Dienstes (V-7). Undokumentiert: `/api/v0/generic/*` der Web-Oberfläche (landevice, eth_ports, vpn, plc, dnscfg, ipv6, wlan_light, forwardrules, ipv6firewall) – nicht Teil dieser Matrix.

### Je TR-064-Service

„lesend erreichbar“ = Anteil der Get-Actions mit ✅ oder 🟡.

| Service | Actions | ✅ | 🟡 | ❌ | ⛔ | lesend erreichbar |
|---|---|---|---|---|---|---|
| DeviceInfo1 | 5 | 3 | 1 | 1 | 0 | 100 % |
| DeviceConfig1 | 16 | 1 | 4 | 6 | 5 | 80 % |
| Hosts1 | 21 | 8 | 4 | 8 | 1 | 100 % |
| LANConfigSecurity1 | 5 | 3 | 1 | 0 | 1 | 100 % |
| LANEthernetInterfaceConfig1 | 3 | 0 | 2 | 0 | 1 | 100 % |
| LANHostConfigManagement1 | 11 | 3 | 3 | 0 | 5 | 100 % |
| Layer3Forwarding1 | 8 | 6 | 0 | 2 | 0 | 100 % |
| ManagementServer1 | 10 | 2 | 0 | 1 | 7 | 100 % |
| Time1 | 2 | 1 | 0 | 1 | 0 | 100 % |
| UserInterface1 | 9 | 4 | 1 | 1 | 3 | 100 % |
| WANCommonInterfaceConfig1 | 9 | 5 | 3 | 0 | 1 | 100 % |
| WANDSLInterfaceConfig1 | 4 | 4 | 0 | 0 | 0 | 100 % |
| WANDSLLinkConfig1 | 10 | 0 | 6 | 4 | 0 | 100 % |
| WANEthernetLinkConfig1 | 1 | 0 | 1 | 0 | 0 | 100 % |
| WANIPConnection1 | 18 | 9 | 3 | 4 | 2 | 100 % |
| WANPPPConnection1 | 24 | 10 | 4 | 5 | 5 | 92 % |
| X_AVM-DE_WANFiber1 | 3 | 3 | 0 | 0 | 0 | 100 % |
| X_AVM-DE_WANMobileConnection1 | 11 | 3 | 3 | 3 | 2 | 100 % |
| WLANConfiguration1 | 38 | 13 | 10 | 10 | 5 | 91 % |
| X_AVM-DE_AppSetup1 | 11 | 1 | 2 | 2 | 6 | 60 % |
| X_AVM-DE_Auth1 | 3 | 2 | 0 | 0 | 1 | 100 % |
| X_AVM-DE_OnTel1 | 31 | 13 | 6 | 12 | 0 | 100 % |
| X_AVM-DE_Dect1 | 5 | 3 | 1 | 0 | 1 | 100 % |
| X_AVM-DE_Filelinks1 | 7 | 2 | 0 | 3 | 2 | 50 % |
| X_AVM-DE_Homeauto1 | 5 | 4 | 1 | 0 | 0 | 100 % |
| X_AVM-DE_Homeplug1 | 4 | 3 | 0 | 0 | 1 | 100 % |
| X_AVM-DE_HostFilter1 | 10 | 9 | 1 | 0 | 0 | 100 % |
| X_AVM-DE_Media1 | 5 | 1 | 2 | 1 | 1 | 100 % |
| X_AVM-DE_MyFritz1 | 6 | 3 | 0 | 2 | 1 | 100 % |
| X_AVM-DE_RemoteAccess1 | 7 | 3 | 0 | 2 | 2 | 67 % |
| X_AVM-DE_Speedtest1 | 4 | 4 | 0 | 0 | 0 | 100 % |
| X_AVM-DE_Storage1 | 7 | 5 | 0 | 1 | 1 | 100 % |
| X_AVM-DE_TAM1 | 6 | 6 | 0 | 0 | 0 | 100 % |
| X_AVM-DE_UPnP1 | 2 | 1 | 0 | 1 | 0 | 100 % |
| X_AVM-DE_USPController1 | 8 | 4 | 0 | 3 | 1 | 100 % |
| X_VoIP1 | 44 | 8 | 13 | 11 | 12 | 72 % |
| X_AVM-DE_WebDAVClient1 | 2 | 1 | 0 | 1 | 0 | 100 % |

## TR-064 – je Service und Action

### DeviceInfo1

5 Actions · ✅ 3 · 🟡 1 · ❌ 1 · ⛔ 0

| Action | R/W | Recht (Doku) | Abdeckung | Status |
|---|---|---|---|---|
| `GetInfo` | R | – | system_info, firmware_status, boxes_overview | ✅ |
| `SetProvisioningCode` | W | – | noch nicht gebaut (Netz-/Zugangsrisiko, siehe Kandidaten) | ❌ |
| `GetDeviceLog` | R | – | system_log, network_doctor | ✅ |
| `GetSecurityPort` | R | keins | tr064_call | 🟡 |
| `X_AVM-DE_GetDeviceLogPath` | R | – | system_log | ✅ |

### DeviceConfig1

16 Actions · ✅ 1 · 🟡 4 · ❌ 6 · ⛔ 5

| Action | R/W | Recht (Doku) | Abdeckung | Status |
|---|---|---|---|---|
| `GetPersistentData` | R | – | tr064_call | 🟡 |
| `SetPersistentData` | W | – | noch nicht gebaut (Netz-/Zugangsrisiko, siehe Kandidaten) | ❌ |
| `ConfigurationStarted` | W | – | noch nicht gebaut (Netz-/Zugangsrisiko, siehe Kandidaten) | ❌ |
| `ConfigurationFinished` | W | – | noch nicht gebaut (Netz-/Zugangsrisiko, siehe Kandidaten) | ❌ |
| `FactoryReset` | W | – | Neustart/Werksreset nur über kritisches Tool | ⛔ |
| `Reboot` | W | – | reboot_plan/_execute (critical) – im generischen Caller gesperrt | ✅ |
| `X_GenerateUUID` | W | – | noch nicht gebaut (Netz-/Zugangsrisiko, siehe Kandidaten) | ❌ |
| `X_AVM-DE_GetConfigFile` | R | – | Konfig-Export/-Import (enthält alle Zugangsdaten) | ⛔ |
| `X_AVM-DE_SetConfigFile` | W | – | Konfig-Export/-Import (enthält alle Zugangsdaten) | ⛔ |
| `X_AVM-DE_CreateUrlSID` | W | App / Phone / NAS / Homeauto | liefert Session-ID | ⛔ |
| `X_AVM-DE_GetSupportDataInfo` | R | App / Dial / Phone / NAS / Homeauto | tr064_call | 🟡 |
| `X_AVM-DE_SendSupportData` | W | – | lädt Support-Daten zum Hersteller hoch | ⛔ |
| `X_AVM-DE_GetSupportDataEnable` | R | keins | tr064_call | 🟡 |
| `X_AVM-DE_SetSupportDataEnable` | W | App | noch nicht gebaut | ❌ |
| `X_AVM-DE_GetUserAgreement` | R | – | tr064_call | 🟡 |
| `X_AVM-DE_SetUserAgreement` | W | App | noch nicht gebaut | ❌ |

### Hosts1

21 Actions · ✅ 8 · 🟡 4 · ❌ 8 · ⛔ 1

| Action | R/W | Recht (Doku) | Abdeckung | Status |
|---|---|---|---|---|
| `GetHostNumberOfEntries` | R | keins | list_hosts (Fallback) | ✅ |
| `GetSpecificHostEntry` | R | keins | rename_host (Rücklesen) | ✅ |
| `GetGenericHostEntry` | R | keins | list_hosts (Fallback) | ✅ |
| `X_AVM-DE_GetInfo` | R | keins | tr064_call | 🟡 |
| `X_AVM-DE_GetChangeCounter` | R | keins | devices_change_counter, Messreihe/Alarme | ✅ |
| `X_AVM-DE_GetAutoWakeOnLANByMACAddress` | R | keins | tr064_call | 🟡 |
| `X_AVM-DE_SetAutoWakeOnLANByMACAddress` | W | keins | noch nicht gebaut | ❌ |
| `X_AVM-DE_SetHostNameByMACAddress` | W | – | rename_host | ✅ |
| `X_AVM-DE_WakeOnLANByMACAddress` | W | – | wake_on_lan | ✅ |
| `X_AVM-DE_GetSpecificHostEntryByIP` | R | App / Phone | tr064_call (Repeater-Login-Token geschwärzt) | 🟡 |
| `X_AVM-DE_HostsCheckUpdate` | W | App | noch nicht gebaut | ❌ |
| `X_AVM-DE_HostDoUpdate` | W | App | Firmware-Update | ⛔ |
| `X_AVM-DE_SetPrioritizationByIP` | W | App / Phone | noch nicht gebaut | ❌ |
| `X_AVM-DE_GetHostListPath` | R | – | list_hosts, Aufräum-Assistent, Schnappschuss, avm_device_updates (Model/UpdateAvailable) | ✅ |
| `X_AVM-DE_GetMeshListPath` | R | – | mesh_overview, device_connection_quality, network_doctor | ✅ |
| `X_AVM-DE_GetFriendlyName` | R | – | tr064_call | 🟡 |
| `X_AVM-DE_SetFriendlyName` | W | – | noch nicht gebaut | ❌ |
| `X_AVM-DE_SetFriendlyNameByIP` | W | – | noch nicht gebaut | ❌ |
| `X_AVM-DE_SetFriendlyNameByMAC` | W | – | noch nicht gebaut | ❌ |
| `X_AVM-DE_SetDeviceClassUserByIP` | W | – | noch nicht gebaut | ❌ |
| `X_AVM-DE_SetDeviceClassUserByMAC` | W | – | noch nicht gebaut | ❌ |

### LANConfigSecurity1

5 Actions · ✅ 3 · 🟡 1 · ❌ 0 · ⛔ 1

| Action | R/W | Recht (Doku) | Abdeckung | Status |
|---|---|---|---|---|
| `GetInfo` | R | keins | setup_check (Standardkennwort aktiv?) | ✅ |
| `X_AVM-DE_GetAnonymousLogin` | R | keins | setup_check | ✅ |
| `X_AVM-DE_GetCurrentUser` | R | App / Dial / Phone / NAS / Homeauto | setup_check (Rechte des MCP-Benutzers, K-13) | ✅ |
| `SetConfigPassword` | W | App / Dial / Phone / NAS / Homeauto | Schlüssel, Zugangsdaten bzw. Konto-Daten | ⛔ |
| `X_AVM-DE_GetUserList` | R | – | tr064_call | 🟡 |

### LANEthernetInterfaceConfig1

3 Actions · ✅ 0 · 🟡 2 · ❌ 0 · ⛔ 1

| Action | R/W | Recht (Doku) | Abdeckung | Status |
|---|---|---|---|---|
| `SetEnable` | W | – | Aussperr-/Ausfallrisiko | ⛔ |
| `GetInfo` | R | – | tr064_call | 🟡 |
| `GetStatistics` | R | – | tr064_call | 🟡 |

### LANHostConfigManagement1

11 Actions · ✅ 3 · 🟡 3 · ❌ 0 · ⛔ 5

| Action | R/W | Recht (Doku) | Abdeckung | Status |
|---|---|---|---|---|
| `GetInfo` | R | – | get_lan_dns (Fallback) | ✅ |
| `SetDHCPServerEnable` | W | – | Aussperr-/Ausfallrisiko | ⛔ |
| `SetSubnetMask` | W | – | Aussperr-/Ausfallrisiko | ⛔ |
| `GetSubnetMask` | R | – | tr064_call | 🟡 |
| `SetIPRouter` | W | – | Aussperr-/Ausfallrisiko | ⛔ |
| `GetIPRoutersList` | R | – | Schutzregeln (Box-IP) | ✅ |
| `SetIPInterface` | W | – | Aussperr-/Ausfallrisiko | ⛔ |
| `GetAddressRange` | R | – | tr064_call | 🟡 |
| `SetAddressRange` | W | – | Aussperr-/Ausfallrisiko | ⛔ |
| `GetIPInterfaceNumberOfEntries` | R | – | tr064_call | 🟡 |
| `GetDNSServer` | R | – | get_lan_dns, get_dns_settings, network_doctor | ✅ |

### Layer3Forwarding1

8 Actions · ✅ 6 · 🟡 0 · ❌ 2 · ⛔ 0

| Action | R/W | Recht (Doku) | Abdeckung | Status |
|---|---|---|---|---|
| `SetDefaultConnectionService` | W | – | noch nicht gebaut (Netz-/Zugangsrisiko, siehe Kandidaten) | ❌ |
| `GetDefaultConnectionService` | R | – | static_route_add_execute (Interface der Default-Verbindung) | ✅ |
| `GetForwardNumberOfEntries` | R | – | system_transparency (statische Routen) | ✅ |
| `AddForwardingEntry` | W | – | static_route_add_plan/_execute (critical, Stufe 10.6) | ✅ |
| `DeleteForwardingEntry` | W | – | static_route_delete_plan/_execute (critical, Stufe 10.6) | ✅ |
| `GetSpecificForwardingEntry` | R | – | static_route_* (Rücklesen) | ✅ |
| `GetGenericForwardingEntry` | R | – | system_transparency (statische Routen) | ✅ |
| `SetForwardingEntryEnable` | W | – | noch nicht gebaut (Netz-/Zugangsrisiko, siehe Kandidaten) | ❌ |

### ManagementServer1

10 Actions · ✅ 2 · 🟡 0 · ❌ 1 · ⛔ 7

| Action | R/W | Recht (Doku) | Abdeckung | Status |
|---|---|---|---|---|
| `GetInfo` | R | – | system_transparency, security_check (Feld-Whitelist: ACS-Host, Inform, Upgrades); tr064_call geschwärzt | ✅ |
| `SetManagementServerURL` | W | – | Aussperr-/Ausfallrisiko | ⛔ |
| `SetManagementServerUsername` | W | – | verlangt bzw. setzt Passwörter/Kontodaten – bewusst nicht gebaut | ⛔ |
| `SetManagementServerPassword` | W | – | Schlüssel, Zugangsdaten bzw. Konto-Daten | ⛔ |
| `SetPeriodicInform` | W | – | noch nicht gebaut (Netz-/Zugangsrisiko, siehe Kandidaten) | ❌ |
| `SetConnectionRequestAuthentication` | W | – | verlangt bzw. setzt Passwörter/Kontodaten – bewusst nicht gebaut | ⛔ |
| `SetUpgradeManagement` | W | – | Aussperr-/Ausfallrisiko | ⛔ |
| `X_SetTR069Enable` | W | – | Aussperr-/Ausfallrisiko | ⛔ |
| `X_AVM_DE_GetTR069FirmwareDownloadEnabled` | R | – | system_transparency | ✅ |
| `X_AVM_DE_SetTR069FirmwareDownloadEnabled` | W | – | Aussperr-/Ausfallrisiko | ⛔ |

### Time1

2 Actions · ✅ 1 · 🟡 0 · ❌ 1 · ⛔ 0

| Action | R/W | Recht (Doku) | Abdeckung | Status |
|---|---|---|---|---|
| `GetInfo` | R | App / Dial / Phone / NAS / Homeauto | system_transparency, network_doctor (Uhr-Abweichung) | ✅ |
| `SetNTPServers` | W | – | noch nicht gebaut (Netz-/Zugangsrisiko, siehe Kandidaten) | ❌ |

### UserInterface1

9 Actions · ✅ 4 · 🟡 1 · ❌ 1 · ⛔ 3

| Action | R/W | Recht (Doku) | Abdeckung | Status |
|---|---|---|---|---|
| `GetInfo` | R | keins | firmware_status | ✅ |
| `X_AVM-DE_CheckUpdate` | W | – | firmware_update_plan (critical, `check=true`) | ✅ |
| `X_AVM-DE_DoPrepareCGI` | W | – | liefert Session-ID für Konfig-Import/Firmware-Upload | ⛔ |
| `X_AVM-DE_DoUpdate` | W | Einstellungen bzw. keins (je Konfiguration) | firmware_update_plan/_execute (critical, Stufe 10.6) – im generischen Caller gesperrt | ✅ |
| `X_AVM-DE_DoManualUpdate` | W | – | Firmware-Update | ⛔ |
| `X_AVM-DE_GetInternationalConfig` | R | – | tr064_call | 🟡 |
| `X_AVM-DE_SetInternationalConfig` | W | – | Aussperr-/Ausfallrisiko | ⛔ |
| `X_AVM-DE_GetInfo` | R | keins | firmware_status, security_check | ✅ |
| `X_AVM-DE_SetConfig` | W | – | noch nicht gebaut (Netz-/Zugangsrisiko, siehe Kandidaten) | ❌ |

### WANCommonInterfaceConfig1

9 Actions · ✅ 5 · 🟡 3 · ❌ 0 · ⛔ 1

| Action | R/W | Recht (Doku) | Abdeckung | Status |
|---|---|---|---|---|
| `GetCommonLinkProperties` | R | – | wan_status, dsl_info, online_monitor (Sync-Rate, wenn `X_AVM-DE_GetAddonInfos` fehlt) | ✅ |
| `GetTotalBytesSent` | R | – | online_monitor | ✅ |
| `GetTotalBytesReceived` | R | – | online_monitor | ✅ |
| `GetTotalPacketsSent` | R | – | tr064_call | 🟡 |
| `GetTotalPacketsReceived` | R | – | tr064_call | 🟡 |
| `X_AVM-DE_SetWANAccessType` | W | – | Aussperr-/Ausfallrisiko | ⛔ |
| `X_AVM-DE_GetActiveProvider` | R | – | tr064_call | 🟡 |
| `X_AVM-DE_GetAddonInfos` | R | App, Phone | online_monitor (`rates`: Sync/Brutto/Tarif/L2/Manuell; erst seit Doku v22 – fehlt live an der 7583/8.26; 64-bit-Zähler über IGD `WANCommonIFC1`, V-6) | ✅ |
| `X_AVM-DE_GetOnlineMonitor` | R | – | online_monitor | ✅ |

### WANDSLInterfaceConfig1

4 Actions · ✅ 4 · 🟡 0 · ❌ 0 · ⛔ 0

| Action | R/W | Recht (Doku) | Abdeckung | Status |
|---|---|---|---|---|
| `GetInfo` | R | – | dsl_info, network_doctor | ✅ |
| `GetStatisticsTotal` | R | – | dsl_info | ✅ |
| `X_AVM-DE_GetDSLDiagnoseInfo` | R | keins | line_diagnostics (Kabeltest) | ✅ |
| `X_AVM-DE_GetDSLInfo` | R | keins | line_diagnostics (Profil, SNR-Spektrum), online_monitor (Modulation zum Abgleich der Sync-Gruppe) | ✅ |

### WANDSLLinkConfig1

10 Actions · ✅ 0 · 🟡 6 · ❌ 4 · ⛔ 0

| Action | R/W | Recht (Doku) | Abdeckung | Status |
|---|---|---|---|---|
| `GetInfo` | R | – | tr064_call | 🟡 |
| `SetEnable` | W | – | noch nicht gebaut (Netz-/Zugangsrisiko, siehe Kandidaten) | ❌ |
| `SetDSLLinkType` | W | – | noch nicht gebaut (Netz-/Zugangsrisiko, siehe Kandidaten) | ❌ |
| `GetDSLLinkInfo` | R | – | tr064_call | 🟡 |
| `SetDestinationAddress` | W | – | noch nicht gebaut (Netz-/Zugangsrisiko, siehe Kandidaten) | ❌ |
| `GetDestinationAddress` | R | – | tr064_call | 🟡 |
| `SetATMEncapsulation` | W | – | noch nicht gebaut (Netz-/Zugangsrisiko, siehe Kandidaten) | ❌ |
| `GetATMEncapsulation` | R | – | tr064_call | 🟡 |
| `GetAutoConfig` | R | – | tr064_call | 🟡 |
| `GetStatistics` | R | – | tr064_call | 🟡 |

### WANEthernetLinkConfig1

1 Actions · ✅ 0 · 🟡 1 · ❌ 0 · ⛔ 0

| Action | R/W | Recht (Doku) | Abdeckung | Status |
|---|---|---|---|---|
| `GetEthernetLinkStatus` | R | – | tr064_call | 🟡 |

### WANIPConnection1

18 Actions · ✅ 9 · 🟡 3 · ❌ 4 · ⛔ 2

| Action | R/W | Recht (Doku) | Abdeckung | Status |
|---|---|---|---|---|
| `GetInfo` | R | – | tr064_call | 🟡 |
| `GetConnectionTypeInfo` | R | – | tr064_call | 🟡 |
| `SetConnectionType` | W | – | Aussperr-/Ausfallrisiko | ⛔ |
| `GetStatusInfo` | R | – | wan_status (TR-064 zuerst, IGD `WANIPConn1` als Fallback) | ✅ |
| `GetNATRSIPStatus` | R | – | tr064_call | 🟡 |
| `SetConnectionTrigger` | W | – | noch nicht gebaut (Netz-/Zugangsrisiko, siehe Kandidaten) | ❌ |
| `ForceTermination` | W | – | reconnect_wan_plan/_execute (critical) (TR-064 zuerst, IGD `WANIPConn1` als Fallback) – im generischen Caller gesperrt | ✅ |
| `RequestConnection` | W | – | Verbindungsabbau nur über kritisches Tool | ⛔ |
| `X_GetDNSServers` | R | – | get_dns_settings (TR-064 zuerst, IGD `WANIPConn1` als Fallback) | ✅ |
| `X_SetDNSServers` | W | – | noch nicht gebaut (Netz-/Zugangsrisiko, siehe Kandidaten) | ❌ |
| `GetPortMappingNumberOfEntries` | R | – | list_port_forwards, security_check (TR-064 zuerst, IGD `WANIPConn1` als Fallback) | ✅ |
| `GetGenericPortMappingEntry` | R | – | list_port_forwards, security_check (TR-064 zuerst, IGD `WANIPConn1` als Fallback) | ✅ |
| `GetSpecificPortMappingEntry` | R | – | add/delete_port_forward_* (TR-064 zuerst, IGD `WANIPConn1` als Fallback) | ✅ |
| `AddPortMapping` | W | – | add_port_forward_plan/_execute (critical) (TR-064 zuerst, IGD `WANIPConn1` als Fallback) | ✅ |
| `DeletePortMapping` | W | – | delete_port_forward_plan/_execute (critical) (TR-064 zuerst, IGD `WANIPConn1` als Fallback) | ✅ |
| `GetExternalIPAddress` | R | – | wan_status (TR-064 zuerst, IGD `WANIPConn1` als Fallback) | ✅ |
| `SetRouteProtocolRx` | W | – | noch nicht gebaut (Netz-/Zugangsrisiko, siehe Kandidaten) | ❌ |
| `SetIdleDisconnectTime` | W | – | noch nicht gebaut (Netz-/Zugangsrisiko, siehe Kandidaten) | ❌ |

### WANPPPConnection1

24 Actions · ✅ 10 · 🟡 4 · ❌ 5 · ⛔ 5

| Action | R/W | Recht (Doku) | Abdeckung | Status |
|---|---|---|---|---|
| `GetInfo` | R | – | tr064_call (geschwärzt: UserName) | 🟡 |
| `GetConnectionTypeInfo` | R | – | tr064_call | 🟡 |
| `SetConnectionType` | W | – | Aussperr-/Ausfallrisiko | ⛔ |
| `GetStatusInfo` | R | – | wan_status | ✅ |
| `GetLinkLayerMaxBitRates` | R | – | tr064_call | 🟡 |
| `GetUserName` | R | – | PPP-Zugangsname | ⛔ |
| `SetUserName` | W | – | verlangt bzw. setzt Passwörter/Kontodaten – bewusst nicht gebaut | ⛔ |
| `SetPassword` | W | – | Schlüssel, Zugangsdaten bzw. Konto-Daten | ⛔ |
| `GetNATRSIPStatus` | R | – | tr064_call | 🟡 |
| `SetConnectionTrigger` | W | – | noch nicht gebaut (Netz-/Zugangsrisiko, siehe Kandidaten) | ❌ |
| `ForceTermination` | W | – | reconnect_wan_plan/_execute (critical) – im generischen Caller gesperrt | ✅ |
| `RequestConnection` | W | – | Verbindungsabbau nur über kritisches Tool | ⛔ |
| `X_GetDNSServers` | R | – | get_dns_settings | ✅ |
| `X_SetDNSServers` | W | – | noch nicht gebaut (Netz-/Zugangsrisiko, siehe Kandidaten) | ❌ |
| `GetPortMappingNumberOfEntries` | R | – | list_port_forwards, security_check | ✅ |
| `GetGenericPortMappingEntry` | R | – | list_port_forwards, security_check | ✅ |
| `GetSpecificPortMappingEntry` | R | – | add/delete_port_forward_* | ✅ |
| `AddPortMapping` | W | – | add_port_forward_plan/_execute (critical) | ✅ |
| `DeletePortMapping` | W | – | delete_port_forward_plan/_execute (critical) | ✅ |
| `GetExternalIPAddress` | R | – | wan_status | ✅ |
| `SetRouteProtocolRx` | W | – | noch nicht gebaut (Netz-/Zugangsrisiko, siehe Kandidaten) | ❌ |
| `SetIdleDisconnectTime` | W | – | noch nicht gebaut (Netz-/Zugangsrisiko, siehe Kandidaten) | ❌ |
| `X_AVM_DE_GetAutoDisconnectTimeSpan` | R | – | system_transparency (Zwangstrennung; nur am aktiven PPP-Dienst, live 8.26: nicht vorhanden; Fallback-Schreibweise `X_AVM-DE_GetAutoDisconnectTimeSpan`) | ✅ |
| `X_AVM_DE_SetAutoDisconnectTimeSpan` | W | – | noch nicht gebaut (Netz-/Zugangsrisiko, siehe Kandidaten) | ❌ |

### X_AVM-DE_WANFiber1

3 Actions · ✅ 3 · 🟡 0 · ❌ 0 · ⛔ 0

| Action | R/W | Recht (Doku) | Abdeckung | Status |
|---|---|---|---|---|
| `GetInfo` | R | App | line_diagnostics (Pegel, Schwellen; ohne Seriennummer) | ✅ |
| `GetInfoGPON` | R | App | line_diagnostics (ohne GPON-Seriennummer) | ✅ |
| `GetStatistics` | R | App | line_diagnostics, Messreihe | ✅ |

### X_AVM-DE_WANMobileConnection1

11 Actions · ✅ 3 · 🟡 3 · ❌ 3 · ⛔ 2

| Action | R/W | Recht (Doku) | Abdeckung | Status |
|---|---|---|---|---|
| `GetInfo` | R | App | line_diagnostics (SIM-Status) | ✅ |
| `GetInfoEx` | R | App | line_diagnostics (Feld-Whitelist, ohne IMSI/PPP-Benutzer/Zellstandort); tr064_call geschwärzt | ✅ |
| `SetPIN` | W | App | SIM-Sperre möglich | ⛔ |
| `SetPUK` | W | App | SIM-Sperre möglich | ⛔ |
| `SetAccessTechnology` | W | App | noch nicht gebaut (Netz-/Zugangsrisiko, siehe Kandidaten) | ❌ |
| `GetAccessTechnology` | R | App | tr064_call | 🟡 |
| `SetPreferredAccessTechnology` | W | App | noch nicht gebaut (Netz-/Zugangsrisiko, siehe Kandidaten) | ❌ |
| `GetPreferredAccessTechnology` | R | App | tr064_call | 🟡 |
| `SetEnabledBandCapabilities` | W | App | noch nicht gebaut (Netz-/Zugangsrisiko, siehe Kandidaten) | ❌ |
| `GetEnabledBandCapabilities` | R | App | line_diagnostics | ✅ |
| `GetBandCapabilities` | R | App | tr064_call | 🟡 |

### WLANConfiguration1

38 Actions · ✅ 13 · 🟡 10 · ❌ 10 · ⛔ 5

| Action | R/W | Recht (Doku) | Abdeckung | Status |
|---|---|---|---|---|
| `SetEnable` | W | App | set_guest_wifi, set_wlan_enabled_* (critical) | ✅ |
| `GetInfo` | R | App / Phone | wlan_status, guest_wifi_status, wlan_settings | ✅ |
| `SetConfig` | W | – | noch nicht gebaut (Netz-/Zugangsrisiko, siehe Kandidaten) | ❌ |
| `SetSecurityKeys` | W | App | verlangt bzw. setzt Passwörter/Kontodaten – bewusst nicht gebaut | ⛔ |
| `GetSecurityKeys` | R | App | liefert WLAN-Schlüssel – im generischen Caller gesperrt; nur guest_wifi_qr (Opt-in `FRITZ_ALLOW_SECRETS`, Schlüssel nur im QR-Bild) | ⛔ |
| `SetDefaultWEPKeyIndex` | W | – | noch nicht gebaut (Netz-/Zugangsrisiko, siehe Kandidaten) | ❌ |
| `GetDefaultWEPKeyIndex` | R | – | tr064_call | 🟡 |
| `SetBasBeaconSecurityProperties` | W | – | noch nicht gebaut (Netz-/Zugangsrisiko, siehe Kandidaten) | ❌ |
| `GetBasBeaconSecurityProperties` | R | – | tr064_call | 🟡 |
| `GetBSSID` | R | – | tr064_call | 🟡 |
| `GetSSID` | R | App | tr064_call | 🟡 |
| `SetSSID` | W | – | noch nicht gebaut (Netz-/Zugangsrisiko, siehe Kandidaten) | ❌ |
| `GetBeaconType` | R | App | tr064_call | 🟡 |
| `SetBeaconType` | W | – | noch nicht gebaut (Netz-/Zugangsrisiko, siehe Kandidaten) | ❌ |
| `GetChannelInfo` | R | – | wlan_settings | ✅ |
| `SetChannel` | W | – | set_wlan_channel | ✅ |
| `GetBeaconAdvertisement` | R | – | tr064_call | 🟡 |
| `SetBeaconAdvertisement` | W | – | noch nicht gebaut (Netz-/Zugangsrisiko, siehe Kandidaten) | ❌ |
| `GetTotalAssociations` | R | App / Phone | wlan_status | ✅ |
| `GetGenericAssociatedDeviceInfo` | R | App / Phone | mesh_overview, device_connection_quality, network_doctor (Signal-% je WLAN-Gerät, Fallback, max. 64 je Dienst) | ✅ |
| `GetSpecificAssociatedDeviceInfo` | R | App / Phone | device_connection_quality | ✅ |
| `X_AVM-DE_GetSpecificAssociatedDeviceInfoByIp` | R | App / Phone | tr064_call | 🟡 |
| `X_AVM-DE_GetWLANDeviceListPath` | R | App / Phone | mesh_overview, device_connection_quality, network_doctor (Signal-% aller WLAN-Geräte, eine Abfrage, Feld-Whitelist); im generischen Caller weiter gesperrt (Pfad trägt eine Session-ID) | ✅ |
| `X_AVM-DE_SetStickSurfEnable` | W | – | noch nicht gebaut (Netz-/Zugangsrisiko, siehe Kandidaten) | ❌ |
| `X_AVM-DE_GetIPTVOptimized` | R | – | tr064_call | 🟡 |
| `X_AVM-DE_SetIPTVOptimized` | W | – | noch nicht gebaut | ❌ |
| `GetStatistics` | R | – | tr064_call | 🟡 |
| `GetPacketStatistics` | R | – | tr064_call | 🟡 |
| `X_AVM-DE_GetNightControl` | R | keins | wlan_settings | ✅ |
| `X_SetHighFrequencyBand` | W | – | noch nicht gebaut (Netz-/Zugangsrisiko, siehe Kandidaten) | ❌ |
| `X_AVM-DE_GetWLANHybridMode` | R | – | liefert WLAN-Schlüssel | ⛔ |
| `X_AVM-DE_SetWLANHybridMode` | W | – | noch nicht gebaut (Netz-/Zugangsrisiko, siehe Kandidaten) | ❌ |
| `X_AVM-DE_GetWLANExtInfo` | R | App | wlan_status, guest_wifi_status, guest_wifi_session (Box-Zeitbegrenzung, nur lesbar), security_check | ✅ |
| `X_AVM-DE_SetWLANGlobalEnable` | W | App | Aussperr-/Ausfallrisiko | ⛔ |
| `X_AVM-DE_GetWPSInfo` | R | App | security_check, wps_button (Rücklesen) | ✅ |
| `X_AVM-DE_SetWPSConfig` | W | App | wps_button (pbc/stop, write mit Warnung) | ✅ |
| `X_AVM-DE_SetWPSEnable` | W | App | WPS dauerhaft einschalten senkt die Sicherheit – bewusst nicht gebaut | ⛔ |
| `X_AVM-DE_GetWLANConnectionInfo` | R | – | test_my_device | ✅ |

### X_AVM-DE_AppSetup1

11 Actions · ✅ 1 · 🟡 2 · ❌ 2 · ⛔ 6

| Action | R/W | Recht (Doku) | Abdeckung | Status |
|---|---|---|---|---|
| `GetAppMessageFilter` | R | – | tr064_call | 🟡 |
| `GetAppRemoteInfo` | R | – | Schlüssel, Zugangsdaten bzw. Konto-Daten | ⛔ |
| `GetConfig` | R | jedes | myfritz_status, setup_check (Rechte-Fallback) | ✅ |
| `GetInfo` | R | – | tr064_call | 🟡 |
| `RegisterApp` | W | – | verlangt bzw. setzt Passwörter/Kontodaten – bewusst nicht gebaut | ⛔ |
| `ResetEvent` | W | – | noch nicht gebaut | ❌ |
| `SetAppMessageFilter` | W | – | noch nicht gebaut | ❌ |
| `SetAppMessageReceiver` | W | – | verlangt bzw. setzt Passwörter/Kontodaten – bewusst nicht gebaut | ⛔ |
| `SetAppVPN` | W | – | Schlüssel, Zugangsdaten bzw. Konto-Daten | ⛔ |
| `SetAppVPNwithPFS` | W | – | Schlüssel, Zugangsdaten bzw. Konto-Daten | ⛔ |
| `GetBoxSenderId` | R | – | Schlüssel, Zugangsdaten bzw. Konto-Daten | ⛔ |

### X_AVM-DE_Auth1

3 Actions · ✅ 2 · 🟡 0 · ❌ 0 · ⛔ 1

| Action | R/W | Recht (Doku) | Abdeckung | Status |
|---|---|---|---|---|
| `GetInfo` | R | jedes | two_factor_status | ✅ |
| `GetState` | R | jedes | two_factor_status | ✅ |
| `SetConfig` | W | jedes | bewusst nicht gebaut: startet/stoppt eine Zusatzbestätigung; Abschluss bräuchte das Token im SOAP-Header – der Server begleitet nur (K-14) | ⛔ |

### X_AVM-DE_OnTel1

31 Actions · ✅ 13 · 🟡 6 · ❌ 12 · ⛔ 0

| Action | R/W | Recht (Doku) | Abdeckung | Status |
|---|---|---|---|---|
| `GetInfo` | R | Phone | tr064_call (geschwärzt: Username) | 🟡 |
| `SetEnable` | W | Phone | noch nicht gebaut (Netz-/Zugangsrisiko, siehe Kandidaten) | ❌ |
| `SetConfig` | W | Phone | noch nicht gebaut (Netz-/Zugangsrisiko, siehe Kandidaten) | ❌ |
| `GetInfoByIndex` | R | Phone | tr064_call (geschwärzt: Username) | 🟡 |
| `SetEnableByIndex` | W | – | noch nicht gebaut | ❌ |
| `SetConfigByIndex` | W | Phone | noch nicht gebaut | ❌ |
| `GetNumberOfEntries` | R | Phone | tr064_call | 🟡 |
| `DeleteByIndex` | W | Phone | noch nicht gebaut | ❌ |
| `GetCallList` | R | – | call_list (optional Namen aus Telefonbüchern) | ✅ |
| `GetPhonebookList` | R | Phone | phonebook_list, phonebook_search | ✅ |
| `GetPhonebook` | R | Phone | phonebook_list, phonebook_search, call_list(resolve_names) | ✅ |
| `AddPhonebook` | W | Phone | noch nicht gebaut | ❌ |
| `DeletePhonebook` | W | Phone | noch nicht gebaut | ❌ |
| `GetPhonebookEntry` | R | Phone | tr064_call | 🟡 |
| `GetPhonebookEntryUID` | R | Phone | tr064_call | 🟡 |
| `SetPhonebookEntry` | W | – | noch nicht gebaut | ❌ |
| `SetPhonebookEntryUID` | W | – | noch nicht gebaut | ❌ |
| `DeletePhonebookEntry` | W | Phone | noch nicht gebaut | ❌ |
| `DeletePhonebookEntryUID` | W | Phone | noch nicht gebaut | ❌ |
| `GetCallBarringEntry` | R | Phone | tr064_call | 🟡 |
| `GetCallBarringEntryByNum` | R | Phone | call_barring_add/_remove (Rücklesen) | ✅ |
| `GetCallBarringList` | R | Phone | call_barring_list | ✅ |
| `SetCallBarringEntry` | W | Phone | call_barring_add | ✅ |
| `DeleteCallBarringEntryUID` | W | Phone | call_barring_remove | ✅ |
| `GetDECTHandsetList` | R | Phone | dect_handsets | ✅ |
| `GetDECTHandsetInfo` | R | Phone | dect_handsets | ✅ |
| `SetDECTHandsetPhonebook` | W | Phone | noch nicht gebaut | ❌ |
| `GetNumberOfDeflections` | R | Phone | call_deflections (Fallback) | ✅ |
| `GetDeflection` | R | Phone | call_deflections (Fallback) | ✅ |
| `GetDeflections` | R | Phone | call_deflections | ✅ |
| `SetDeflectionEnable` | W | Phone | set_call_deflection (Warnung Kosten/Erreichbarkeit) | ✅ |

### X_AVM-DE_Dect1

5 Actions · ✅ 3 · 🟡 1 · ❌ 0 · ⛔ 1

| Action | R/W | Recht (Doku) | Abdeckung | Status |
|---|---|---|---|---|
| `GetNumberOfDectEntries` | R | App / Phone / Homeauto | avm_device_updates, dect_handsets | ✅ |
| `GetGenericDectEntry` | R | App / Phone / Homeauto | avm_device_updates, dect_handsets | ✅ |
| `GetSpecificDectEntry` | R | App / Phone / Homeauto | avm_device_detail (Stufe 10.7) | ✅ |
| `DectDoUpdate` | W | – | Firmware-Update | ⛔ |
| `GetDectListPath` | R | – | tr064_call (Pfad, SID geschwärzt) | 🟡 |

### X_AVM-DE_Filelinks1

7 Actions · ✅ 2 · 🟡 0 · ❌ 3 · ⛔ 2

| Action | R/W | Recht (Doku) | Abdeckung | Status |
|---|---|---|---|---|
| `GetNumberOfFilelinkEntries` | R | – | nas_status | ✅ |
| `GetGenericFilelinkEntry` | R | – | nas_status (ohne Token) – im generischen Caller gesperrt | ✅ |
| `GetSpecificFilelinkEntry` | R | – | Download-Token geteilter Links | ⛔ |
| `NewFilelinkEntry` | W | – | noch nicht gebaut | ❌ |
| `SetFilelinkEntry` | W | – | noch nicht gebaut | ❌ |
| `DeleteFilelinkEntry` | W | – | noch nicht gebaut | ❌ |
| `GetFilelinkListPath` | R | – | Download-Token geteilter Links | ⛔ |

### X_AVM-DE_Homeauto1

5 Actions · ✅ 4 · 🟡 1 · ❌ 0 · ⛔ 0

| Action | R/W | Recht (Doku) | Abdeckung | Status |
|---|---|---|---|---|
| `GetInfo` | R | – | tr064_call | 🟡 |
| `GetGenericDeviceInfos` | R | Homeauto | smarthome_tr064_devices (K-28) | ✅ |
| `GetSpecificDeviceInfos` | R | Homeauto | smarthome_tr064_set_switch, smarthome_rename_* (Rücklesen) | ✅ |
| `SetDeviceName` | W | App | smarthome_rename_plan/_execute (critical, Fallback ohne REST) | ✅ |
| `SetSwitch` | W | Homeauto | smarthome_tr064_set_switch (write, K-28, Rücklesen) | ✅ |

### X_AVM-DE_Homeplug1

4 Actions · ✅ 3 · 🟡 0 · ❌ 0 · ⛔ 1

| Action | R/W | Recht (Doku) | Abdeckung | Status |
|---|---|---|---|---|
| `GetNumberOfDeviceEntries` | R | App | avm_device_updates | ✅ |
| `GetGenericDeviceEntry` | R | App | avm_device_updates | ✅ |
| `GetSpecificDeviceEntry` | R | App | avm_device_detail (Stufe 10.7) | ✅ |
| `DeviceDoUpdate` | W | App | Firmware-Update | ⛔ |

### X_AVM-DE_HostFilter1

10 Actions · ✅ 9 · 🟡 1 · ❌ 0 · ⛔ 0

| Action | R/W | Recht (Doku) | Abdeckung | Status |
|---|---|---|---|---|
| `DisallowWANAccessByIP` | W | App | set_internet_access | ✅ |
| `DiscardAllTickets` | W | App | parental_tickets_discard_* (critical) | ✅ |
| `GetTicketIDStatus` | R | App | parental_ticket_status | ✅ |
| `GetWANAccessByIP` | R | App | internet_access_status, Schnappschuss | ✅ |
| `MarkTicket` | W | App | parental_ticket_create | ✅ |
| `GetHostEntryByIP` | R | App | parental_device_status, parental_add_ticket_time | ✅ |
| `GetFilterProfileByID` | R | App | tr064_call | 🟡 |
| `AddTicketTimeToHostEntryByIP` | W | App | parental_add_ticket_time | ✅ |
| `AddHostEntryToFilterProfile` | W | App | set_parental_profile | ✅ |
| `GetFilterProfiles` | R | App | parental_profiles | ✅ |

### X_AVM-DE_Media1

5 Actions · ✅ 1 · 🟡 2 · ❌ 1 · ⛔ 1

| Action | R/W | Recht (Doku) | Abdeckung | Status |
|---|---|---|---|---|
| `GetInfo` | R | keins | nas_status | ✅ |
| `GetDVBCEnable` | R | keins | tr064_call | 🟡 |
| `SetDVBCEnable` | W | App | Aussperr-/Ausfallrisiko | ⛔ |
| `StationSearch` | W | App | noch nicht gebaut (Netz-/Zugangsrisiko, siehe Kandidaten) | ❌ |
| `GetSearchProgress` | R | keins | tr064_call | 🟡 |

### X_AVM-DE_MyFritz1

6 Actions · ✅ 3 · 🟡 0 · ❌ 2 · ⛔ 1

| Action | R/W | Recht (Doku) | Abdeckung | Status |
|---|---|---|---|---|
| `GetInfo` | R | App / Phone / NAS / Homeauto | myfritz_status, vpn_status, security_check | ✅ |
| `SetMyFRITZ` | W | – | verlangt bzw. setzt Passwörter/Kontodaten – bewusst nicht gebaut | ⛔ |
| `GetNumberOfServices` | R | App / Phone | myfritz_status, vpn_status | ✅ |
| `GetServiceByIndex` | R | App / Phone | myfritz_status | ✅ |
| `SetServiceByIndex` | W | App / Phone | noch nicht gebaut | ❌ |
| `DeleteServiceByIndex` | W | App / Phone | noch nicht gebaut | ❌ |

### X_AVM-DE_RemoteAccess1

7 Actions · ✅ 3 · 🟡 0 · ❌ 2 · ⛔ 2

| Action | R/W | Recht (Doku) | Abdeckung | Status |
|---|---|---|---|---|
| `GetInfo` | R | App / Phone / NAS / Homeauto | myfritz_status, security_check, vpn_status | ✅ |
| `SetConfig` | W | – | noch nicht gebaut (Netz-/Zugangsrisiko, siehe Kandidaten) | ❌ |
| `GetDDNSInfo` | R | – | myfritz_status, vpn_status (Feld-Whitelist) – im generischen Caller gesperrt | ✅ |
| `GetDDNSProviders` | R | – | Schlüssel, Zugangsdaten bzw. Konto-Daten | ⛔ |
| `SetDDNSConfig` | W | – | Schlüssel, Zugangsdaten bzw. Konto-Daten | ⛔ |
| `SetEnable` | W | – | set_remote_access_plan/_execute (critical) | ✅ |
| `SetLetsEncryptEnable` | W | App | noch nicht gebaut | ❌ |

### X_AVM-DE_Speedtest1

4 Actions · ✅ 4 · 🟡 0 · ❌ 0 · ⛔ 0

| Action | R/W | Recht (Doku) | Abdeckung | Status |
|---|---|---|---|---|
| `GetInfo` | R | – | box_speedtest_info | ✅ |
| `SetConfig` | W | – | box_speedtest_run (`enable_temporarily`: nur LAN-TCP, WAN-Schalter unverändert, danach Rückstellung) | ✅ |
| `GetStatistics` | R | – | box_speedtest_info/_run | ✅ |
| `ResetStatistics` | W | – | box_speedtest_run | ✅ |

### X_AVM-DE_Storage1

7 Actions · ✅ 5 · 🟡 0 · ❌ 1 · ⛔ 1

| Action | R/W | Recht (Doku) | Abdeckung | Status |
|---|---|---|---|---|
| `GetInfo` | R | App | nas_status, backup_target_check | ✅ |
| `SetFTPServer` | W | – | set_nas_protocol | ✅ |
| `SetFTPServerWAN` | W | – | set_nas_internet_access_* (critical) | ✅ |
| `RequestFTPServerWAN` | W | – | noch nicht gebaut | ❌ |
| `SetSMBServer` | W | – | set_nas_protocol | ✅ |
| `GetUserInfo` | R | – | nas_status | ✅ |
| `SetUserConfig` | W | – | verlangt bzw. setzt Passwörter/Kontodaten – bewusst nicht gebaut | ⛔ |

### X_AVM-DE_TAM1

6 Actions · ✅ 6 · 🟡 0 · ❌ 0 · ⛔ 0

| Action | R/W | Recht (Doku) | Abdeckung | Status |
|---|---|---|---|---|
| `GetInfo` | R | Phone | set_tam_enabled (Rücklesen) | ✅ |
| `SetEnable` | W | Phone | set_tam_enabled | ✅ |
| `GetMessageList` | R | Phone | tam_list, tam_mark_message/tam_delete_message_* (Rücklesen) | ✅ |
| `MarkMessage` | W | Phone | tam_mark_message | ✅ |
| `DeleteMessage` | W | Phone | tam_delete_message_plan/_execute (critical) | ✅ |
| `GetList` | R | Phone / App | tam_list | ✅ |

### X_AVM-DE_UPnP1

2 Actions · ✅ 1 · 🟡 0 · ❌ 1 · ⛔ 0

| Action | R/W | Recht (Doku) | Abdeckung | Status |
|---|---|---|---|---|
| `GetInfo` | R | – | nas_status, security_check | ✅ |
| `SetConfig` | W | – | noch nicht gebaut (Netz-/Zugangsrisiko, siehe Kandidaten) | ❌ |

### X_AVM-DE_USPController1

8 Actions · ✅ 4 · 🟡 0 · ❌ 3 · ⛔ 1

| Action | R/W | Recht (Doku) | Abdeckung | Status |
|---|---|---|---|---|
| `GetInfo` | R | jedes | myfritz_status (Fallback) | ✅ |
| `GetUSPControllerByIndex` | R | – | myfritz_status (ohne Benutzer) | ✅ |
| `GetUSPControllerNumberOfEntries` | R | – | myfritz_status | ✅ |
| `AddUSPController` | W | – | verlangt bzw. setzt Passwörter/Kontodaten – bewusst nicht gebaut | ⛔ |
| `DeleteUSPControllerByIndex` | W | – | noch nicht gebaut (Netz-/Zugangsrisiko, siehe Kandidaten) | ❌ |
| `SetUSPControllerEnableByIndex` | W | – | noch nicht gebaut (Netz-/Zugangsrisiko, siehe Kandidaten) | ❌ |
| `GetUSPMyFRITZEnable` | R | jedes | myfritz_status | ✅ |
| `SetUSPMyFRITZEnable` | W | AppRights | noch nicht gebaut | ❌ |

### X_VoIP1

44 Actions · ✅ 8 · 🟡 13 · ❌ 11 · ⛔ 12

| Action | R/W | Recht (Doku) | Abdeckung | Status |
|---|---|---|---|---|
| `GetInfo` | R | Phone | tr064_call | 🟡 |
| `GetInfoEx` | R | Phone | tr064_call | 🟡 |
| `GetExistingVoIPNumbers` | R | Phone | tr064_call | 🟡 |
| `GetMaxVoIPNumbers` | R | Phone | tr064_call | 🟡 |
| `GetVoIPCommonAreaCode` | R | Phone | tr064_call | 🟡 |
| `GetVoIPEnableAreaCode` | R | Phone | tr064_call | 🟡 |
| `SetVoIPEnableAreaCode` | W | Phone | noch nicht gebaut | ❌ |
| `SetVoIPCommonAreaCode` | W | Phone | noch nicht gebaut | ❌ |
| `GetVoIPCommonCountryCode` | R | Phone | tr064_call | 🟡 |
| `GetVoIPEnableCountryCode` | R | Phone | tr064_call | 🟡 |
| `SetConfig` | W | Phone | noch nicht gebaut (Netz-/Zugangsrisiko, siehe Kandidaten) | ❌ |
| `SetVoIPCommonCountryCode` | W | Phone | noch nicht gebaut | ❌ |
| `SetVoIPEnableCountryCode` | W | Phone | noch nicht gebaut | ❌ |
| `X_AVM-DE_AddVoIPAccount` | W | Phone | verlangt bzw. setzt Passwörter/Kontodaten – bewusst nicht gebaut | ⛔ |
| `X_AVM-DE_DeleteClient` | W | Phone | noch nicht gebaut (Netz-/Zugangsrisiko, siehe Kandidaten) | ❌ |
| `X_AVM-DE_DelVoIPAccount` | W | Phone | noch nicht gebaut (Netz-/Zugangsrisiko, siehe Kandidaten) | ❌ |
| `X_AVM-DE_DialGetConfig` | R | Phone | dial_number_plan (Telefon der Wählhilfe) | ✅ |
| `X_AVM-DE_DialHangup` | W | Phone | dial_hangup | ✅ |
| `X_AVM-DE_DialNumber` | W | Phone | dial_number_plan/_execute (critical, Kosten-/Notruf-Warnung); im generischen Caller gesperrt | ✅ |
| `X_AVM-DE_DialSetConfig` | W | Phone | noch nicht gebaut (Netz-/Zugangsrisiko, siehe Kandidaten) | ❌ |
| `X_AVM-DE_GetNumberOfClients` | R | Phone | tr064_call | 🟡 |
| `X_AVM-DE_GetClient` | R | Phone | SIP-Zugangsdaten/-Benutzernamen | ⛔ |
| `X_AVM-DE_GetClient2` | R | Phone | SIP-Zugangsdaten/-Benutzernamen | ⛔ |
| `X_AVM-DE_GetClient3` | R | Phone | SIP-Zugangsdaten/-Benutzernamen | ⛔ |
| `X_AVM-DE_GetClientByClientId` | R | – | SIP-Zugangsdaten/-Benutzernamen | ⛔ |
| `X_AVM-DE_GetClients` | R | Phone | SIP-Zugangsdaten/-Benutzernamen | ⛔ |
| `X_AVM-DE_GetNumberOfNumbers` | R | Phone | tr064_call | 🟡 |
| `X_AVM-DE_GetNumbers` | R | Phone | phone_numbers_status | ✅ |
| `X_AVM-DE_GetPhonePort` | R | Phone | tr064_call | 🟡 |
| `X_AVM-DE_GetVoIPAccount` | R | Phone | SIP-Zugangsdaten/-Benutzernamen | ⛔ |
| `X_AVM-DE_GetVoIPAccounts` | R | App / Phone | SIP-Zugangsdaten/-Benutzernamen | ⛔ |
| `X_AVM-DE_GetVoIPStatus` | R | App / Phone | phone_numbers_status, alarms_check | ✅ |
| `X_AVM-DE_SetClient` | W | Phone | verlangt bzw. setzt Passwörter/Kontodaten – bewusst nicht gebaut | ⛔ |
| `X_AVM-DE_SetClient2` | W | Phone | verlangt bzw. setzt Passwörter/Kontodaten – bewusst nicht gebaut | ⛔ |
| `X_AVM-DE_SetClient3` | W | Phone | verlangt bzw. setzt Passwörter/Kontodaten – bewusst nicht gebaut | ⛔ |
| `X_AVM-DE_SetClient4` | W | Phone | verlangt bzw. setzt Passwörter/Kontodaten – bewusst nicht gebaut | ⛔ |
| `X_AVM-DE_SetDelayedCallNotification` | W | Phone | noch nicht gebaut | ❌ |
| `X_AVM-DE_SetVoIPCommonCountryCode` | W | Phone | noch nicht gebaut | ❌ |
| `X_AVM-DE_GetVoIPCommonCountryCode` | R | Phone | tr064_call | 🟡 |
| `X_AVM-DE_SetVoIPCommonAreaCode` | W | Phone | noch nicht gebaut | ❌ |
| `X_AVM-DE_GetVoIPCommonAreaCode` | R | Phone | tr064_call | 🟡 |
| `X_AVM-DE_GetAlarmClock` | R | Phone | alarm_clocks | ✅ |
| `X_AVM-DE_GetNumberOfAlarmClocks` | R | Phone | alarm_clocks | ✅ |
| `X_AVM-DE_SetAlarmClockEnable` | W | Phone | set_alarm_clock | ✅ |

### X_AVM-DE_WebDAVClient1

2 Actions · ✅ 1 · 🟡 0 · ❌ 1 · ⛔ 0

| Action | R/W | Recht (Doku) | Abdeckung | Status |
|---|---|---|---|---|
| `GetInfo` | R | – | nas_status (nur Host/Mountpoint) – im generischen Caller gesperrt | ✅ |
| `SetConfig` | W | – | noch nicht gebaut (Netz-/Zugangsrisiko, siehe Kandidaten) | ❌ |

## IGD (UPnP, „Internet Gateway Device Support“ v1/v2)

Nicht Teil der TR-064-Zählung oben. IGD-Dienste antworten nur, wenn in der Box „Statusinformationen über UPnP übertragen“ aktiv ist; Pinholes zusätzlich nur mit „Änderungen der Sicherheitseinstellungen über UPnP gestatten“.

| Service | Action | R/W | Abdeckung | Status |
|---|---|---|---|---|
| `WANIPConn1` | `X_AVM_DE_GetExternalIPv6Address` | R | wan_status | ✅ |
| `WANIPConn1` | `X_AVM_DE_GetDNSServer`, `X_AVM_DE_GetIPv6DNSServer` | R | get_dns_settings | ✅ |
| `WANIPConn1` | `X_AVM_DE_GetIPv6Prefix`, `X_AVM_DE_GetDsliteStatus` | R | system_transparency | ✅ |
| `WANCommonIFC1` | `GetAddonInfos` | R | online_monitor (64-bit-Zähler) | ✅ |
| `WANIPv6Firewall1` / `WANIPv6FirewallControl1` | `GetFirewallStatus` | R | ipv6_firewall_status, system_transparency (live 7583: `WANIPv6Firewall1`, Felder ohne `New`) | ✅ |
| `WANIPv6Firewall1` / `WANIPv6FirewallControl1` | `AddPinhole` | W | ipv6_pinhole_add_plan/_execute (critical) | ✅ |
| `WANIPv6Firewall1` / `WANIPv6FirewallControl1` | `UpdatePinhole` | W | Rücklesen der Pinholes | ✅ |
| `WANIPv6Firewall1` / `WANIPv6FirewallControl1` | `DeletePinhole` | W | ipv6_pinhole_delete_plan/_execute (critical) | ✅ |

## AHA-HTTP-Interface (`/webservices/homeautoswitch.lua`)

| Kommando | R/W | Abdeckung | Status |
|---|---|---|---|
| `getdevicelistinfos` | R | smarthome_list_devices, Schnappschuss | ✅ |
| `getbasicdevicestats` | R | smarthome_device_stats | ✅ |
| `setswitchon` / `setswitchoff` | W | smarthome_set_switch | ✅ |
| `getswitchstate` | R | smarthome_set_switch (Rücklesen) | ✅ |
| `sethkrtsoll` | W | smarthome_set_thermostat (16–56 = 8–28 °C, 253 aus, 254 an) | ✅ |
| `gethkrtsoll` | R | smarthome_set_thermostat (Rücklesen) | ✅ |
| `getswitchlist`, `getswitchpresent`, `getswitchpower`, `getswitchenergy`, `getswitchname`, `gettemperature`, `gethkrkomfort`, `gethkrabsenk`, `getdeviceinfos` | R | Werte stecken in getdevicelistinfos → smarthome_list_devices | 🟡 indirekt |
| `setswitchtoggle` | W | – (Toggle ohne Sollzustand widerspricht dem Rücklese-Prinzip) | ❌ |
| `sethkrboost`, `sethkrwindowopen` | W | smarthome_thermostat_mode (Fallback < 8.2, Echo der Endzeit als Rücklesen) | ✅ |
| `gettemplatelistinfos`, `applytemplate` | R/W | `applytemplate`: smarthome_apply_template (Fallback < 8.2); Liste: nur REST | 🟡 |
| `gettriggerlistinfos`, `settriggeractive` | R/W | `settriggeractive`: smarthome_set_routine (Fallback < 8.2, nicht rücklesbar); Liste: nur REST | 🟡 |
| `setsimpleonoff`, `setlevel`, `setlevelpercentage` | W | smarthome_set_unit (Fallback < 8.2: `setsimpleonoff`, `setlevelpercentage`) | ✅ |
| `setcolor`, `setunmappedcolor`, `setcolortemperature`, `getcolordefaults`, `addcolorleveltemplate` | R/W | Kandidat K-20 (Farblampen) | ❌ |
| `setblind` | W | smarthome_set_unit(blind) (Fallback < 8.2) | ✅ |
| `setname`, `setmetadata` | W | nicht geplant (braucht zusätzlich App-Recht; Umbenennen über REST sinnvoller) | ❌ |
| `startulesubscription`, `getsubscriptionstate` | W/R | smarthome_pairing_execute / _status (Fallback < 8.2, K-19) | ✅ |

Zählung: 36 Kommandos (Einzelbefehle der Tabelle zusammengefasst). Ab FRITZ!OS 8.2 ist die Smart-Home-REST-API der bevorzugte Weg; AHA bleibt Fallback für ältere Boxen.

## Smart-Home-REST-API (FRITZ!OS 8.2 / 8.5)

Basis `https://<box>/api/v0`, Anmeldung mit Header `AUTHORIZATION: AVM-SID <sid>` (wie die übrigen `/api/v0`-Aufrufe; die zentrale `/api/v0`-Schwärzung greift also automatisch). 8.5 ergänzt Trigger-Konfiguration, globale Werte schreiben (Urlaub/Sommer), Geofencing und Illuminance.

Schwärzung (seit 8.5a, `redact_api`): `latitude`/`longitude`, alles mit `geofenc…`, `location`, Push-Mail-`recipient`, `installCode`/`resetCode`/Pairing-Codes, `httpRequest`-Objekte (nur `method` bleibt lesbar).

| Methode | Endpunkt (unter `/api/v0`) | 8.2 | 8.5 | Status | Einordnung |
|---|---|---|---|---|---|
| GET | `/smarthome/configuration/devices/{UID}` | ✓ | ✓ | ❌ | lesen – Kandidat K-15 (Stufe 8.5a) |
| PUT | `/smarthome/configuration/devices/{UID}` | ✓ | ✓ | ❌ | Konfiguration ändern – Stufe 10 (K-17) |
| DELETE | `/smarthome/configuration/devices/{UID}` | ✓ | ✓ | ❌ | critical (Plan/Execute) – Stufe 10 |
| POST | `/smarthome/configuration/groups` | ✓ | ✓ | ❌ | Anlegen – offen (große Bodies, erst live prüfen; 10.6b) |
| GET | `/smarthome/configuration/groups/{UID}` | ✓ | ✓ | ✅ | smarthome_delete_* (Name, Rücklesen) |
| PUT | `/smarthome/configuration/groups/{UID}` | ✓ | ✓ | ❌ | Konfiguration ändern – Stufe 10 (K-17) |
| DELETE | `/smarthome/configuration/groups/{UID}` | ✓ | ✓ | ✅ | smarthome_delete_plan/_execute (critical, 10.6b) |
| GET | `/smarthome/configuration/templateCapabilities` | ✓ | ✓ | ❌ | lesen – Kandidat K-15 (Stufe 8.5a) |
| POST | `/smarthome/configuration/templates` | ✓ | ✓ | ❌ | Anlegen – offen (Vorlagen können `httpRequest` mit Zugangsdaten tragen; 10.6b) |
| GET | `/smarthome/configuration/templates/{UID}` | ✓ | ✓ | ✅ | smarthome_delete_* (Name, Rücklesen) |
| PUT | `/smarthome/configuration/templates/{UID}` | ✓ | ✓ | ❌ | Konfiguration ändern – Stufe 10 (K-17) |
| DELETE | `/smarthome/configuration/templates/{UID}` | ✓ | ✓ | ✅ | smarthome_delete_plan/_execute (critical, 10.6b) |
| GET | `/smarthome/configuration/triggerCapabilities` | – | ✓ | ❌ | lesen – Kandidat K-15 (Stufe 8.5a) |
| POST | `/smarthome/configuration/triggers` | – | ✓ | ❌ | Anlegen – offen (10.6b) |
| GET | `/smarthome/configuration/triggers/{UID}` | – | ✓ | ✅ | smarthome_delete_* (Name, Rücklesen) |
| PUT | `/smarthome/configuration/triggers/{UID}` | – | ✓ | ❌ | Konfiguration ändern – Stufe 10 (K-17) |
| DELETE | `/smarthome/configuration/triggers/{UID}` | – | ✓ | ✅ | smarthome_delete_plan/_execute (critical, 10.6b) |
| GET | `/smarthome/configuration/units/{UID}` | ✓ | ✓ | ✅ | smarthome_thermostat_config, Rücklesen für Urlaub/Sommer/Name (10.6b) |
| PUT | `/smarthome/configuration/units/{UID}` | ✓ | ✓ | ✅ | smarthome_holidays_*, smarthome_summer_period_*, smarthome_rename_* (critical, 10.6b); Heizplan (`timer`) bewusst noch nicht |
| POST | `/smarthome/connect/installCode/{serial}` | ✓ | ✓ | ⛔ | Pairing-Codes (Geheimnis) – nicht geplant |
| GET | `/smarthome/connect/radioBases` | ✓ | ✓ | ✅ | smarthome_pairing_plan/_status/_stop |
| GET | `/smarthome/connect/radioBases/{serial}` | ✓ | ✓ | ❌ | lesen – Kandidat K-15 (Stufe 8.5a) |
| POST | `/smarthome/connect/resetCode/{serial}` | ✓ | ✓ | ⛔ | Pairing-Codes (Geheimnis) – nicht geplant |
| POST | `/smarthome/connect/startSubscription/{serial}` | ✓ | ✓ | ✅ | smarthome_pairing_plan/_execute (critical, K-19) |
| POST | `/smarthome/connect/stopSubscription/{serial}` | ✓ | ✓ | ✅ | smarthome_pairing_stop (write) |
| GET | `/smarthome/connect/subscriptionState/{UID}` | ✓ | ✓ | ✅ | smarthome_pairing_status, Rücklesen im Execute |
| GET | `/smarthome/geofence/registrations` | – | ✓ | ❌ | Standortdaten (lat/lon) – höchstens Anzahl/Status, Koordinaten nie ausgeben |
| POST | `/smarthome/geofence/registrations` | – | ✓ | ⛔ | Standortdaten – nicht geplant |
| GET | `/smarthome/geofence/registrations/{UID}` | – | ✓ | ❌ | Standortdaten (lat/lon) – höchstens Anzahl/Status, Koordinaten nie ausgeben |
| PUT | `/smarthome/geofence/registrations/{UID}` | – | ✓ | ⛔ | Standortdaten – nicht geplant |
| DELETE | `/smarthome/geofence/registrations/{UID}` | – | ✓ | ⛔ | Standortdaten – nicht geplant |
| GET | `/smarthome/geofence/zones` | – | ✓ | ❌ | Standortdaten (lat/lon) – höchstens Anzahl/Status, Koordinaten nie ausgeben |
| POST | `/smarthome/geofence/zones` | – | ✓ | ⛔ | Standortdaten – nicht geplant |
| GET | `/smarthome/geofence/zones/{UID}` | – | ✓ | ❌ | Standortdaten (lat/lon) – höchstens Anzahl/Status, Koordinaten nie ausgeben |
| PUT | `/smarthome/geofence/zones/{UID}` | – | ✓ | ⛔ | Standortdaten – nicht geplant |
| DELETE | `/smarthome/geofence/zones/{UID}` | – | ✓ | ⛔ | Standortdaten – nicht geplant |
| GET | `/smarthome/overview` | ✓ | ✓ | ✅ | smarthome_overview, smarthome_energy_report (8.5a) |
| GET | `/smarthome/overview/devices` | ✓ | ✓ | ✅ | gleiche Daten über `/smarthome/overview` (smarthome_overview) |
| GET | `/smarthome/overview/devices/{UID}` | ✓ | ✓ | ❌ | lesen – Kandidat K-15 (Stufe 8.5a) |
| GET | `/smarthome/overview/globals` | ✓ | ✓ | ✅ | gleiche Daten über `/smarthome/overview` (smarthome_overview) |
| PUT | `/smarthome/overview/globals` | – | ✓ | ⛔ | enthält nur Lampen-Presets, Standort und den einmaligen Geofence-Schalter – bewusst nicht gebaut (Urlaub liegt in `configuration/units`, Stufe 10) |
| GET | `/smarthome/overview/groups` | ✓ | ✓ | ✅ | gleiche Daten über `/smarthome/overview` (smarthome_overview) |
| GET | `/smarthome/overview/groups/{UID}` | ✓ | ✓ | ❌ | lesen – Kandidat K-15 (Stufe 8.5a) |
| GET | `/smarthome/overview/templates` | ✓ | ✓ | ✅ | gleiche Daten über `/smarthome/overview` (smarthome_overview) |
| GET | `/smarthome/overview/templates/{UID}` | ✓ | ✓ | ❌ | lesen – Kandidat K-15 (Stufe 8.5a) |
| POST | `/smarthome/overview/templates/{UID}` | ✓ | ✓ | ✅ | smarthome_apply_template (8.5b, nicht rücklesbar → verified false) |
| GET | `/smarthome/overview/triggers` | ✓ | ✓ | ✅ | gleiche Daten über `/smarthome/overview` (smarthome_overview) |
| GET | `/smarthome/overview/triggers/{UID}` | ✓ | ✓ | ❌ | lesen – Kandidat K-15 (Stufe 8.5a) |
| PUT | `/smarthome/overview/triggers/{UID}` | ✓ | ✓ | ✅ | smarthome_set_routine (8.5b, Rücklesen) |
| GET | `/smarthome/overview/units` | ✓ | ✓ | ✅ | gleiche Daten über `/smarthome/overview` (smarthome_overview) |
| GET | `/smarthome/overview/units/{UID}` | ✓ | ✓ | ✅ | smarthome_unit (Heizplan/Timer, Statistik), Rücklesen in 8.5b |
| PUT | `/smarthome/overview/units/{UID}` | ✓ | ✓ | ✅ | smarthome_set_unit (an/aus, Level, Rollo), smarthome_thermostat_mode (Boost/Fenster offen ≤ 24 h), Rücklesen |
