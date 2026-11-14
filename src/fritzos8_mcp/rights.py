"""Stage 9.7 – which FRITZ!Box user right each tool needs (from the "Recht (Doku)" column in docs/COVERAGE.md, V-24).

Rights (FRITZ!Box > System > FRITZ!Box-Benutzer, AVM names in brackets):

* ``settings`` – "FRITZ!Box Einstellungen" (BoxAdmin): everything over ``/api/v0`` and most TR-064 writes.
* ``app`` – "Eingeschränkte FRITZ!Box Einstellungen für Apps" (App): parental control, guest Wi-Fi/WPS, Powerline,
  storage info, mobile/fibre values, smart-home device names. ``settings`` includes it.
* ``phone`` – "Sprachnachrichten, Faxnachrichten, FRITZ!App Fon und Anrufliste" (Phone).
* ``dial`` – "Wählhilfe" (Dial).
* ``nas`` – "Zugang zu NAS-Inhalten" (NAS).
* ``smarthome`` – "Smart Home" (HomeAuto).
* ``none`` – no box right (local data only, or TR-064 actions without a documented right).

Each tool lists ALL rights it needs (most need one). ``setup_check`` compares them with the rights of the configured
user and reports the tools that will fail. ``tests/test_rights.py`` makes sure every registered tool is listed.
"""

from __future__ import annotations

RIGHT_LABELS: dict[str, str] = {
    "settings": "FRITZ!Box Einstellungen",
    "app": "Eingeschränkte FRITZ!Box Einstellungen für Apps",
    "phone": "Sprachnachrichten, Faxnachrichten, FRITZ!App Fon und Anrufliste",
    "dial": "Wählhilfe",
    "nas": "Zugang zu NAS-Inhalten",
    "smarthome": "Smart Home",
    "none": "kein Recht nötig",
}

# AVM right paths (X_AVM-DE_CurrentUserRights / login_sid.lua <Rights>) → our codes
AVM_RIGHT_PATHS: dict[str, str] = {
    "boxadmin": "settings",
    "app": "app",
    "phone": "phone",
    "dial": "dial",
    "nas": "nas",
    "homeauto": "smarthome",
}

_S = ("settings",)
_A = ("app",)
_P = ("phone",)
_N = ("none",)
_H = ("smarthome",)
_NAS = ("nas",)

TOOL_RIGHTS: dict[str, tuple[str, ...]] = {
    # --- server / local only
    "server_status": _N,
    "history_query": _N,
    "history_summary": _N,
    "history_anomalies": _N,
    "isp_report": _N,
    "network_optimizer_effect": _N,
    "snapshot_list": _N,
    # --- system, WAN, diagnostics (TR-064)
    "system_info": _N,
    "boxes_overview": _S,
    "compare_boxes": _S,
    "wan_status": _N,
    "dsl_info": _S,
    "line_diagnostics": _A,
    "online_monitor": _A,
    "firmware_status": _N,
    "firmware_update_status": _N,
    "firmware_update_plan": _S,
    "firmware_update_execute": _S,
    "system_log": _S,
    "system_transparency": _S,
    "security_check": _S,
    "network_doctor": _S,
    "history_collect": _S,
    "alarms_check": _S,
    "family_admin_report": _S,
    "two_factor_status": _N,
    "reboot_plan": _S,
    "reboot_execute": _S,
    "reconnect_wan_plan": _S,
    "reconnect_wan_execute": _S,
    "static_route_add_plan": _S,
    "static_route_add_execute": _S,
    "static_route_delete_plan": _S,
    "static_route_delete_execute": _S,
    "ipv6_firewall_status": _N,
    "ipv6_pinhole_add_plan": _N,
    "ipv6_pinhole_add_execute": _N,
    "ipv6_pinhole_delete_plan": _N,
    "ipv6_pinhole_delete_execute": _N,
    "tr064_list_services": _N,
    "tr064_describe_action": _N,
    "tr064_call": _S,
    # --- devices / hosts
    "list_hosts": _S,
    "list_landevices": _S,
    "get_lan_dns": _S,
    "get_dns_settings": _S,
    "rename_host": _S,
    "set_static_ip": _S,
    "delete_host": _S,
    "delete_host_force_plan": _S,
    "delete_host_force_execute": _S,
    "devices_cleanup_report": _S,
    "devices_cleanup_plan": _S,
    "devices_cleanup_execute": _S,
    "devices_change_counter": _N,
    "avm_device_updates": _A,
    "avm_device_detail": _A,
    "dect_handsets": _A,
    "snapshot_create": _S,
    "snapshot_diff": _S,
    "wake_on_lan": _S,
    "mesh_overview": _S,
    "fritz_drift": _S,
    "fritz_export": _S,
    "fritz_apply_plan": _S,
    "fritz_apply_execute": _S,
    # --- LAN, VPN, quality (/api/v0 + TR-064)
    "lan_ports": _S,
    "set_lan_eee": _S,
    "vpn_status": _S,
    "vpn_connections": _S,
    "powerline_status": _S,
    "box_speedtest_info": _S,
    "box_speedtest_run": _S,
    "device_connection_quality": _S,
    "test_my_device": _S,
    "network_optimizer_suggest": _S,
    "network_optimizer_apply_plan": _S,
    "network_optimizer_apply_execute": _S,
    # --- WLAN, guest
    "wlan_status": _A,
    "wlan_settings": _A,
    "set_wlan_channel": _S,
    "set_wlan_enabled_plan": _S,
    "set_wlan_enabled_execute": _S,
    "guest_wifi_status": _A,
    "set_guest_wifi": _A,
    "guest_wifi_session": _A,
    "guest_wifi_session_start": _A,
    "guest_wifi_session_stop": _A,
    "guest_wifi_qr": _A,
    "wps_button": _A,
    # --- parental control
    "internet_access_status": _A,
    "set_internet_access": _A,
    "parental_profiles": _A,
    "parental_device_status": _A,
    "parental_ticket_status": _A,
    "set_parental_profile": _A,
    "parental_ticket_create": _A,
    "parental_add_ticket_time": _A,
    "parental_tickets_discard_plan": _A,
    "parental_tickets_discard_execute": _A,
    # --- port forwarding
    "list_port_forwards": _S,
    "add_port_forward_plan": _S,
    "add_port_forward_execute": _S,
    "delete_port_forward_plan": _S,
    "delete_port_forward_execute": _S,
    # --- NAS & remote access
    "nas_status": _A,
    "backup_target_check": _A,
    "set_nas_protocol": _S,
    "set_nas_internet_access_plan": _S,
    "set_nas_internet_access_execute": _S,
    "myfritz_status": _S,
    "set_remote_access_plan": _S,
    "set_remote_access_execute": _S,
    # --- telephony
    "call_list": _P,
    "tam_list": _P,
    "phonebook_list": _P,
    "phonebook_search": _P,
    "phone_numbers_status": _P,
    "alarm_clocks": _P,
    "call_deflections": _P,
    "call_barring_list": _P,
    "set_tam_enabled": _P,
    "set_alarm_clock": _P,
    "set_call_deflection": _P,
    "call_barring_add": _P,
    "call_barring_remove": _P,
    "tam_mark_message": _P,
    "tam_delete_message_plan": _P,
    "tam_delete_message_execute": _P,
    "dial_number_plan": ("dial",),
    "dial_number_execute": ("dial",),
    "dial_hangup": ("dial",),
    # --- smart home (AHA, REST, TR-064)
    "smarthome_list_devices": _H,
    "smarthome_device_stats": _H,
    "smarthome_set_switch": _H,
    "smarthome_set_thermostat": _H,
    "smarthome_overview": _H,
    "smarthome_unit": _H,
    "smarthome_energy_report": _H,
    "smarthome_set_unit": _H,
    "smarthome_thermostat_mode": _H,
    "smarthome_set_routine": _H,
    "smarthome_apply_template": _H,
    "smarthome_thermostat_config": _H,
    "smarthome_holidays_plan": _H,
    "smarthome_holidays_execute": _H,
    "smarthome_summer_period_plan": _H,
    "smarthome_summer_period_execute": _H,
    "smarthome_delete_plan": _H,
    "smarthome_delete_execute": _H,
    "smarthome_rename_plan": ("smarthome", "app"),
    "smarthome_rename_execute": ("smarthome", "app"),
    "smarthome_pairing_status": ("smarthome", "app"),
    "smarthome_pairing_plan": ("smarthome", "app"),
    "smarthome_pairing_execute": ("smarthome", "app"),
    "smarthome_pairing_stop": ("smarthome", "app"),
    "smarthome_tr064_devices": _H,
    "smarthome_tr064_set_switch": _H,
    # --- setup
    "setup_check": _N,
}

# Tools that work partially without the right (the missing part is reported as unavailable, not as an error).
PARTIAL: dict[str, str] = {
    "security_check": "einzelne Prüfungen ohne Recht = unknown",
    "network_doctor": "Quellen ohne Recht fallen einzeln aus",
    "family_admin_report": "Teile ohne Recht = unbekannt",
    "nas_status": "Freigaben ins Internet brauchen 'FRITZ!Box Einstellungen'",
    "boxes_overview": "Kurz-Sicherheitsstatus braucht 'FRITZ!Box Einstellungen'",
    "history_collect": "Messgrößen ohne Recht fehlen einzeln",
    "alarms_check": "Prüfungen ohne Recht fallen einzeln aus",
}


def satisfied(needed: tuple[str, ...], have: set[str]) -> bool:
    """``settings`` includes ``app``; ``none`` is always satisfied."""
    effective = set(have) | ({"app"} if "settings" in have else set()) | {"none"}
    return all(n in effective for n in needed)


def affected_tools(have: set[str], registered: set[str] | None = None) -> dict[str, list[str]]:
    """Missing right → tools that need it (only registered tools if given)."""
    out: dict[str, list[str]] = {}
    for tool, needed in sorted(TOOL_RIGHTS.items()):
        if registered is not None and tool not in registered:
            continue
        if satisfied(needed, have):
            continue
        for n in needed:
            if not satisfied((n,), have):
                out.setdefault(n, []).append(tool)
    return out
