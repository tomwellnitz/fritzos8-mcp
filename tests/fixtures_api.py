"""Realistic /api/v0 answers (structure as seen live on FRITZ!OS 8.26) with INVENTED values only.

Every key/password below is made up; the ``FAKE`` marker lets tests assert that nothing of it leaks.
"""

from __future__ import annotations

FAKE_PSK = "FAKEpskAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
FAKE_PUB = "FAKEpubBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
FAKE_PRIV = "FAKEprivCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC="
FAKE_XAUTH = "FAKE-xauth-Passwort-123"
FAKE_ACCESS_PSK = "FAKE-access-psk-456"
FAKE_WG_CONF = (
    "[Interface]\nPrivateKey = " + FAKE_PRIV + "\nAddress = 192.0.2.2/24\n\n"
    "[Peer]\nPublicKey = " + FAKE_PUB + "\nPresharedKey = " + FAKE_PSK + "\nEndpoint = box-b.example:51820\n"
)

FAKE_SECRETS = (FAKE_PSK, FAKE_PUB, FAKE_PRIV, FAKE_XAUTH, FAKE_ACCESS_PSK, "FAKE-user")

VPN = {
    "connection": [
        {
            "UID": "connection1",
            "name": "Box B",
            "state": "ready",
            "activated": "1",
            "connected_since": "1763120000",
            "remote_ip": "198.51.100.7",
            "dst": "box-b.example",
            "src": "",
            "display_local_net": "192.0.2.0/24",
            "display_remote_net": "198.51.100.0/24",
            "wg_endpoint": "box-b.example:51820",
            "wg_endpoint_own": "box-a.example:51820",
            "wg_allowed_ips": "198.51.100.0/24",
            "wg_connection_type": "lan2lan",
            "wg_error": "0",
            "wg_error_reason": "",
            "wg_preshared_key": FAKE_PSK,
            "wg_public_key": FAKE_PUB,
            "wg_slave_config": FAKE_WG_CONF,
            "wg_master_config": FAKE_WG_CONF,
            "wg_mastered_slave_config": FAKE_WG_CONF,
            "access_psk": "",
            "xauth_password": "",
            "access_username": "",
            "xauth_username": "",
        },
        {
            "UID": "connection2",
            "name": "Altes IPSec",
            "state": "not active",
            "activated": "0",
            "connected_since": "0",
            "remote_ip": "",
            "dst": "ipsec.example",
            "display_local_net": "192.0.2.0/24",
            "display_remote_net": "203.0.113.0/24",
            "wg_endpoint": "",
            "wg_connection_type": "",
            "wg_error": "",
            "wg_error_reason": "",
            "wg_preshared_key": "",
            "access_psk": FAKE_ACCESS_PSK,
            "xauth_password": FAKE_XAUTH,
            "access_username": "FAKE-user",
            "xauth_username": "FAKE-user",
        },
    ],
    "global": [
        {
            "wg_listen_port": "51820",
            "wg_public_key": FAKE_PUB,
            "default_local_phase1_id": "box-a.example",
            "wg_device_config": FAKE_WG_CONF,
        }
    ],
}

ETH_PORTS = {
    "eth": [
        {
            "ifname": "eth0",
            "label": "LAN:1",
            "UID": "ethport8054",
            "function": "lan",
            "carrier": "1",
            "speed": "1000",
            "speed_list": "10,100,1000",
            "maxspeed": "1000",
            "mode": "2",
            "portmode": "0",
            "eee_supported": "1",
            "eee_mode": "0",
            "eee_active": "1",
        },
        {
            "ifname": "eth1",
            "label": "LAN:2",
            "UID": "ethport8055",
            "function": "lan",
            "carrier": "1",
            "speed": "100",
            "speed_list": "10,100,1000",
            "maxspeed": "1000",
            "mode": "2",
            "portmode": "0",
            "eee_supported": "1",
            "eee_mode": "0",
            "eee_active": "0",
        },
        {
            "ifname": "eth2",
            "label": "LAN:3",
            "UID": "ethport8056",
            "function": "guest",
            "carrier": "0",
            "speed": "0",
            "speed_list": "10,100,1000",
            "maxspeed": "1000",
            "mode": "2",
            "portmode": "0",
            "eee_supported": "1",
            "eee_mode": "0",
            "eee_active": "0",
        },
        {
            "ifname": "wan",
            "label": "WAN:1",
            "UID": "ethport8060",
            "function": "wan",
            "carrier": "0",
            "speed": "0",
            "speed_list": "10,100,1000",
            "maxspeed": "1000",
            "mode": "2",
            "portmode": "0",
            "eee_supported": "1",
            "eee_mode": "0",
            "eee_active": "0",
        },
    ]
}

PLC = {
    "device": [
        {
            "model": "FRITZ!Powerline 1260",
            "mac": "AA:BB:CC:DD:EE:50",
            "status": "active",
            "coupling": "good",
            "firmwareVersion": "7.58",
            "hasFirmwareupdate": "0",
            "phyRateRX": "512",
            "phyRateTX": "480",
            "green": "1",
            "led": "1",
            "isLocal": "0",
            "remoteAdapters": [{"mac": "AA:BB:CC:DD:EE:51", "phyRateRX": "500", "phyRateTX": "470"}],
            "securityID": "FAKE-DPW-ABCD-EFGH",
            "password": "FAKE-plc-pass",
        }
    ],
    "powerSave": "1",
}
