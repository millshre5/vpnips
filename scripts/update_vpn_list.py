#!/usr/bin/env python3
"""
Update VPN IP/CIDR list from authoritative sources:
  - RIPE Stat API  : for providers that announce their own ASN prefixes
  - Provider APIs  : for providers that publish public server lists
  - Static entries : for providers with no public API or ASN
"""

import csv
import ipaddress
import sys
import time
from pathlib import Path

import requests

OUTPUT_FILE = Path(__file__).parent.parent / "vpn_ip_provider_list.csv"
RIPE_STAT_URL = "https://stat.ripe.net/data/announced-prefixes/data.json"

SESSION = requests.Session()
SESSION.headers.update({"User-Agent": "vpn-ip-list-updater/1.0 (github.com/millshre5/vpnips)"})

# ---------------------------------------------------------------------------
# Providers with their own ASNs — RIPE Stat returns authoritative CIDR blocks
# ---------------------------------------------------------------------------
ASN_PROVIDERS = [
    ("Mullvad",         ["AS39351"]),
    ("ProtonVPN",       ["AS62597"]),
    ("IVPN",            ["AS35505"]),
    ("AirVPN",          ["AS197962"]),
    ("AzireVPN",        ["AS208562"]),
    ("OVPN",            ["AS21409"]),
    ("Surfshark",       ["AS34523"]),
    ("PrivateVPN",      ["AS60404"]),
    ("PerfectPrivacy",  ["AS59642"]),
    ("VyprVPN",         ["AS29761"]),
    ("TunnelBear",      ["AS395823"]),
    ("PIA",             ["AS40676"]),
]

# ---------------------------------------------------------------------------
# Static entries — providers with no reliable public API or own ASN.
# These are manually verified and kept as a stable seed in the output.
# ---------------------------------------------------------------------------
STATIC_ENTRIES = [
    ("217.138.193.0/24", "ExpressVPN"),
    ("217.138.200.0/24", "ExpressVPN"),
    ("217.138.204.0/24", "ExpressVPN"),
    ("185.57.80.0/22",   "ExpressVPN"),
    ("192.153.56.0/24",  "ExpressVPN"),
    ("198.7.56.0/22",    "IPVanish"),
    ("64.127.56.0/22",   "IPVanish"),
    ("64.235.48.0/22",   "IPVanish"),
    ("96.44.167.0/24",   "IPVanish"),
    ("104.129.24.0/24",  "IPVanish"),
    ("146.70.90.0/24",   "CyberGhost"),
    ("185.212.170.0/24", "CyberGhost"),
    ("5.180.62.0/24",    "CyberGhost"),
    ("5.253.204.0/24",   "CyberGhost"),
    ("87.247.186.0/24",  "CyberGhost"),
    ("64.44.80.0/21",    "Windscribe"),
    ("192.36.27.0/24",   "Windscribe"),
    ("198.50.128.0/24",  "Windscribe"),
    ("69.167.132.0/24",  "Windscribe"),
    ("104.238.228.0/24", "Windscribe"),
    ("46.235.224.0/24",  "HMA"),
    ("5.34.180.0/24",    "HMA"),
    ("87.118.116.0/24",  "HMA"),
    ("185.230.124.0/24", "HMA"),
    ("23.93.88.0/21",    "TorGuard"),
    ("104.168.102.0/24", "TorGuard"),
    ("198.27.64.0/24",   "TorGuard"),
    ("89.40.181.0/24",   "TorGuard"),
    ("104.223.96.0/24",  "TunnelBear"),
    ("209.197.21.0/24",  "TunnelBear"),
    ("172.83.40.0/24",   "TunnelBear"),
    ("107.152.64.0/19",  "HotspotShield"),
    ("107.152.96.0/20",  "HotspotShield"),
    ("23.105.168.0/22",  "HotspotShield"),
    ("213.152.161.0/24", "Hide.me"),
    ("213.152.162.0/24", "Hide.me"),
    ("83.143.116.0/24",  "Hide.me"),
    ("185.220.101.0/24", "Tor"),
    ("185.220.102.0/24", "Tor"),
    ("185.220.103.0/24", "Tor"),
    ("185.130.44.0/24",  "Tor"),
    ("45.151.167.0/24",  "Tor"),
    ("66.220.2.0/24",    "PureVPN"),
    ("37.44.213.0/24",   "PureVPN"),
    ("185.185.8.0/24",   "PureVPN"),
    ("91.206.14.0/24",   "PureVPN"),
    ("103.200.30.0/24",  "PureVPN"),
    ("217.138.218.0/24", "PureVPN"),
    ("193.148.16.0/24",  "AtlasVPN"),
    ("149.102.234.0/24", "AtlasVPN"),
    ("194.127.167.0/24", "AtlasVPN"),
    ("194.242.8.0/24",   "OVPN"),
    ("93.115.27.0/24",   "OVPN"),
    ("185.177.124.0/24", "PrivateVPN"),
    ("46.246.122.0/24",  "PrivateVPN"),
    ("185.177.125.0/24", "PrivateVPN"),
    ("162.220.62.0/24",  "VPNUnlimited"),
    ("104.200.128.0/24", "VPNUnlimited"),
    ("69.174.99.0/24",   "VPNUnlimited"),
    ("89.46.100.0/24",   "StrongVPN"),
    ("198.8.83.0/24",    "StrongVPN"),
    ("209.58.128.0/20",  "StrongVPN"),
    ("5.45.116.0/22",    "ZenMate"),
    ("213.165.93.0/24",  "ZenMate"),
    ("178.162.203.0/24", "AvastVPN"),
    ("194.126.177.0/24", "AvastVPN"),
    ("185.94.192.0/24",  "AvastVPN"),
    ("104.193.252.0/24", "NortonVPN"),
    ("199.188.105.0/24", "NortonVPN"),
    ("77.81.104.0/24",   "PerfectPrivacy"),
    ("82.102.19.0/24",   "PerfectPrivacy"),
    ("194.165.16.128/25","VPN.ac"),
    ("93.114.52.0/24",   "VPN.ac"),
    ("37.187.103.0/24",  "Astrill"),
    ("46.166.188.0/24",  "Astrill"),
    ("185.75.56.0/24",   "Astrill"),
    ("45.134.140.0/24",  "Astrill"),
    ("46.183.221.0/24",  "FastVPN"),
    ("185.49.104.0/24",  "FastVPN"),
    ("199.116.116.0/24", "Seed4.me"),
    ("185.154.195.0/24", "Seed4.me"),
    ("81.171.71.0/24",   "VeePN"),
    ("185.244.212.0/24", "VeePN"),
    ("82.146.60.0/24",   "CactusVPN"),
    ("195.181.170.0/24", "CactusVPN"),
    ("185.233.104.0/24", "FreedomeVPN"),
    ("185.233.105.0/24", "FreedomeVPN"),
    ("198.50.185.0/24",  "SaferVPN"),
    ("199.204.138.0/24", "SaferVPN"),
    ("185.234.216.0/24", "GooseVPN"),
    ("185.234.217.0/24", "GooseVPN"),
    ("194.110.112.0/24", "TigerVPN"),
    ("194.110.115.0/24", "TigerVPN"),
    ("185.229.58.0/24",  "Hidester"),
    ("185.10.68.0/24",   "Hidester"),
    ("209.127.17.0/24",  "Speedify"),
    ("209.127.18.0/24",  "Speedify"),
]


def normalize_cidr(value: str) -> str | None:
    """Return a normalized CIDR string, or None if invalid."""
    try:
        return str(ipaddress.ip_network(value, strict=False))
    except ValueError:
        return None


def fetch_ripe_prefixes(asn: str) -> list[str]:
    """Return announced IPv4 CIDR prefixes for the given ASN via RIPE Stat."""
    try:
        resp = SESSION.get(RIPE_STAT_URL, params={"resource": asn}, timeout=20)
        resp.raise_for_status()
        prefixes = []
        for item in resp.json().get("data", {}).get("prefixes", []):
            cidr = normalize_cidr(item.get("prefix", ""))
            if cidr and ":" not in cidr:  # skip IPv6
                prefixes.append(cidr)
        time.sleep(0.5)  # be polite to RIPE Stat
        return prefixes
    except Exception as e:
        print(f"  [WARN] RIPE Stat error for {asn}: {e}", file=sys.stderr)
        return []


def fetch_nordvpn() -> list[tuple[str, str]]:
    """Fetch server IPs from the NordVPN public API."""
    results = []
    try:
        resp = SESSION.get(
            "https://api.nordvpn.com/v1/servers",
            params={"limit": 7000},
            timeout=30,
        )
        resp.raise_for_status()
        for server in resp.json():
            ip = server.get("station")
            if ip:
                cidr = normalize_cidr(f"{ip}/32")
                if cidr:
                    results.append((cidr, "NordVPN"))
    except Exception as e:
        print(f"  [WARN] NordVPN API error: {e}", file=sys.stderr)
    return results


def fetch_mullvad() -> list[tuple[str, str]]:
    """Fetch relay IPs from the Mullvad public API."""
    results = []
    try:
        resp = SESSION.get("https://api.mullvad.net/www/relays/all/", timeout=20)
        resp.raise_for_status()
        for relay in resp.json():
            ip = relay.get("ipv4_addr_in") or relay.get("ip_address")
            if ip:
                cidr = normalize_cidr(f"{ip}/32")
                if cidr:
                    results.append((cidr, "Mullvad"))
    except Exception as e:
        print(f"  [WARN] Mullvad API error: {e}", file=sys.stderr)
    return results


def fetch_protonvpn() -> list[tuple[str, str]]:
    """Fetch server IPs from the ProtonVPN public API."""
    results = []
    try:
        resp = SESSION.get("https://api.protonvpn.ch/vpn/logicals", timeout=30)
        resp.raise_for_status()
        for logical in resp.json().get("LogicalServers", []):
            for server in logical.get("Servers", []):
                for key in ("EntryIP", "ExitIP"):
                    ip = server.get(key)
                    if ip:
                        cidr = normalize_cidr(f"{ip}/32")
                        if cidr:
                            results.append((cidr, "ProtonVPN"))
    except Exception as e:
        print(f"  [WARN] ProtonVPN API error: {e}", file=sys.stderr)
    return results


def main():
    # Use dict to preserve insertion order and deduplicate
    entries: dict[tuple[str, str], None] = {}

    # 1. Static seed entries (always included)
    print("Loading static entries...")
    for cidr, vpn in STATIC_ENTRIES:
        c = normalize_cidr(cidr)
        if c:
            entries[(c, vpn)] = None
    print(f"  {len(entries)} static entries loaded")

    # 2. RIPE Stat ASN prefixes
    for provider, asns in ASN_PROVIDERS:
        before = len(entries)
        for asn in asns:
            print(f"Fetching RIPE prefixes for {provider} ({asn})...")
            for prefix in fetch_ripe_prefixes(asn):
                entries[(prefix, provider)] = None
        added = len(entries) - before
        print(f"  +{added} prefixes for {provider}")

    # 3. Provider APIs
    for label, fetcher in [
        ("NordVPN",   fetch_nordvpn),
        ("Mullvad",   fetch_mullvad),
        ("ProtonVPN", fetch_protonvpn),
    ]:
        before = len(entries)
        print(f"Fetching {label} server list...")
        for entry in fetcher():
            entries[entry] = None
        print(f"  +{len(entries) - before} IPs for {label}")

    # 4. Sort by provider name then CIDR and write
    def sort_key(item):
        cidr, vpn = item
        return (vpn.lower(), ipaddress.ip_network(cidr, strict=False))

    sorted_entries = sorted(entries.keys(), key=sort_key)

    with open(OUTPUT_FILE, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["cidr", "vpn"])
        writer.writerows(sorted_entries)

    print(f"\nDone — wrote {len(sorted_entries)} entries to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
