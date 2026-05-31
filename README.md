# vpnips

A daily-updated CSV list of IP addresses and CIDR ranges attributed to known VPN providers.

## File

**`vpn_ip_provider_list.csv`** — two columns, no extras:

```
cidr,vpn
103.86.96.0/22,NordVPN
193.138.218.0/24,Mullvad
...
```

## Providers

| Provider | Source |
|---|---|
| AirVPN | RIPE Stat (AS197962) |
| Astrill | Static |
| AtlasVPN | Static |
| AvastVPN | Static |
| AzireVPN | RIPE Stat (AS208562) |
| CactusVPN | Static |
| CyberGhost | Static |
| ExpressVPN | Static |
| FastVPN | Static |
| FreedomeVPN | Static |
| GooseVPN | Static |
| Hide.me | Static |
| Hidester | Static |
| HMA | Static |
| HotspotShield | Static |
| IPVanish | Static |
| IVPN | RIPE Stat (AS35505) |
| Mullvad | RIPE Stat (AS39351) + Provider API |
| NordVPN | Provider API |
| NortonVPN | Static |
| OVPN | RIPE Stat (AS21409) |
| PerfectPrivacy | RIPE Stat (AS59642) |
| PIA | RIPE Stat (AS40676) |
| PrivateVPN | RIPE Stat (AS60404) |
| ProtonVPN | RIPE Stat (AS62597) + Provider API |
| PureVPN | Static |
| SaferVPN | Static |
| Seed4.me | Static |
| Speedify | Static |
| StrongVPN | Static |
| Surfshark | RIPE Stat (AS34523) |
| TigerVPN | Static |
| Tor | Static |
| TorGuard | Static |
| TunnelBear | RIPE Stat (AS395823) |
| VeePN | Static |
| VPN.ac | Static |
| VPNUnlimited | Static |
| VyprVPN | RIPE Stat (AS29761) |
| Windscribe | Static |
| ZenMate | Static |

## Data Sources

All data is pulled directly from authoritative sources — no third-party aggregator lists.

- **RIPE Stat API** — `https://stat.ripe.net/data/announced-prefixes/data.json`  
  Used for providers that announce their own ASN prefixes. Returns actual CIDR blocks.

- **NordVPN API** — `https://api.nordvpn.com/v1/servers`  
  Official NordVPN server list (public, no auth required).

- **Mullvad API** — `https://api.mullvad.net/www/relays/all/`  
  Official Mullvad relay list (public, no auth required).

- **ProtonVPN API** — `https://api.protonvpn.ch/vpn/logicals`  
  Official ProtonVPN server list (public, no auth required).

- **Static entries** — manually verified CIDR blocks for providers that do not publish a public API or operate their own ASN. These remain stable between runs.

## Automation

A GitHub Action runs daily at **02:00 UTC** and commits updated data if anything changed.

To trigger a manual refresh: **Actions → Update VPN IP List → Run workflow**

## Notes

- VPN providers rotate IPs frequently. Dynamic entries (API/RIPE) reflect current data at time of last run.
- Static entries are point-in-time snapshots and may drift over time. PRs to update them are welcome.
- Individual server IPs fetched from provider APIs are stored as `/32` host routes.
- IPv6 ranges are not currently included.
