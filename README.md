# paloalto-automation-tools

Automation and troubleshooting tools for a multi-site estate of Palo Alto Networks firewalls (HA pairs and
standalone cloud firewalls, with Panorama).

| Tool | Command | What it's for | Changes firewalls? |
|---|---|---|---|
| [Site-to-site VPN manager](s2s_vpn/README.md) | `corp-s2s` | Audit, plan and apply IPsec tunnels so both ends of every link match | Only `apply --execute`, to devices you name |
| [Firewall troubleshooter](troubleshoot/README.md) | `pan-troubleshoot` | Why is this IP blocked? CLI plus the **Firewall Check** web app for helpdesk, best-practice audit, HA health | Never (read-only) |

## Layout

```
common/          shared by every tool: PAN-OS XML API client, config parser, xpath helpers, YAML loader
s2s_vpn/         site-to-site VPN manager          (README, examples/, tests/)
troubleshoot/    firewall troubleshooter + web app  (README, examples/, tests/, web/)
inventory/       your real firewall lists: git-ignored, never committed
```

A new tool gets its own folder next to these, with its own README, examples and tests, and reuses `common/`.

## Install

Python 3.9 or newer.

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
corp-s2s demo            # VPN manager on fictional data; sends nothing
pan-troubleshoot demo    # troubleshooter scenarios on fictional data; contacts nothing
```

Without installing, `python3 vpn_manager.py ...` and `python3 fw_troubleshoot.py ...` do the same from this folder.

## Tests

```bash
python3 -m unittest discover        # every tool
python3 -m unittest discover -s troubleshoot/tests -t .   # one tool
```

All tests are offline: they use the fictional data in each tool's `examples/` and fake API transports.

## Data handling

* Only code, docs and **fictional** data are tracked. Demos use RFC 5737 addresses and `example.net`.
* `.gitignore` excludes device exports (`*.xml` outside `examples/`), `inventory/`, backups, plans, reports, keys
  and `.env*`.
* Secrets are stripped when a config is read; plans, reports and logs redact them. API keys come from the
  environment and are kept in memory only.
