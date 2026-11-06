# Changelog

## Unreleased

Audit fixes (still passive and local-only):

- Global flags given before a subcommand (`sentinel.py --json report`,
  `--html FILE demo`, `--iface NAME scan`) are no longer overwritten by
  the subparser defaults.
- `nmcli` parsing: the invalid `CHAN_BW` field made the whole query fail
  on current nmcli, and terse-mode `\:` escaping broke SSID/BSSID
  parsing. Both are fixed.
- `iw scan` RSN capabilities are read from the real `* Capabilities:`
  line, so PMF (802.11w) is detected. Monitor-mode beacons now take
  signal strength from `dBm_AntSignal` and read RSN capabilities from
  the IE (the old duplicate branch was unreachable).
- A neighbour's mesh network no longer scores as a critical evil twin
  on your network; only duplicates of your own SSID are critical.
- Unknown/absent WiFi security is no longer graded as an open network
  (a missing adapter used to cost 45 points).
- Rogue DHCP is not reported when the default gateway is unknown, and
  the macOS lease-file path is now actually read.
- ARP scan falls back to the neighbour table when scapy is installed but
  raw sockets are denied (unprivileged run); Windows `arp -a` parsing no
  longer aborts on its header line.
- Windows adapter discovery via `ipconfig`; the package no longer fails
  to import on Windows (`fcntl` is Unix-only).
- Duplicate vendor prefixes removed (the later entry silently won).
- CI: `sentinelwifi/test_config_env.py` now carries the required header,
  so the passive-only audit step passes.

## v2.2.0

Unique-value detection pass, all passive:

- WPS detection from beacons / `iw scan` (enabled WPS = brute-forceable
  PIN regardless of password strength), scored −10.
- PMF (802.11w) check from RSN capabilities — tells you whether deauth
  attacks would work against your network without performing any.
- WiFi generation detection (WiFi 4/5/6/7) from HT/VHT/HE beacon IEs.
- Connection block shows WPS / deauth-safety / generation lines.
- +2 scoring checks and parser tests (36 total).

## v2.1.0

Professionalization pass:

- PyPI-ready packaging: `pipx install git+https://github.com/Nav54877/SentinelWiFi.git`
  gives you a `sentinelwifi` command.
- `doctor` alias for `selftest`.
- `--csv` on `devices` (ip, mac, vendor, flags, hostname) and `--quiet`
  global flag for cron/dashboard use.
- SECURITY.md, CONTRIBUTING.md, issue/PR templates, ROADMAP.md.
- README: support matrix up top, explicit "does not do" section, cron
  example.

## v2.0.3

Fixes from real-world runs:

- `iw scan` parser no longer treats `BSS Load:` / `BSS Color:` IE lines
  as access points (they produced phantom "hidden" networks and a false
  evil-twin critical).
- Evil-twin check skips hidden SSIDs — there is nothing meaningful to
  compare.
- `ip neigh` fallback parsing fixed; device inventory now works without
  scapy (a quick connect sweep primes the kernel ARP table first).
- First run with real data is a history baseline, not a diff — no more
  "everything is new" penalties.
- Clearer error when scapy is installed per-user but the tool is run
  under sudo.
- Latent crash when the connected SSID isn't among the visible APs.

## v2.0.2

- Replaced a real-user SSID that had slipped into a test fixture with a
  generic one.

## v2.0.1

Fixes from a live audit on a minimal Linux box:

- Managed-mode scan falls back to `iw dev <iface> scan` when nmcli is
  absent; stdlib parser for its output (SSID/BSSID/freq/signal/RSN/WPA).
- Channel and encryption resolved via `iw link` freq, interface info, and
  a one-off scan matched to the connected BSSID.
- scapy-less ARP fallback for Windows (`arp -a`) and an ARP-priming
  connect sweep on Linux.

## v2.0.0

- Rogue-DHCP detection from local lease files.
- Exposed-service scan (26 curated ports, banner grabbing) on your own
  devices.
- Cross-run history: new/gone APs and devices since the last run.
- HTML report export (`--html`), self-contained and offline-safe.
- Desktop notifications in watch mode (`--notify`).
- Config file at `~/.sentinelwifi/config.json` (intervals, trusted
  BSSIDs, toggles).
- Windows support for connection details and gateway detection.
- `demo` and `selftest` commands.
- 30+ unit tests and GitHub Actions CI.

## v1.0.0

Initial release: connection audit, passive AP scan with evil-twin
detection and congestion analysis, ARP device inventory with newcomer
tracking, A–F grading, rich/JSON reports, watch mode.
