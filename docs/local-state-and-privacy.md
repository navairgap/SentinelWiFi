# Local state and privacy boundaries

SentinelWiFi keeps its configuration and inventory history on the machine where it runs. The data is useful for comparing scans, but it can still reveal details about a private network. Treat the state directory and exported reports as local security data rather than public diagnostics.

## Files and purpose

| File | Purpose | Data retained |
| --- | --- | --- |
| `~/.sentinelwifi/config.json` | User overrides | Preferred interface, scan timing, notification preference, trusted BSSIDs, and port-scan settings |
| `~/.sentinelwifi/history.json` | Cross-run comparison | Observed access-point BSSIDs/SSIDs and device MAC/IP mappings from the latest snapshot |
| `~/.sentinelwifi/known_devices.json` | New-device detection | Previously observed MAC addresses |

The configuration loader ignores unknown keys and invalid values, retaining defaults for those settings. Saving configuration writes a complete merged settings object through a same-directory temporary file and atomic replacement. History is a snapshot, not a packet capture; it is not intended to retain traffic payloads.

## Handling guidance

- Do not attach the state directory or a full scan report to a public issue without reviewing and redacting network names, MAC addresses, IP addresses, and interface names.
- Back up the directory only to a location with access controls appropriate for local network inventory.
- Remove the directory when the history is no longer needed. Deleting it resets the local baseline; it does not change router or device configuration.
- Keep trusted BSSID entries limited to access points the operator has independently identified. A trusted entry suppresses a finding; it does not authenticate an access point.
- Use synthetic addresses and names in tests and documentation examples.

## Diagnostic reports

A report describes observations available to the current process and may be incomplete when an adapter, permission, or platform feature is unavailable. Preserve the limitation messages when sharing a report; do not present a partial inventory as a complete proof that no other device is present.
