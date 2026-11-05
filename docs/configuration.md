# Local configuration

SentinelWiFi reads optional settings from ~/.sentinelwifi/config.json. Invalid
values are ignored in favor of safe defaults; unknown keys are ignored for
forward compatibility. The file is written through a same-directory temporary
file and atomic replacement so readers do not see partially written JSON.

Supported settings:

| Key | Default | Accepted values |
| --- | --- | --- |
| watch_interval | 60 | Integer from 1 to 3600 seconds |
| port_scan_timeout | 0.5 | Number greater than 0 and at most 10 seconds |
| port_scan_enabled | true | Boolean |
| notify | false | Boolean |
| trusted_bssids | [] | List of six-octet colon-separated MAC addresses |
| preferred_iface | "" | Interface name shorter than 16 characters |

For headless sessions, set SENTINELWIFI_NO_NOTIFY to one of `1`,
`true`, `yes`, or `on`
(case-insensitive) to suppress desktop notifications. Values such as `0`
and `false` do not override the saved preference.

The configuration stays local. No setting sends it to a remote service.
