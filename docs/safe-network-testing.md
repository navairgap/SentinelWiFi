# safe network testing

Run tests only against owned lab networks or systems with explicit permission. Cover absent interfaces, malformed addresses, permission errors, unreachable routers, control characters in hostnames, and report privacy. Prefer fixtures and mocked command output over live probes in CI. Ordinary unit tests should not require root. Sample reports must not contain passwords, pre-shared keys, or credential material.

## Interface and permission cases

Run parser and configuration tests with mocked command output first. Cover an interface that disappears between discovery and scan, a command that exits non-zero, missing optional utilities, denied permissions, and output that is empty despite a successful exit status. A read-only scan must not change interface state or create network connections outside the selected target scope. Test report generation separately from live discovery so a report bug never requires a privileged scan to reproduce.
