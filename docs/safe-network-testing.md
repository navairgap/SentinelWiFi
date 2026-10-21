# safe network testing

Run tests only against owned lab networks or systems with explicit permission. Cover absent interfaces, malformed addresses, permission errors, unreachable routers, control characters in hostnames, and report privacy. Prefer fixtures and mocked command output over live probes in CI. Ordinary unit tests should not require root. Sample reports must not contain passwords, pre-shared keys, or credential material.
