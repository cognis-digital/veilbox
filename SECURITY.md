# Security Policy

## Reporting a vulnerability

Please report security issues privately to **security@cognis.digital**. Do not
open a public issue for vulnerabilities.

We aim to acknowledge reports within 72 hours.

## Scope

`veilbox` is standard-library Python with **no third-party dependencies** and
**zero telemetry**. The only outbound network access is the opt-in `--live`
audit probe (public-IP lookup), which degrades gracefully offline.

Of particular interest:

- Any path where veilbox transmits data without explicit user action.
- Any fingerprint profile that validates as coherent but leaks in practice.
- Any audit check that reports `pass` while a real leak exists (false negative).
