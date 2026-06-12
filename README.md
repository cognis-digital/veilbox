# veilbox — self-hosted, zero-telemetry anti-fingerprint privacy container

> Part of the **[Cognis Neural Suite](https://github.com/cognis-digital)** by [Cognis Digital](https://cognis.digital)
> Cognis Open Collaboration License (COCL) v1.0 · domain: `privacy`

[![PyPI](https://img.shields.io/pypi/v/cognis-veilbox.svg)](https://pypi.org/project/cognis-veilbox/)
[![CI](https://github.com/cognis-digital/veilbox/actions/workflows/ci.yml/badge.svg)](https://github.com/cognis-digital/veilbox/actions)
[![License: COCL 1.0](https://img.shields.io/badge/License-COCL%201.0-2b6cb0.svg)](LICENSE)
[![Suite](https://img.shields.io/badge/Cognis-Neural%20Suite-6b46c1.svg)](https://github.com/cognis-digital)

**Anti-detect that doesn't phone home — and proves your anonymity with a built-in leak audit.**

`veilbox` is a self-hosted privacy-hardening **container + toolkit**: an
ephemeral, headless container that routes through a configurable proxy chain and
NextDNS over DoH, plus a verifiable, **standard-library-only** Python tool that
(1) generates *internally-consistent* browser fingerprints and (2) runs an
attribution/leak self-audit that scores how traceable you actually are.

> ## ⚖️ Ethics / Acceptable Use
> For **privacy protection, OPSEC, anti-tracking, and AUTHORIZED security
> research only** — **NOT** for fraud, evading fraud-detection, or unlawful
> evasion. See [ETHICS.md](ETHICS.md). By using veilbox you agree to use it
> lawfully and only on systems you own or are authorized to test.

## Why it's different

Most "anti-detect" tools **leak via mismatched fields** — a macOS user-agent
over a Windows `navigator.platform`, a timezone that doesn't match the locale's
country, fonts that can't exist on the claimed OS. Those mismatches are *rarer*
than the truth, so they make you **more** trackable, not less.

veilbox optimizes for the opposite:

1. **Coherence.** Every generated fingerprint is **internally consistent** and
   machine-validated — all fields agree.
2. **Proof.** A built-in **leak self-audit** returns a **traceability score
   (0–100)** with per-check evidence, so anonymity is *verified*, not asserted.
3. **Zero telemetry.** Nothing phones home. The only network call is the opt-in
   `--live` audit probe, and it degrades gracefully offline.

## Install

```bash
pip install cognis-veilbox
# or, from this repo:
pip install -e ".[dev]"
```

No third-party dependencies — Python 3.10+ standard library only.

## Quick start

```bash
veilbox --version

# Generate a fresh, coherent identity (and validate it)
veilbox fingerprint --rotate

# Reproducible identity from a seed; pin OS/browser/locale (coherence enforced)
veilbox fingerprint --seed alpha --os macos --browser safari --locale en-GB --format json

# Just check coherence (exit 1 if anything disagrees)
veilbox fingerprint --seed alpha --validate-only

# Emit egress config (templated, placeholder ids — supply your own)
veilbox dns --profile-id PLACEHOLDER_ID
veilbox proxy --hop socks5://a.example:1080 --hop https://b.example:8443

# THE STANDOUT: prove your anonymity
veilbox audit --signals demos/01-basic/signals-clean.json      # => score 0, ANONYMOUS
veilbox audit --signals demos/01-basic/signals-leaking.json    # => score 100, 5 leaks
veilbox audit --live --format sarif --out audit.sarif          # CI-friendly
veilbox audit --signals session.json --fail-on 25              # gate a pipeline

# Run as an MCP server (Cognis.Studio / Claude Desktop / Cursor)
veilbox mcp
```

## The leak self-audit

`veilbox audit` evaluates eight attribution vectors and rolls them into a single
**traceability score** (lower = more anonymous). Missing signals are *skipped*,
not penalized, so an offline audit is still meaningful.

| Check | Weight | Catches |
|-------|-------:|---------|
| `webrtc_leak` | 30 | A routable/public IP exposed via WebRTC outside the tunnel |
| `dns_leak` | 25 | Queries resolved by anything other than the expected DoH endpoint |
| `ip_proxy_mismatch` | 20 | Public IP ≠ proxy exit node (egress bypassing the tunnel) |
| `tz_geo_mismatch` | 15 | Browser timezone inconsistent with the exit IP's country |
| `client_hint_consistency` | 12 | UA OS token disagrees with the TLS/HTTP2 Client-Hint platform (`Sec-CH-UA-Platform`) — only half the identity was spoofed |
| `navigator_coherence` | 12 | `navigator.plugins`/`mediaDevices`/touch contradict the declared platform (plugins on Firefox/mobile, touch on desktop, labelled devices without permission) |
| `fingerprint_coherence` | 10 | Fingerprint fields that contradict each other |
| `font_entropy` | 10 | Enumerated fonts native to a *different* OS, or a set so large it is a near-unique key |

Output formats: `table` (default), `json`, `sarif`.

### Signals schema

`audit` reads a JSON object of observed signals (all keys optional):

```json
{
  "public_ip": "198.51.100.7",
  "proxy_exit_ip": "198.51.100.7",
  "webrtc_local_ips": ["10.0.0.5"],
  "dns_resolvers": ["45.90.28.0"],
  "expected_resolvers": ["45.90.28.0", "45.90.30.0"],
  "timezone": "Australia/Sydney",
  "ip_geo_country": "AU",
  "profile": { "...a veilbox fingerprint profile..." },

  "user_agent": "Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
  "ua_platform": "\"Linux\"",
  "fonts": ["DejaVu Sans", "Ubuntu"],
  "declared_platform": "linux",
  "browser": "firefox",
  "touch_support": false,
  "navigator_plugins": [],
  "media_devices": [{"kind": "videoinput", "label": ""}]
}
```

`--live` fills gaps with best-effort, stdlib-only collection (public IP, local
address). True WebRTC/canvas probing needs a browser-side collector; veilbox
never fabricates a `pass`.

## The container

```bash
# Build + run the ephemeral, read-only, capability-dropped container.
docker compose up --build
```

- Ephemeral, headless, **non-root**, `read_only` root filesystem, all Linux
  capabilities dropped, `no-new-privileges`.
- **Isolated network namespace** (`internal: true`) — no route to the host LAN.
- Egress is meant to flow through your **proxy chain + NextDNS DoH**, supplied
  via `.env` / `config/veilbox.yaml` (copy `config/veilbox.example.yaml`).
- `entrypoint.sh` renders the effective DoH + proxy config (auditable) then runs
  the CLI. Default command runs the leak audit.

> The container ships `iproute2` + `ca-certificates` so a sidecar can enforce
> kernel-level routing and a kill-switch. veilbox itself never opens a direct
> route around the tunnel and never transmits telemetry.

## Demo

See [`demos/01-basic`](demos/01-basic/SCENARIO.md): a coherent profile, a clean
session scoring **0 / ANONYMOUS**, and a leaking session scoring **100 /
FULLY-TRACEABLE** with all five vectors caught (including a Windows user-agent
paired with a `MacIntel` platform).

## MCP server

veilbox speaks newline-delimited JSON-RPC 2.0 over stdio with **no SDK
required**. Wire it into an agent:

```json
{ "command": "python", "args": ["-m", "veilbox", "mcp"] }
```

Tools: `generate_fingerprint`, `audit_signals`.

## Configuration

`config/veilbox.example.yaml` documents every option (DNS provider, proxy chain,
fingerprint pinning, audit gate). All credentials in examples are **obvious
placeholders**. Never commit `config/veilbox.yaml` or `.env` (both are
gitignored).

## License

Cognis Open Collaboration License (COCL) v1.0 — see [LICENSE](LICENSE) and
[NOTICE](NOTICE). Non-commercial use is free; commercial use:
`licensing@cognis.digital`.
