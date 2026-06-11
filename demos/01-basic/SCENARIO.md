# Demo 01 — coherent fingerprint + a leak caught

This demo shows the two things that make `veilbox` different from cheap
anti-detect tools:

1. **Coherence.** It generates a browser/device fingerprint whose fields all
   *agree*. Mismatched fields (a macOS platform under a Windows user-agent, a
   timezone that does not match the locale's country) are themselves a rare,
   trackable signal — so a leaky spoof is worse than none.
2. **Proof.** It runs an attribution/leak self-audit and returns a
   **traceability score** with per-check evidence, so anonymity is verified,
   not asserted.

## Run it

```bash
# 1. Generate a fresh coherent identity and verify coherence
veilbox fingerprint --rotate

# 2. Reproducible identity from a seed, JSON form
veilbox fingerprint --seed demo-coherent --format json

# 3. Audit a HARDENED session — expect score 0 / ANONYMOUS
veilbox audit --signals demos/01-basic/signals-clean.json

# 4. Audit a LEAKING session — expect score 100 / FULLY-TRACEABLE,
#    five leak vectors caught (WebRTC, DNS, IP/proxy, tz/geo, fingerprint)
veilbox audit --signals demos/01-basic/signals-leaking.json --format json

# 5. CI gate: fail the build if the session is attributable
veilbox audit --signals demos/01-basic/signals-leaking.json --fail-on 25
```

## What you should see

- `signals-clean.json` → **TRACEABILITY SCORE: 0/100 — ANONYMOUS**.
- `signals-leaking.json` → **TRACEABILITY SCORE: 100/100 — FULLY-TRACEABLE**,
  with all five checks flagged. The fingerprint check specifically catches the
  Windows user-agent paired with a `MacIntel` platform.

## Files

- `signals-clean.json` — a coherent, fully-tunneled session.
- `signals-leaking.json` — the same session with real-world leaks introduced.

> The credentials in the proxy/DNS templates are obvious placeholders
> (`USER_PLACEHOLDER`, `PLACEHOLDER_ID`) — never real secrets.
