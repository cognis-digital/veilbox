#!/usr/bin/env sh
# veilbox container entrypoint.
#
# Brings up the privacy egress layer (proxy chain + NextDNS over DoH) from
# env/yaml, then hands control to the `veilbox` CLI. ZERO TELEMETRY: this
# script never transmits anything outbound except through the configured chain.
#
# ETHICS: privacy/OPSEC/authorized research only — not for fraud or unlawful
# evasion.
set -eu

CONFIG="${VEILBOX_CONFIG:-/work/config/veilbox.yaml}"
NEXTDNS_PROFILE_ID="${NEXTDNS_PROFILE_ID:-PLACEHOLDER_ID}"
PROXY_CHAIN="${PROXY_CHAIN:-}"

log() { printf '[veilbox] %s\n' "$1" >&2; }

log "telemetry: ${VEILBOX_TELEMETRY:-off} (no callbacks, ever)"

# 1. Emit the effective DoH + proxy config so the run is auditable. These are
#    rendered by the stdlib core; placeholders unless you supply real ids.
log "rendering NextDNS DoH config (profile id: ${NEXTDNS_PROFILE_ID})"
veilbox dns --profile-id "${NEXTDNS_PROFILE_ID}" --format yaml || true

if [ -n "${PROXY_CHAIN}" ]; then
    log "proxy chain configured from \$PROXY_CHAIN"
    # shellcheck disable=SC2086
    veilbox proxy --hop ${PROXY_CHAIN} --format yaml || true
else
    log "no \$PROXY_CHAIN set — emitting placeholder chain"
    veilbox proxy --format yaml || true
fi

# 2. NOTE: actual kernel-level routing (DoH resolver + chained proxy + egress
#    kill-switch) is wired by your container runtime / sidecar. The image ships
#    iproute2 + ca-certificates so a sidecar can enforce it. veilbox itself
#    never opens a direct route around the tunnel.

# 3. Hand off to the CLI with whatever args the container was given.
log "starting: veilbox $*"
exec veilbox "$@"
