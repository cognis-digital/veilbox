FROM python:3.12-slim
LABEL org.opencontainers.image.title="cognis-veilbox"
LABEL org.opencontainers.image.vendor="Cognis Digital"
LABEL org.opencontainers.image.source="https://github.com/cognis-digital/veilbox"
LABEL org.opencontainers.image.description="Self-hosted, zero-telemetry anti-fingerprint privacy container with a built-in leak self-audit"
LABEL org.opencontainers.image.licenses="LicenseRef-COCL-1.0"

# Minimal runtime tools for the proxy chain + DoH resolver. The Python core is
# stdlib-only; these are only for the *container* networking layer.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates iproute2 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /work
COPY . .
RUN pip install --no-cache-dir -e .

# Run as a non-root, unprivileged user. The container is ephemeral.
RUN useradd --create-home --uid 10001 veil
USER veil

# Zero telemetry: nothing in this image phones home.
ENV VEILBOX_TELEMETRY=off \
    VEILBOX_CONFIG=/work/config/veilbox.yaml

ENTRYPOINT ["/work/docker/entrypoint.sh"]
CMD ["audit", "--live"]
