# fritzos8-mcp als Container (stdio oder Streamable HTTP mit Pflicht-Token).
#
#   docker build -t fritzos8-mcp .          # bzw. veröffentlicht: ghcr.io/tomwellnitz/fritzos8-mcp (amd64 + arm64)
#   # stdio (der MCP-Client startet den Container):
#   docker run -i --rm -e FRITZ_HOST=fritz.box -e FRITZ_USER=mcp \
#     -e FRITZ_PASSWORD_FILE=/run/secrets/fritz -v ~/.config/fritzos8/pw:/run/secrets/fritz:ro fritzos8-mcp
#   # HTTP (nur im Heimnetz/VPN, Token Pflicht):
#   docker run -d -p 127.0.0.1:8765:8765 -e FRITZ_TRANSPORT=http -e FRITZ_HTTP_HOST=0.0.0.0 \
#     -e FRITZ_HTTP_TOKEN_FILE=/run/secrets/token -v …/token:/run/secrets/token:ro … fritzos8-mcp
#   # Messreihe + Home Assistant (MQTT):
#   docker run -d … -e FRITZ_MQTT_HOST=… fritzos8-mcp fritzos8-collector
#
# Zugangsdaten nur als Datei/Secret oder Umgebung – nie als Argument. Zustand (Messreihe, Alarme) unter /data.
# Basis-Images sind per Digest gepinnt (Dependabot aktualisiert sie); Abhängigkeiten kommen mit Hashes aus uv.lock.
FROM ghcr.io/astral-sh/uv:0.13.9@sha256:d3b601f0c7b118bc1753febf7c41cc80981df678445e0254284eecf84db79a7d AS uv

FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b AS build
COPY --from=uv /uv /usr/local/bin/uv
WORKDIR /src
COPY pyproject.toml uv.lock README.md LICENSE NOTICE ./
COPY src ./src
RUN uv build --wheel -o /dist \
    && uv export --frozen --no-dev --extra mqtt --extra qr --no-emit-project --format requirements-txt -o /dist/requirements.txt

FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b
LABEL org.opencontainers.image.title="fritzos8-mcp" \
      org.opencontainers.image.description="MCP server for AVM FRITZ!Box with FRITZ!OS 8 – tiered write safety, read-back, redaction" \
      org.opencontainers.image.source="https://github.com/tomwellnitz/fritzos8-mcp" \
      org.opencontainers.image.documentation="https://github.com/tomwellnitz/fritzos8-mcp#readme" \
      org.opencontainers.image.licenses="MIT"
COPY --from=build /dist /dist
RUN pip install --no-cache-dir --require-hashes -r /dist/requirements.txt \
    && pip install --no-cache-dir --no-deps /dist/*.whl \
    && rm -rf /dist \
    && useradd --create-home --uid 10001 fritz && mkdir -p /data && chown fritz /data
USER fritz
ENV FRITZ_STATE_DIR=/data/state FRITZ_CACHE_DIR=/data/cache PYTHONUNBUFFERED=1
VOLUME ["/data"]
EXPOSE 8765
ENTRYPOINT []
CMD ["fritzos8-mcp"]
