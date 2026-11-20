ARG BUILD_FROM
FROM ${BUILD_FROM}
# Installiert die veröffentlichte Version von PyPI (vorher: Repo/PyPI-Freigabe durch den Maintainer).
# Die Version pflegt release-please (Marker nicht entfernen).
# x-release-please-start-version
ARG FRITZOS8_MCP_VERSION=0.6.0
# x-release-please-end
RUN apk add --no-cache python3 py3-pip \
    && pip3 install --no-cache-dir --break-system-packages "fritzos8-mcp[mqtt]==${FRITZOS8_MCP_VERSION}"
COPY run.sh /run.sh
RUN chmod a+x /run.sh
CMD ["/run.sh"]
