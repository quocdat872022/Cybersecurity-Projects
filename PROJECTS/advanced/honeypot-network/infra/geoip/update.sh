#!/usr/bin/env bash
# ©AngelaMos | 2026
# update.sh — downloads GeoLite2-City and GeoLite2-ASN via MaxMind's
# permalink API and extracts the .mmdb files into the shared volume.

set -euo pipefail

DEST="${GEOIP_DEST:-/usr/share/GeoIP}"
ACCOUNT_ID="${GEOIP_ACCOUNT_ID:?GEOIP_ACCOUNT_ID is required}"
LICENSE_KEY="${GEOIP_LICENSE_KEY:?GEOIP_LICENSE_KEY is required}"

mkdir -p "$DEST"

fetch_edition() {
    local edition="$1"
    local tmp
    tmp="$(mktemp -d)"

    echo "[geoip-updater] downloading ${edition}..."
    curl -sSL -u "${ACCOUNT_ID}:${LICENSE_KEY}" \
        "https://download.maxmind.com/geoip/databases/${edition}/download?suffix=tar.gz" \
        -o "${tmp}/${edition}.tar.gz"

    tar -xzf "${tmp}/${edition}.tar.gz" -C "${tmp}"

    find "${tmp}" -name "*.mmdb" -exec mv {} "${DEST}/" \;
    rm -rf "${tmp}"
    echo "[geoip-updater] ${edition} installed to ${DEST}"
}

fetch_edition "GeoLite2-City"
fetch_edition "GeoLite2-ASN"

echo "[geoip-updater] done."