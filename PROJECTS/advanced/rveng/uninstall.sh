#!/usr/bin/env bash
# ©AngelaMos | 2026
# uninstall.sh
#
# Mirror of install.sh: stop rveng, remove its containers, images, and volumes,
# and delete the cached clone the installer made. Leaves Docker itself alone.

set -euo pipefail

if [ -t 2 ] && [ -z "${NO_COLOR:-}" ]; then
    BOLD=$'\033[1m'; DIM=$'\033[2m'; RED=$'\033[31m'; GREEN=$'\033[32m'
    YELLOW=$'\033[33m'; CYAN=$'\033[36m'; RESET=$'\033[0m'
else
    BOLD=""; DIM=""; RED=""; GREEN=""; YELLOW=""; CYAN=""; RESET=""
fi

info() { printf '%s\n' "  ${CYAN}+${RESET} $*" >&2; }
ok()   { printf '%s\n' "  ${GREEN}+${RESET} $*" >&2; }
warn() { printf '%s\n' "  ${YELLOW}!${RESET} $*" >&2; }
have() { command -v "$1" >/dev/null 2>&1; }

find_project() {
    if [ -f "./compose.yml" ] && [ -f "./infra/docker/api.dockerfile" ]; then
        pwd; return
    fi
    local self="${BASH_SOURCE[0]:-}"
    if [ -n "$self" ] && [ -f "$(dirname "$self")/compose.yml" ]; then
        (cd "$(dirname "$self")" && pwd); return
    fi
    local cache="${XDG_CACHE_HOME:-$HOME/.cache}/rveng-src/PROJECTS/advanced/rveng"
    [ -f "$cache/compose.yml" ] && printf '%s\n' "$cache"
}

printf '\n%s\n\n' "${BOLD}${CYAN}--- removing rveng ---${RESET}" >&2

if have docker; then
    PROJECT="$(find_project || true)"
    if [ -n "${PROJECT:-}" ] && [ -d "$PROJECT" ]; then
        info "stopping stacks in $PROJECT"
        ( cd "$PROJECT" && docker compose down -v --remove-orphans 2>/dev/null || true )
        ( cd "$PROJECT" && docker compose -f dev.compose.yml down -v --remove-orphans 2>/dev/null || true )
        ok "containers and volumes removed"
    else
        warn "could not find the project dir; skipping compose down"
    fi
else
    warn "docker not found; nothing to stop"
fi

CACHE="${XDG_CACHE_HOME:-$HOME/.cache}/rveng-src"
if [ -d "$CACHE" ]; then
    info "removing cached clone at $CACHE"
    rm -rf "$CACHE"
    ok "cache removed"
fi

printf '\n%s\n\n' "  ${GREEN}${BOLD}rveng removed.${RESET}" >&2
printf '%s\n' "  ${DIM}Docker itself was left installed.${RESET}" >&2
