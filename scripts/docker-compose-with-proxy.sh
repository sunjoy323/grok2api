#!/usr/bin/env bash
# Run docker compose with host local proxy for image pull + build-time downloads.
#
# Usage:
#   ./scripts/docker-compose-with-proxy.sh build
#   ./scripts/docker-compose-with-proxy.sh up -d --build
#   ./scripts/docker-compose-with-proxy.sh logs -f
#
# Env overrides:
#   HOST_PROXY      Proxy for docker CLI / daemon on the host (default: http://127.0.0.1:10808)
#   BUILD_PROXY     Proxy visible inside build containers (default: http://host.docker.internal:10808)
#   NO_PROXY        Comma-separated bypass list
#   SKIP_PROXY_CHECK=1  Skip connectivity probe

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

HOST_PROXY="${HOST_PROXY:-http://127.0.0.1:10808}"
# Build containers cannot use 127.0.0.1 of the host; Docker Desktop provides this DNS name.
BUILD_PROXY="${BUILD_PROXY:-http://host.docker.internal:10808}"
NO_PROXY="${NO_PROXY:-localhost,127.0.0.1,host.docker.internal,.local,grok2api}"

export HTTP_PROXY="$HOST_PROXY"
export HTTPS_PROXY="$HOST_PROXY"
export http_proxy="$HOST_PROXY"
export https_proxy="$HOST_PROXY"
export ALL_PROXY="${ALL_PROXY:-$HOST_PROXY}"
export all_proxy="${all_proxy:-$HOST_PROXY}"
export NO_PROXY
export no_proxy="$NO_PROXY"

# Consumed by docker-compose.yml build.args (must be host.docker.internal for RUN steps).
export BUILD_HTTP_PROXY="$BUILD_PROXY"
export BUILD_HTTPS_PROXY="$BUILD_PROXY"
export BUILD_NO_PROXY="$NO_PROXY"

export DOCKER_BUILDKIT=1
export COMPOSE_DOCKER_CLI_BUILD=1

if [[ "${SKIP_PROXY_CHECK:-0}" != "1" ]]; then
  if ! curl -fsS --connect-timeout 3 -x "$HOST_PROXY" -o /dev/null -w "" https://pypi.org >/dev/null 2>&1 \
    && ! curl -fsS --connect-timeout 3 -x "$HOST_PROXY" -o /dev/null -w "" http://pypi.org >/dev/null 2>&1; then
    # Some proxies return non-2xx to probe URLs but still tunnel CONNECT — try a simple TCP check.
    if ! curl -sS --connect-timeout 2 -o /dev/null -w "" -x "$HOST_PROXY" https://1.1.1.1 >/dev/null 2>&1; then
      echo "[proxy] WARN: cannot reach network via $HOST_PROXY — build may still work if proxy only allows some hosts" >&2
    fi
  else
    echo "[proxy] host OK: $HOST_PROXY"
  fi
fi

echo "[proxy] host  HTTP(S)_PROXY=$HOST_PROXY"
echo "[proxy] build HTTP(S)_PROXY=$BUILD_PROXY"
echo "[proxy] NO_PROXY=$NO_PROXY"
echo "[proxy] docker compose $*"

exec docker compose "$@"
