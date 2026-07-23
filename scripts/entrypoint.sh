#!/usr/bin/env sh
set -eu

# When started as root (default image user before drop), fix volume ownership
# then re-exec as the unprivileged app user.
if [ "$(id -u)" = "0" ]; then
  DATA_DIR="${DATA_DIR:-/app/data}"
  LOG_DIR="${LOG_DIR:-/app/logs}"
  mkdir -p "$DATA_DIR" "$LOG_DIR"

  # Bind mounts / NFS often reject chown; surface that instead of silent fail.
  if ! chown -R app:app "$DATA_DIR" "$LOG_DIR" 2>/tmp/grok2api-chown.err; then
    echo "[entrypoint] WARN: chown app:app failed for $DATA_DIR / $LOG_DIR" >&2
    if [ -s /tmp/grok2api-chown.err ]; then
      sed 's/^/[entrypoint] WARN: /' /tmp/grok2api-chown.err >&2 || true
    fi
    echo "[entrypoint] WARN: ensure the host path is writable by uid=1000 gid=1000" >&2
    echo "[entrypoint] WARN: e.g.  sudo chown -R 1000:1000 ./data ./logs" >&2
  fi
  rm -f /tmp/grok2api-chown.err 2>/dev/null || true
  exec su-exec app "$0" "$@"
fi

DATA_DIR="${DATA_DIR:-/app/data}"
LOG_DIR="${LOG_DIR:-/app/logs}"
mkdir -p "$DATA_DIR" "$LOG_DIR"

# Fail fast with an actionable message when the data volume is not writable.
# SQLite surfaces the same problem later as: OperationalError: disk I/O error.
_probe="$DATA_DIR/.write_probe.$$"
if ! ( umask 077; : >"$_probe" ) 2>/tmp/grok2api-write.err; then
  echo "[entrypoint] ERROR: cannot write to DATA_DIR=$DATA_DIR (uid=$(id -u) gid=$(id -g))" >&2
  if [ -s /tmp/grok2api-write.err ]; then
    sed 's/^/[entrypoint] ERROR: /' /tmp/grok2api-write.err >&2 || true
  fi
  ls -lad "$DATA_DIR" "$LOG_DIR" 2>&1 | sed 's/^/[entrypoint] ERROR: /' >&2 || true
  echo "[entrypoint] ERROR: fix host volume permissions, then restart:" >&2
  echo "[entrypoint] ERROR:   sudo mkdir -p ./data ./logs && sudo chown -R 1000:1000 ./data ./logs" >&2
  echo "[entrypoint] ERROR: on SELinux hosts you may also need:  chcon -Rt svirt_sandbox_file_t ./data ./logs" >&2
  echo "[entrypoint] ERROR: avoid NFS/CIFS for SQLite if possible; use a local ext4/xfs path." >&2
  rm -f /tmp/grok2api-write.err 2>/dev/null || true
  exit 1
fi
rm -f "$_probe" /tmp/grok2api-write.err 2>/dev/null || true

/app/scripts/init_storage.sh

exec "$@"
