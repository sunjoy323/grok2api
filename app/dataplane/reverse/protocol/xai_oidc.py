"""xAI OIDC helpers for Grok CLI chat proxy.

SSO cookie (grok.com / accounts.x.ai) → device-flow OIDC access_token,
compatible with cli-chat-proxy.grok.com (same approach as HM2899/grokcli-2api).
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import queue as _queue
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from app.platform.errors import UpstreamError
from app.platform.logging.logger import logger

OIDC_ISSUER = "https://auth.x.ai"
GROK_CLI_CLIENT_ID = "b1a00492-073a-47ea-816f-4c329264a828"
OIDC_SCOPES = (
    "openid profile email offline_access grok-cli:access api:access "
    "conversations:read conversations:write"
)
OIDC_DEVICE_URL = f"{OIDC_ISSUER}/oauth2/device/code"
OIDC_TOKEN_URL = f"{OIDC_ISSUER}/oauth2/token"

# Process-local cache: sso_token → oidc credential dict
_OIDC_CACHE: dict[str, dict[str, Any]] = {}
_REFRESH_SKEW_S = 120.0
_DISK_LOCK = threading.Lock()
_DISK_LOADED = False
_PROXY_LOGGED = False


# Warm index: sso_sha256 of credentials still within refresh skew.
# Reverse map only when we know the full SSO string (not disk-only hash entries).
_WARM_HASHES: set[str] = set()
_HASH_TO_SSO: dict[str, str] = {}

# Per-SSO convert locks — admin import + repair worker + hot convert share these
# so concurrent device-flows cannot revoke each other's refresh tokens.
_KEY_LOCKS: dict[str, threading.Lock] = {}
_KEY_LOCKS_GUARD = threading.Lock()

def _normalize_sso(sso_token: str) -> str:
    tok = sso_token[4:] if sso_token.startswith("sso=") else sso_token
    return tok.strip()


def _env_proxy_url() -> str:
    """Prefer process env (scripts/docker exec -e HTTP_PROXY=...)."""
    for key in (
        "HTTPS_PROXY",
        "HTTP_PROXY",
        "ALL_PROXY",
        "https_proxy",
        "http_proxy",
        "all_proxy",
    ):
        val = (os.getenv(key) or "").strip()
        if val:
            return val
    return ""


def _config_proxy_url() -> str:
    """Read app proxy.egress (same source as chat traffic)."""
    try:
        from app.platform.config.snapshot import get_config

        cfg = get_config()
        mode = (cfg.get_str("proxy.egress.mode", "direct") or "direct").strip().lower()
        if mode in ("", "direct"):
            return ""
        url = (cfg.get_str("proxy.egress.proxy_url", "") or "").strip()
        if url:
            return url
        if mode == "proxy_pool":
            pool = cfg.get_list("proxy.egress.proxy_pool", []) or []
            for item in pool:
                if isinstance(item, str) and item.strip():
                    return item.strip()
    except Exception:
        return ""
    return ""


def _egress_proxy_url() -> str:
    """Resolve proxy for OIDC device-flow / token HTTP.

    Order: env → config proxy.egress → direct.
    """
    global _PROXY_LOGGED
    proxy = _env_proxy_url() or _config_proxy_url()
    if proxy and not _PROXY_LOGGED:
        _PROXY_LOGGED = True
        logger.info("oidc transport using proxy: {}", proxy.split("@")[-1])
    return proxy


def _urlopen(req: urllib.request.Request, *, timeout: float = 20.0):
    """urllib open with optional egress proxy (blocking)."""
    proxy = _egress_proxy_url()
    if not proxy:
        return urllib.request.urlopen(req, timeout=timeout)
    handler = urllib.request.ProxyHandler({"http": proxy, "https": proxy})
    opener = urllib.request.build_opener(handler)
    return opener.open(req, timeout=timeout)


def _apply_proxy_to_curl_session(session: Any) -> dict[str, Any]:
    """Attach egress proxy onto a curl_cffi Session; return extra request kwargs."""
    extra: dict[str, Any] = {}
    proxy = _egress_proxy_url()
    if not proxy:
        return extra
    try:
        from app.dataplane.proxy.adapters.session import normalize_proxy_url

        proxy = normalize_proxy_url(proxy)
    except Exception:
        pass
    scheme = proxy.split("://", 1)[0].lower() if "://" in proxy else ""
    if scheme.startswith("socks"):
        session.proxies = {"all": proxy}
    else:
        session.proxies = {"http": proxy, "https": proxy}
    try:
        from app.platform.config.snapshot import get_config

        if get_config().get_bool("proxy.egress.skip_ssl_verify", False):
            extra["verify"] = False
    except Exception:
        pass
    return extra


# Default on-disk cache written by scripts/sso_to_oidc.py
def _default_disk_path() -> Path:
    env = os.getenv("GROK_OIDC_AUTH_FILE", "").strip()
    if env:
        return Path(env)
    # xai_oidc.py → protocol → reverse → dataplane → app → root
    root = Path(__file__).resolve().parents[4]
    return root / "data" / "oidc_auth.json"


def sso_key(sso_token: str) -> str:
    """Stable lookup key for disk cache (sha256 of normalized SSO)."""
    return hashlib.sha256(_normalize_sso(sso_token).encode("utf-8")).hexdigest()


def _b64url_json(segment: str) -> dict[str, Any]:
    try:
        pad = "=" * (-len(segment) % 4)
        raw = base64.urlsafe_b64decode(segment + pad)
        data = json.loads(raw.decode("utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def decode_jwt_claims(token: str) -> dict[str, Any]:
    parts = token.split(".")
    if len(parts) < 2:
        return {}
    return _b64url_json(parts[1])

def _expires_at_from_token(access: str, expires_in: float | None = None) -> float:
    claims = decode_jwt_claims(access)
    exp = claims.get("exp")
    if exp is not None:
        try:
            return float(exp)
        except (TypeError, ValueError):
            pass
    if expires_in is not None:
        return time.time() + float(expires_in)
    return time.time() + 21_600.0


def _is_fresh(cred: dict[str, Any]) -> bool:
    access = cred.get("access_token") or ""
    if not access:
        return False
    exp = float(cred.get("expires_at") or 0)
    return exp > (time.time() + _REFRESH_SKEW_S)


def _get_key_lock(key: str) -> threading.Lock:
    with _KEY_LOCKS_GUARD:
        lock = _KEY_LOCKS.get(key)
        if lock is None:
            lock = threading.Lock()
            _KEY_LOCKS[key] = lock
        return lock


def _index_warm(sso_token: str, cred: dict[str, Any] | None) -> None:
    """Update warm hash index after cache put / drop."""
    key = _normalize_sso(sso_token)
    if not key:
        return
    sk = sso_key(key)
    if cred is not None and _is_fresh(cred):
        _WARM_HASHES.add(sk)
        _HASH_TO_SSO[sk] = key
    else:
        _WARM_HASHES.discard(sk)
        _HASH_TO_SSO.pop(sk, None)


def has_fresh_oidc(sso_token: str) -> bool:
    """True when cache/disk already holds a usable access_token for *sso_token*.

    Uses process memory only (after a one-time disk hydrate). Safe to call in
    account-selection loops without re-reading ``oidc_auth.json`` per token.
    """
    key = _normalize_sso(sso_token)
    if not key:
        return False
    _ensure_disk_loaded()
    sk = sso_key(key)
    for cache_key in (key, f"hash:{sk}"):
        cred = _OIDC_CACHE.get(cache_key)
        if cred and _is_fresh(cred):
            _index_warm(key, cred)
            return True
    _WARM_HASHES.discard(sk)
    return False


def any_warm_oidc() -> bool:
    """True if the process knows at least one still-fresh OIDC credential."""
    _ensure_disk_loaded()
    if not _WARM_HASHES:
        return False
    for sk in list(_WARM_HASHES):
        cred = _OIDC_CACHE.get(f"hash:{sk}")
        if cred is None:
            sso = _HASH_TO_SSO.get(sk)
            if sso:
                cred = _OIDC_CACHE.get(sso)
        if cred and _is_fresh(cred):
            return True
        _WARM_HASHES.discard(sk)
    return False


def list_warm_sso_tokens() -> list[str]:
    """Full SSO strings with warm OIDC — O(warm), for account prefer_tokens.

    Only includes tokens whose full SSO is known (used at least once or put
    via cache_put). Disk-hydrated hash-only entries appear in any_warm_oidc()
    but not here until the full SSO is observed.
    """
    _ensure_disk_loaded()
    out: list[str] = []
    for sk, sso in list(_HASH_TO_SSO.items()):
        if has_fresh_oidc(sso):
            out.append(sso)
    return out


def _drop_cred(sso_token: str) -> None:
    """Remove stale/revoked credentials from memory (and best-effort disk)."""
    key = _normalize_sso(sso_token)
    sk = sso_key(key)
    _OIDC_CACHE.pop(key, None)
    _OIDC_CACHE.pop(f"hash:{sk}", None)
    _index_warm(key, None)
    try:
        p = _default_disk_path()
        if not p.is_file():
            return
        with _DISK_LOCK:
            data = load_disk_cache(p)
            entries = data.get("entries")
            if isinstance(entries, dict) and sk in entries:
                entries.pop(sk, None)
                data["updated_at"] = time.time()
                tmp = p.with_suffix(p.suffix + ".tmp")
                tmp.write_text(
                    json.dumps(data, indent=2, ensure_ascii=False) + "\n",
                    encoding="utf-8",
                )
                tmp.replace(p)
    except Exception as exc:
        logger.warning("oidc drop disk entry failed: {}", exc)


def _request_device_code() -> dict[str, Any]:
    data = urllib.parse.urlencode(
        {"client_id": GROK_CLI_CLIENT_ID, "scope": OIDC_SCOPES}
    ).encode()
    req = urllib.request.Request(
        OIDC_DEVICE_URL,
        data=data,
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    try:
        with _urlopen(req, timeout=20) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")[:300]
        raise UpstreamError(
            f"OIDC device/code failed: {exc.code} {body}",
            status=502,
            body=body,
        ) from exc


def _poll_token(device_code: str, interval: int, expires_in: int) -> dict[str, Any]:
    """Poll token endpoint after device approval.

    Polls immediately first (approval already completed in device flow), then
    waits only on ``authorization_pending`` / ``slow_down``. The previous
    sleep-before-poll order wasted a full interval (~5s) on every convert.
    """
    deadline = time.time() + min(int(expires_in or 1800), 90)
    wait = max(1, int(interval or 5))
    last_err = "authorization_pending"
    while time.time() < deadline:
        data = urllib.parse.urlencode(
            {
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "client_id": GROK_CLI_CLIENT_ID,
                "device_code": device_code,
            }
        ).encode()
        req = urllib.request.Request(
            OIDC_TOKEN_URL,
            data=data,
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        try:
            with _urlopen(req, timeout=20) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            try:
                err = json.loads(exc.read().decode("utf-8", "replace"))
            except Exception:
                err = {}
            last_err = str(err.get("error") or exc.code)
            if last_err == "authorization_pending":
                time.sleep(wait)
                continue
            if last_err == "slow_down":
                wait += 2
                time.sleep(wait)
                continue
            raise UpstreamError(
                f"OIDC token poll failed: {last_err}",
                status=502,
                body=str(err)[:300],
            ) from exc
    raise UpstreamError(f"OIDC token poll timeout: {last_err}", status=502)


def _refresh_token(refresh_token: str) -> dict[str, Any]:
    data = urllib.parse.urlencode(
        {
            "grant_type": "refresh_token",
            "client_id": GROK_CLI_CLIENT_ID,
            "refresh_token": refresh_token,
        }
    ).encode()
    req = urllib.request.Request(
        OIDC_TOKEN_URL,
        data=data,
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    try:
        with _urlopen(req, timeout=20) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")[:300]
        raise UpstreamError(
            f"OIDC refresh failed: {exc.code} {body}",
            status=401,
            body=body,
        ) from exc


def _sso_device_approve(sso_token: str, device: dict[str, Any]) -> None:
    """Use SSO session cookie to approve a device code (headless)."""
    from curl_cffi import requests as crequests

    sso = _normalize_sso(sso_token)
    session = crequests.Session()
    req_extra = _apply_proxy_to_curl_session(session)
    session.cookies.set("sso", sso, domain=".x.ai")

    try:
        probe = session.get(
            "https://accounts.x.ai/", impersonate="chrome", timeout=20, **req_extra
        )
    except Exception as exc:
        raise UpstreamError(f"OIDC SSO probe failed: {exc}", status=502) from exc
    if "sign-in" in (probe.url or "") or "sign-up" in (probe.url or ""):
        raise UpstreamError("SSO cookie invalid for OIDC conversion", status=401)

    user_code = device.get("user_code") or ""
    verify_uri = device.get("verification_uri_complete") or ""
    if not user_code or not verify_uri:
        raise UpstreamError("OIDC device payload incomplete", status=502)

    try:
        session.get(verify_uri, impersonate="chrome", timeout=20, **req_extra)
        verify = session.post(
            f"{OIDC_ISSUER}/oauth2/device/verify",
            data={"user_code": user_code},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            impersonate="chrome",
            timeout=20,
            allow_redirects=True,
            **req_extra,
        )
        if "consent" not in (verify.url or ""):
            raise UpstreamError(
                f"OIDC device verify failed: {verify.url}",
                status=502,
            )
        approve = session.post(
            f"{OIDC_ISSUER}/oauth2/device/approve",
            data={
                "user_code": user_code,
                "action": "allow",
                "principal_type": "User",
                "principal_id": "",
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            impersonate="chrome",
            timeout=20,
            allow_redirects=True,
            **req_extra,
        )
        if "done" not in (approve.url or ""):
            raise UpstreamError(
                f"OIDC device approve failed: {approve.url}",
                status=502,
            )
    except UpstreamError:
        raise
    except Exception as exc:
        raise UpstreamError(f"OIDC device approve transport failed: {exc}", status=502) from exc


def _token_response_to_cred(token_data: dict[str, Any], *, previous: dict[str, Any] | None = None) -> dict[str, Any]:
    access = token_data.get("access_token") or token_data.get("key")
    if not access or not isinstance(access, str):
        raise UpstreamError("OIDC response missing access_token", status=502)
    refresh = token_data.get("refresh_token") or (previous or {}).get("refresh_token") or ""
    expires_in = token_data.get("expires_in")
    try:
        expires_in_f = float(expires_in) if expires_in is not None else None
    except (TypeError, ValueError):
        expires_in_f = None
    claims = decode_jwt_claims(access)
    return {
        "access_token": access,
        "refresh_token": refresh if isinstance(refresh, str) else "",
        "expires_at": _expires_at_from_token(access, expires_in_f),
        "user_id": claims.get("principal_id") or claims.get("sub") or "",
        "team_id": claims.get("team_id") or "",
        "scope": claims.get("scope") or token_data.get("scope") or "",
    }


def sso_to_oidc(sso_token: str) -> dict[str, Any]:
    """Convert SSO cookie to OIDC access/refresh credentials (blocking)."""
    device = _request_device_code()
    _sso_device_approve(sso_token, device)
    token_data = _poll_token(
        str(device.get("device_code") or ""),
        int(device.get("interval") or 5),
        int(device.get("expires_in") or 1800),
    )
    cred = _token_response_to_cred(token_data)
    logger.info(
        "oidc converted from sso: user_id={} team_id={} expires_in≈{}",
        str(cred.get("user_id") or "")[:12],
        str(cred.get("team_id") or "")[:12],
        int(float(cred["expires_at"]) - time.time()),
    )
    return cred


def refresh_oidc(cred: dict[str, Any]) -> dict[str, Any]:
    refresh = cred.get("refresh_token") or ""
    if not refresh:
        raise UpstreamError("OIDC refresh_token missing", status=401)
    token_data = _refresh_token(refresh)
    return _token_response_to_cred(token_data, previous=cred)


def load_disk_cache(path: Path | None = None) -> dict[str, Any]:
    """Load oidc_auth.json → {"entries": {sso_sha256: cred}}."""
    p = path or _default_disk_path()
    if not p.is_file():
        return {"version": 1, "entries": {}}
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            return {"version": 1, "entries": {}}
        entries = raw.get("entries")
        if not isinstance(entries, dict):
            raw["entries"] = {}
        return raw
    except Exception:
        return {"version": 1, "entries": {}}


def save_disk_entry(
    sso_token: str,
    cred: dict[str, Any],
    *,
    path: Path | None = None,
) -> Path:
    """Upsert one OIDC credential into data/oidc_auth.json."""
    p = path or _default_disk_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    with _DISK_LOCK:
        data = load_disk_cache(p)
        entries = data.setdefault("entries", {})
        if not isinstance(entries, dict):
            entries = {}
            data["entries"] = entries
        sk = sso_key(sso_token)
        entries[sk] = {
            "access_token": cred.get("access_token"),
            "refresh_token": cred.get("refresh_token"),
            "expires_at": cred.get("expires_at"),
            "user_id": cred.get("user_id"),
            "team_id": cred.get("team_id"),
            "scope": cred.get("scope"),
            "sso_prefix": _normalize_sso(sso_token)[:16],
            "updated_at": time.time(),
        }
        data["version"] = 1
        data["updated_at"] = time.time()
        tmp = p.with_suffix(p.suffix + ".tmp")
        tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        tmp.replace(p)
    return p


def _ensure_disk_loaded() -> None:
    """Hydrate process cache from disk once per process."""
    global _DISK_LOADED
    if _DISK_LOADED:
        return
    with _DISK_LOCK:
        if _DISK_LOADED:
            return
        data = load_disk_cache()
        entries = data.get("entries") or {}
        # Disk is keyed by sha256; runtime resolve needs SSO→cred.
        # We keep a reverse index by sso_prefix is insufficient; store
        # shadow map keyed by hash under a special prefix.
        for sk, cred in entries.items():
            if not isinstance(sk, str) or not isinstance(cred, dict):
                continue
            if not cred.get("access_token"):
                continue
            _OIDC_CACHE[f"hash:{sk}"] = cred
            if _is_fresh(cred):
                _WARM_HASHES.add(sk)
        _DISK_LOADED = True


def _lookup_disk_for_sso(sso_token: str) -> dict[str, Any] | None:
    _ensure_disk_loaded()
    sk = sso_key(sso_token)
    # Prefer hash-prefixed in-memory mirror
    cred = _OIDC_CACHE.get(f"hash:{sk}")
    if cred:
        return cred
    # Reload single entry from disk (handles concurrent script writes)
    data = load_disk_cache()
    entry = (data.get("entries") or {}).get(sk)
    if isinstance(entry, dict) and entry.get("access_token"):
        _OIDC_CACHE[f"hash:{sk}"] = entry
        if _is_fresh(entry):
            _WARM_HASHES.add(sk)
        return entry
    return None


# ---------------------------------------------------------------------------
# Shared exclusive convert (admin import + repair + hot last-resort)
# ---------------------------------------------------------------------------

_REPAIR_Q: _queue.Queue[str] = _queue.Queue()
_REPAIR_PENDING: set[str] = set()
_REPAIR_LOCK = threading.Lock()
_REPAIR_THREAD: threading.Thread | None = None
_REPAIR_PACE_S = 1.0


def convert_oidc_one(sso_token: str) -> tuple[str, str | None]:
    """Blocking SSO→OIDC under a per-token lock (shared by all convert paths).

    Returns ``(status, error)`` where status is:
      ``ok`` | ``skipped`` | ``rate_limited`` | ``failed``

    Concurrent callers for the same SSO serialize; the second caller typically
    sees ``skipped`` after the first finishes, avoiding double device-flow that
    would revoke the first refresh_token.
    """
    key = _normalize_sso(sso_token)
    if not key:
        return "failed", "empty sso token"

    with _get_key_lock(key):
        if has_fresh_oidc(key):
            # Ensure reverse map / full-key cache is populated for prefer_tokens.
            disk = _lookup_disk_for_sso(key)
            if disk:
                cache_put(key, disk)
            return "skipped", None

        try:
            base = _OIDC_CACHE.get(key) or _lookup_disk_for_sso(key)
            if base and base.get("refresh_token"):
                try:
                    refreshed = refresh_oidc(base)
                    cache_put(key, refreshed)
                    try:
                        save_disk_entry(key, refreshed)
                    except Exception as exc:
                        logger.warning("oidc disk save after refresh failed: {}", exc)
                    _BG_INVALID_GRANT.discard(sso_key(key))
                    return "ok", None
                except UpstreamError as exc:
                    detail = f"{exc} {(exc.details or {}).get('body', '')}"
                    logger.warning(
                        "oidc refresh failed in convert_oidc_one: token={}... error={}",
                        key[:10],
                        exc,
                    )
                    if "invalid_grant" in detail or "revoked" in detail.lower():
                        _drop_cred(key)
                    # Fall through to full device convert.

            cred = sso_to_oidc(key)
            cache_put(key, cred)
            try:
                save_disk_entry(key, cred)
            except Exception as exc:
                logger.warning("oidc disk save after convert failed: {}", exc)
            # Successful convert (or refresh above) revives bg-refresh eligibility.
            _BG_INVALID_GRANT.discard(sso_key(key))
            return "ok", None
        except UpstreamError as exc:
            msg = str(exc)
            if "rate_limited" in msg or "slow_down" in msg or "429" in msg:
                return "rate_limited", msg
            return "failed", msg
        except Exception as exc:  # noqa: BLE001
            return "failed", f"{type(exc).__name__}: {exc}"


def schedule_oidc_repair(sso_token: str) -> bool:
    """Enqueue a non-blocking full device-flow convert for *sso_token*.

    Returns True when the token was newly queued. Deduplicates in-flight work.
    Uses the same :func:`convert_oidc_one` path as admin import (per-key lock).
    """
    key = _normalize_sso(sso_token)
    if not key:
        return False
    try:
        if has_fresh_oidc(key):
            return False
    except Exception:
        pass
    with _REPAIR_LOCK:
        if key in _REPAIR_PENDING:
            return False
        _REPAIR_PENDING.add(key)
        _REPAIR_Q.put(key)
        _ensure_repair_worker()
    logger.info("oidc repair enqueued: token={}... queue≈{}", key[:10], _REPAIR_Q.qsize())
    return True


def _ensure_repair_worker() -> None:
    global _REPAIR_THREAD
    t = _REPAIR_THREAD
    if t is not None and t.is_alive():
        return
    worker = threading.Thread(
        target=_repair_worker_loop,
        name="oidc-repair",
        daemon=True,
    )
    _REPAIR_THREAD = worker
    worker.start()


def _repair_worker_loop() -> None:
    while True:
        try:
            key = _REPAIR_Q.get(timeout=120.0)
        except _queue.Empty:
            with _REPAIR_LOCK:
                if _REPAIR_Q.empty() and not _REPAIR_PENDING:
                    global _REPAIR_THREAD
                    _REPAIR_THREAD = None
                    return
            continue
        requeue = False
        try:
            t0 = time.time()
            status, err = convert_oidc_one(key)
            if status in ("ok", "skipped"):
                logger.info(
                    "oidc repair done: token={}... status={} elapsed_ms={}",
                    key[:10],
                    status,
                    int((time.time() - t0) * 1000),
                )
            elif status == "rate_limited":
                requeue = True
                logger.warning(
                    "oidc repair rate_limited: token={}... error={}",
                    key[:10],
                    (err or "")[:160],
                )
                time.sleep(max(_REPAIR_PACE_S, 5.0))
            else:
                logger.warning(
                    "oidc repair failed: token={}... error={}",
                    key[:10],
                    (err or "")[:200],
                )
        except Exception as exc:
            logger.warning(
                "oidc repair failed: token={}... error={}",
                key[:10],
                exc,
            )
        finally:
            with _REPAIR_LOCK:
                _REPAIR_PENDING.discard(key)
                if requeue and key not in _REPAIR_PENDING:
                    _REPAIR_PENDING.add(key)
                    _REPAIR_Q.put(key)
            time.sleep(_REPAIR_PACE_S)


def resolve_oidc_access_token(
    sso_token: str,
    *,
    allow_convert: bool = True,
    schedule_repair: bool = True,
) -> str:
    """Return a usable OIDC access_token for *sso_token*.

    Resolution order:
      1. Fresh in-memory / disk access_token
      2. refresh_token grant (fast HTTP)
      3. Full SSO device-flow convert — only when *allow_convert* is True

    Chat hot paths should pass ``allow_convert=False`` so a revoked refresh
    token does not block the request for ~10s. Misses are repaired in the
    background via :func:`schedule_oidc_repair`.
    """
    key = _normalize_sso(sso_token)
    t0 = time.time()

    cached = _OIDC_CACHE.get(key)
    if cached and _is_fresh(cached):
        _index_warm(key, cached)
        return str(cached["access_token"])

    # Disk cache from scripts/sso_to_oidc.py / prior converts
    disk_cred = _lookup_disk_for_sso(key)
    if disk_cred and _is_fresh(disk_cred):
        cache_put(key, disk_cred)
        return str(disk_cred["access_token"])

    base = cached or disk_cred
    if base and base.get("refresh_token"):
        try:
            refreshed = refresh_oidc(base)
            cache_put(key, refreshed)
            try:
                save_disk_entry(key, refreshed)
            except Exception as exc:
                logger.warning("oidc disk save after refresh failed: {}", exc)
            logger.debug(
                "oidc refresh ok: token={}... elapsed_ms={}",
                key[:10],
                int((time.time() - t0) * 1000),
            )
            return str(refreshed["access_token"])
        except UpstreamError as exc:
            logger.warning(
                "oidc refresh failed: token={}... error={}",
                key[:10],
                exc,
            )
            detail = f"{exc} {(exc.details or {}).get('body', '')}"
            if "invalid_grant" in detail or "revoked" in detail.lower():
                _drop_cred(key)

    if not allow_convert:
        if schedule_repair:
            schedule_oidc_repair(key)
        # Use 503 (not 401): account feedback maps 401 → EXPIRED and would
        # permanently kill healthy SSO accounts that merely lack a warm OIDC token.
        raise UpstreamError(
            "OIDC unavailable for account (no fresh token; convert deferred)",
            status=503,
            body="oidc_unavailable",
        )

    # Hot convert goes through the shared exclusive path (serializes w/ repair/admin).
    status, err = convert_oidc_one(key)
    if status in ("ok", "skipped"):
        access = (_OIDC_CACHE.get(key) or {}).get("access_token") or (
            (_lookup_disk_for_sso(key) or {}).get("access_token")
        )
        if access:
            logger.info(
                "oidc hot convert done: token={}... status={} elapsed_ms={}",
                key[:10],
                status,
                int((time.time() - t0) * 1000),
            )
            return str(access)
    raise UpstreamError(
        f"OIDC hot convert failed: {err or status}",
        status=502,
        body=str(err or status)[:300],
    )


def cache_put(sso_token: str, cred: dict[str, Any]) -> None:
    norm = _normalize_sso(sso_token)
    _OIDC_CACHE[norm] = cred
    _OIDC_CACHE[f"hash:{sso_key(norm)}"] = cred
    _index_warm(norm, cred)


def cache_get(sso_token: str) -> dict[str, Any] | None:
    return _OIDC_CACHE.get(_normalize_sso(sso_token))


# ---------------------------------------------------------------------------
# Background refresh-only warm-up (rotate_warm / opt-in)
# ---------------------------------------------------------------------------

_BG_REFRESH_THREAD: threading.Thread | None = None
_BG_REFRESH_STOP = threading.Event()
_BG_REFRESH_GUARD = threading.Lock()
_BG_REFRESH_CURSOR = 0
_BG_INVALID_GRANT: set[str] = set()  # sk → skip until convert succeeds
_BG_STATS = {
    "cycles": 0,
    "refreshed": 0,
    "skipped_fresh": 0,
    "skipped_no_refresh": 0,
    "failed": 0,
    "rate_limited": 0,
    "invalid_grant": 0,
}


def _bg_refresh_enabled(cfg: Any) -> bool:
    """True when selection is rotate_warm, or cli_oidc_bg_refresh is forced on."""
    try:
        if cfg.get_bool("chat.cli_oidc_bg_refresh", False):
            return True
        mode = (
            cfg.get_str("chat.cli_account_selection", "warm_prefer") or "warm_prefer"
        )
        mode = str(mode).strip().lower().replace("-", "_")
        return mode in ("rotate_warm", "rotate-warm")
    except Exception:
        return False


def _bg_refresh_settings(cfg: Any) -> dict[str, float | int]:
    return {
        "interval": max(
            30.0, float(cfg.get_float("chat.cli_oidc_bg_refresh_interval_sec", 120.0))
        ),
        "lead": max(
            300.0, float(cfg.get_float("chat.cli_oidc_bg_refresh_lead_sec", 3600.0))
        ),
        "max_per_cycle": max(
            1, min(int(cfg.get_int("chat.cli_oidc_bg_refresh_max_per_cycle", 64)), 512)
        ),
        "concurrency": max(
            1, min(int(cfg.get_int("chat.cli_oidc_bg_refresh_concurrency", 2)), 8)
        ),
        "item_delay": max(
            0.0, float(cfg.get_float("chat.cli_oidc_bg_refresh_item_delay_sec", 0.25))
        ),
    }


def _needs_bg_refresh(cred: dict[str, Any], *, lead_s: float, now: float) -> bool:
    """True when access is missing/expired/near-expiry but refresh_token exists."""
    if not cred.get("refresh_token"):
        return False
    exp = float(cred.get("expires_at") or 0)
    # Fresh enough (beyond lead window) → skip.
    if exp > now + lead_s:
        return False
    return True


def _refresh_one_entry(
    sk: str,
    sso: str | None,
    cred: dict[str, Any],
    *,
    lead_s: float = 3600.0,
) -> str:
    """Refresh a single disk/memory entry under per-SSO lock.

    Returns status: ok | skipped | failed | rate_limited | invalid_grant.
    """
    if sk in _BG_INVALID_GRANT:
        return "invalid_grant"

    key = _normalize_sso(sso) if sso else ""
    # Prefer full SSO when known (from reverse map); else use hash-only path.
    lock_key = key or f"hash:{sk}"

    with _get_key_lock(lock_key if key else sk):
        # Re-check freshness under lock (another path may have refreshed).
        live = None
        if key:
            live = _OIDC_CACHE.get(key) or _lookup_disk_for_sso(key)
        if live is None:
            live = _OIDC_CACHE.get(f"hash:{sk}") or cred
        if not isinstance(live, dict):
            return "skipped"
        now = time.time()
        if not _needs_bg_refresh(live, lead_s=lead_s, now=now):
            # Beyond lead window (or no refresh_token) — skip.
            if key:
                cache_put(key, live)
            else:
                _OIDC_CACHE[f"hash:{sk}"] = live
                if _is_fresh(live):
                    _WARM_HASHES.add(sk)
            return "skipped"

        refresh = live.get("refresh_token") or ""
        if not refresh:
            return "skipped"

        try:
            refreshed = refresh_oidc(live)
        except UpstreamError as exc:
            detail = f"{exc} {(exc.details or {}).get('body', '')}"
            msg = detail.lower()
            if "invalid_grant" in msg or "revoked" in msg:
                _BG_INVALID_GRANT.add(sk)
                if key:
                    _drop_cred(key)
                else:
                    _OIDC_CACHE.pop(f"hash:{sk}", None)
                    _WARM_HASHES.discard(sk)
                return "invalid_grant"
            if "rate_limited" in msg or "slow_down" in msg or "429" in msg:
                return "rate_limited"
            return "failed"
        except Exception:
            return "failed"

        if key:
            cache_put(key, refreshed)
            try:
                save_disk_entry(key, refreshed)
            except Exception as exc:
                logger.warning("oidc bg refresh disk save failed: {}", exc)
        else:
            # Hash-only: update memory + disk entry by sk without full SSO.
            _OIDC_CACHE[f"hash:{sk}"] = refreshed
            if _is_fresh(refreshed):
                _WARM_HASHES.add(sk)
            try:
                p = _default_disk_path()
                with _DISK_LOCK:
                    data = load_disk_cache(p)
                    entries = data.setdefault("entries", {})
                    if isinstance(entries, dict):
                        prev = entries.get(sk) if isinstance(entries.get(sk), dict) else {}
                        entries[sk] = {
                            **(prev or {}),
                            "access_token": refreshed.get("access_token"),
                            "refresh_token": refreshed.get("refresh_token")
                            or (prev or {}).get("refresh_token"),
                            "expires_at": refreshed.get("expires_at"),
                            "user_id": refreshed.get("user_id")
                            or (prev or {}).get("user_id"),
                            "team_id": refreshed.get("team_id")
                            or (prev or {}).get("team_id"),
                            "scope": refreshed.get("scope")
                            or (prev or {}).get("scope"),
                            "updated_at": time.time(),
                        }
                        data["updated_at"] = time.time()
                        tmp = p.with_suffix(p.suffix + ".tmp")
                        tmp.write_text(
                            json.dumps(data, indent=2, ensure_ascii=False) + "\n",
                            encoding="utf-8",
                        )
                        tmp.replace(p)
            except Exception as exc:
                logger.warning("oidc bg refresh hash disk save failed: {}", exc)

        _BG_INVALID_GRANT.discard(sk)
        return "ok"


def _collect_bg_refresh_candidates(
    *, lead_s: float, max_n: int, start: int
) -> tuple[list[tuple[str, str | None, dict[str, Any]]], int]:
    """Return (candidates, next_cursor) scanned from disk entries in round-robin."""
    _ensure_disk_loaded()
    data = load_disk_cache()
    entries = data.get("entries") or {}
    if not isinstance(entries, dict) or not entries:
        return [], 0

    items = list(entries.items())
    n = len(items)
    if n == 0:
        return [], 0

    now = time.time()
    out: list[tuple[str, str | None, dict[str, Any]]] = []
    idx = start % n
    scanned = 0
    while scanned < n and len(out) < max_n:
        sk, cred = items[idx]
        idx = (idx + 1) % n
        scanned += 1
        if not isinstance(sk, str) or not isinstance(cred, dict):
            continue
        if sk in _BG_INVALID_GRANT:
            continue
        if not _needs_bg_refresh(cred, lead_s=lead_s, now=now):
            continue
        sso = _HASH_TO_SSO.get(sk)
        out.append((sk, sso, cred))
    return out, idx


def run_oidc_bg_refresh_cycle(cfg: Any | None = None) -> dict[str, int]:
    """One paced refresh-only cycle. Safe to call from tests."""
    global _BG_REFRESH_CURSOR

    if cfg is None:
        from app.platform.config.snapshot import get_config

        cfg = get_config()

    settings = _bg_refresh_settings(cfg)
    lead = float(settings["lead"])
    max_n = int(settings["max_per_cycle"])
    concurrency = int(settings["concurrency"])
    item_delay = float(settings["item_delay"])

    candidates, _BG_REFRESH_CURSOR = _collect_bg_refresh_candidates(
        lead_s=lead, max_n=max_n, start=_BG_REFRESH_CURSOR
    )
    stats = {
        "candidates": len(candidates),
        "ok": 0,
        "skipped": 0,
        "failed": 0,
        "rate_limited": 0,
        "invalid_grant": 0,
    }
    if not candidates:
        _BG_STATS["cycles"] += 1
        return stats

    from concurrent.futures import ThreadPoolExecutor, as_completed

    def _one(item: tuple[str, str | None, dict[str, Any]]) -> str:
        sk, sso, cred = item
        if item_delay > 0 and concurrency <= 1:
            time.sleep(item_delay)
        return _refresh_one_entry(sk, sso, cred, lead_s=lead)

    with ThreadPoolExecutor(
        max_workers=concurrency, thread_name_prefix="oidc-bg-refresh"
    ) as pool:
        futs = [pool.submit(_one, c) for c in candidates]
        for fut in as_completed(futs):
            try:
                status = fut.result()
            except Exception:
                status = "failed"
            if status == "ok":
                stats["ok"] += 1
                _BG_STATS["refreshed"] += 1
            elif status == "skipped":
                stats["skipped"] += 1
                _BG_STATS["skipped_fresh"] += 1
            elif status == "rate_limited":
                stats["rate_limited"] += 1
                _BG_STATS["rate_limited"] += 1
            elif status == "invalid_grant":
                stats["invalid_grant"] += 1
                _BG_STATS["invalid_grant"] += 1
            else:
                stats["failed"] += 1
                _BG_STATS["failed"] += 1

    _BG_STATS["cycles"] += 1
    if stats["ok"] or stats["rate_limited"] or stats["failed"]:
        logger.info(
            "oidc bg refresh cycle: candidates={} ok={} skipped={} "
            "failed={} rate_limited={} invalid_grant={}",
            stats["candidates"],
            stats["ok"],
            stats["skipped"],
            stats["failed"],
            stats["rate_limited"],
            stats["invalid_grant"],
        )
    return stats


def _bg_refresh_loop() -> None:
    logger.info("oidc bg refresh worker started")
    while not _BG_REFRESH_STOP.is_set():
        try:
            from app.platform.config.snapshot import get_config

            cfg = get_config()
            if _bg_refresh_enabled(cfg):
                cycle = run_oidc_bg_refresh_cycle(cfg)
                settings = _bg_refresh_settings(cfg)
                wait = float(settings["interval"])
                # Mild extra delay only when this cycle hit auth rate limits.
                if int(cycle.get("rate_limited") or 0) > 0:
                    wait = max(wait, 60.0)
            else:
                wait = 30.0
        except Exception as exc:
            logger.warning("oidc bg refresh loop error: {}", exc)
            wait = 60.0
        _BG_REFRESH_STOP.wait(wait)
    logger.info("oidc bg refresh worker stopped")


def start_oidc_bg_refresh_worker() -> bool:
    """Start daemon thread for refresh-only warm-up. Idempotent."""
    global _BG_REFRESH_THREAD
    with _BG_REFRESH_GUARD:
        if _BG_REFRESH_THREAD is not None and _BG_REFRESH_THREAD.is_alive():
            return False
        _BG_REFRESH_STOP.clear()
        _BG_REFRESH_THREAD = threading.Thread(
            target=_bg_refresh_loop,
            name="oidc-bg-refresh",
            daemon=True,
        )
        _BG_REFRESH_THREAD.start()
        return True


def stop_oidc_bg_refresh_worker(*, join_timeout: float = 5.0) -> None:
    """Signal the background worker to stop."""
    global _BG_REFRESH_THREAD
    _BG_REFRESH_STOP.set()
    with _BG_REFRESH_GUARD:
        thr = _BG_REFRESH_THREAD
        _BG_REFRESH_THREAD = None
    if thr is not None and thr.is_alive():
        thr.join(timeout=join_timeout)


def oidc_bg_refresh_stats() -> dict[str, Any]:
    return dict(_BG_STATS)


__all__ = [
    "OIDC_ISSUER",
    "GROK_CLI_CLIENT_ID",
    "decode_jwt_claims",
    "sso_key",
    "sso_to_oidc",
    "refresh_oidc",
    "has_fresh_oidc",
    "any_warm_oidc",
    "list_warm_sso_tokens",
    "convert_oidc_one",
    "schedule_oidc_repair",
    "resolve_oidc_access_token",
    "load_disk_cache",
    "save_disk_entry",
    "cache_put",
    "cache_get",
    "run_oidc_bg_refresh_cycle",
    "start_oidc_bg_refresh_worker",
    "stop_oidc_bg_refresh_worker",
    "oidc_bg_refresh_stats",
]
