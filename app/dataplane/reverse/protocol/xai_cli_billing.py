"""Grok CLI billing / credits (cli-chat-proxy.grok.com/v1/billing).

Uses OIDC access_token (same as cli-chat). Response shape matches Grok Build
/ pi-grok-cli billing API::

    GET /v1/billing
    {
      "config": {
        "monthlyLimit": {"val": <number>},
        "used": {"val": <number>},
        "billingPeriodEnd": "2026-08-01T00:00:00+00:00",
        ...
      }
    }

Mapped into QuotaWindow as remaining/total credits for admin display.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any

import orjson

from app.platform.errors import UpstreamError
from app.platform.logging.logger import logger
from app.platform.runtime.clock import now_ms


def parse_cli_billing(body: dict[str, Any], *, synced_at: int | None = None) -> object | None:
    """Parse billing JSON into a QuotaWindow, or None if unusable."""
    from app.control.account.enums import QuotaSource
    from app.control.account.models import QuotaWindow

    cfg = body.get("config") if isinstance(body, dict) else None
    if not isinstance(cfg, dict):
        return None

    def _val(obj: Any) -> float | None:
        if isinstance(obj, dict) and "val" in obj:
            try:
                return float(obj["val"])
            except (TypeError, ValueError):
                return None
        if isinstance(obj, (int, float)):
            return float(obj)
        return None

    limit = _val(cfg.get("monthlyLimit"))
    used = _val(cfg.get("used"))
    if limit is None or used is None:
        return None

    # Credits may be fractional in theory; store as rounded ints for QuotaWindow.
    total = max(0, int(round(limit)))
    used_i = max(0, int(round(used)))
    remaining = max(0, total - used_i)

    period_end = cfg.get("billingPeriodEnd")
    reset_at: int | None = None
    window_seconds = 0
    ts = synced_at if synced_at is not None else now_ms()
    if isinstance(period_end, str) and period_end.strip():
        try:
            # Support trailing Z and offset forms.
            raw = period_end.strip().replace("Z", "+00:00")
            dt = datetime.fromisoformat(raw)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            reset_ms = int(dt.timestamp() * 1000)
            reset_at = reset_ms
            window_seconds = max(0, (reset_ms - ts) // 1000)
        except (TypeError, ValueError, OSError):
            reset_at = None

    return QuotaWindow(
        remaining=remaining,
        total=total,
        window_seconds=window_seconds,
        reset_at=reset_at,
        synced_at=ts,
        source=QuotaSource.REAL,
    )


async def _http_get_billing(access_token: str) -> dict[str, Any]:
    from app.control.proxy.models import ProxyFeedback, ProxyFeedbackKind
    from app.dataplane.proxy import get_proxy_runtime
    from app.dataplane.proxy.adapters.session import ResettableSession, build_session_kwargs
    from app.dataplane.reverse.protocol.xai_cli_chat import CLI_VERSION, CLIENT_IDENTIFIER, CLIENT_SURFACE
    from app.dataplane.reverse.runtime.endpoint_table import CLI_BILLING

    headers = {
        "Authorization": f"Bearer {access_token}",
        "X-XAI-Token-Auth": "xai-grok-cli",
        "Accept": "application/json",
        "x-grok-cli-version": CLI_VERSION,
        "x-grok-client-surface": CLIENT_SURFACE,
        "x-grok-client-identifier": CLIENT_IDENTIFIER,
    }

    proxy = await get_proxy_runtime()
    lease = await proxy.acquire()
    session_kwargs = build_session_kwargs(lease=lease)
    try:
        async with ResettableSession(**session_kwargs) as session:
            response = await session.get(CLI_BILLING, headers=headers, timeout=25.0)
            raw = response.content or b""
            if response.status_code != 200:
                body_text = raw.decode("utf-8", "replace")[:400]
                await proxy.feedback(
                    lease,
                    ProxyFeedback(
                        kind=ProxyFeedbackKind.FORBIDDEN
                        if response.status_code in (401, 403)
                        else ProxyFeedbackKind.TRANSPORT_ERROR,
                        status_code=response.status_code,
                    ),
                )
                raise UpstreamError(
                    f"CLI billing returned {response.status_code}: {body_text or '(empty)'}",
                    status=response.status_code,
                    body=body_text,
                )
            await proxy.feedback(
                lease, ProxyFeedback(kind=ProxyFeedbackKind.SUCCESS, status_code=200)
            )
            data = orjson.loads(raw)
            if not isinstance(data, dict):
                raise UpstreamError("CLI billing response is not an object", status=502)
            return data
    except UpstreamError:
        raise
    except Exception as exc:
        await proxy.feedback(
            lease, ProxyFeedback(kind=ProxyFeedbackKind.TRANSPORT_ERROR, status_code=None)
        )
        raise UpstreamError(f"CLI billing transport failed: {exc}", status=502) from exc


async def fetch_cli_quota(sso_token: str) -> object | None:
    """SSO → OIDC → GET /billing → QuotaWindow.

    Returns None on soft failures (no OIDC cache, network blip). Raises only
    for invalid-credential style errors when OIDC conversion fails hard.
    """
    from app.dataplane.reverse.protocol.xai_oidc import resolve_oidc_access_token

    try:
        access = await asyncio.to_thread(resolve_oidc_access_token, sso_token)
    except Exception as exc:
        logger.debug(
            "cli billing oidc resolve failed: token={}... error={}",
            (sso_token or "")[:10],
            exc,
        )
        return None

    try:
        body = await _http_get_billing(access)
    except UpstreamError as exc:
        logger.debug(
            "cli billing fetch failed: token={}... status={} error={}",
            (sso_token or "")[:10],
            getattr(exc, "status", None),
            exc,
        )
        return None
    except Exception as exc:
        logger.debug(
            "cli billing fetch error: token={}... error={}",
            (sso_token or "")[:10],
            exc,
        )
        return None

    window = parse_cli_billing(body)
    if window is None:
        logger.debug(
            "cli billing parse failed: token={}... body_keys={}",
            (sso_token or "")[:10],
            list(body.keys()) if isinstance(body, dict) else type(body),
        )
    return window


__all__ = ["parse_cli_billing", "fetch_cli_quota"]
