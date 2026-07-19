"""Admin usage-stats API — hourly / daily aggregates by model × api_key."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import orjson
from fastapi import APIRouter, Query
from fastapi.responses import Response

from app.platform.usage_stats import get_usage_recorder

router = APIRouter(tags=["Admin - Usage"])


def _json(payload: Any) -> Response:
    return Response(content=orjson.dumps(payload), media_type="application/json")


def _default_range(hours: int = 24) -> tuple[str, str]:
    end = datetime.now(tz=timezone.utc).replace(minute=0, second=0, microsecond=0)
    start = end - timedelta(hours=max(1, hours) - 1)
    fmt = "%Y-%m-%dT%H:00:00Z"
    return start.strftime(fmt), end.strftime(fmt)


@router.get("/usage/summary")
async def usage_summary(
    start: str | None = Query(None, description="Inclusive hour ISO, e.g. 2026-07-20T00:00:00Z"),
    end: str | None = Query(None),
    granularity: str = Query("hour", pattern="^(hour|day)$"),
    model: str | None = Query(None),
    key_id: str | None = Query(None),
    hours: int = Query(24, ge=1, le=24 * 90),
):
    rec = get_usage_recorder()
    if not start or not end:
        start, end = _default_range(hours)
    rows = rec.query(
        start_hour=start,
        end_hour=end,
        model=model or None,
        key_id=key_id or None,
        granularity=granularity,
    )
    totals = {
        "requests": 0,
        "success": 0,
        "errors": 0,
        "prompt_tokens": 0,
        "completion_tokens": 0,
        "total_tokens": 0,
    }
    for r in rows:
        for k in totals:
            totals[k] += int(r.get(k) or 0)

    return _json(
        {
            "enabled": rec.is_enabled(),
            "flush_sec": rec.flush_interval_sec(),
            "retention_days": rec.retention_days(),
            "pending_buckets": rec.pending_buckets(),
            "start": start,
            "end": end,
            "granularity": granularity,
            "totals": totals,
            "rows": rows,
        }
    )


@router.get("/usage/filters")
async def usage_filters():
    rec = get_usage_recorder()
    return _json(
        {
            "enabled": rec.is_enabled(),
            "models": rec.list_models(),
            "keys": rec.list_keys(),
        }
    )


@router.post("/usage/flush")
async def usage_flush():
    rec = get_usage_recorder()
    n = rec.flush_sync()
    return _json({"status": "success", "flushed_buckets": n, "pending_buckets": rec.pending_buckets()})
