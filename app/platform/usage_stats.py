"""In-memory usage stats aggregator with periodic SQLite flush.

Dimension: hour × model × api_key (frontend aggregates hour → day).
Hot path is a locked dict increment; disk I/O only runs on the flush loop.
"""

from __future__ import annotations

import asyncio
import hashlib
import sqlite3
import threading
import time
from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable

from app.platform.logging.logger import logger
from app.platform.paths import data_path

# Request-scoped API key (set by verify_api_key).
_api_key_ctx: ContextVar[str] = ContextVar("usage_api_key", default="")


def set_request_api_key(key: str) -> None:
    _api_key_ctx.set(key or "")


def get_request_api_key() -> str:
    return _api_key_ctx.get() or ""


def key_identity(api_key: str) -> tuple[str, str]:
    """Return (key_id, key_label). Never stores the full secret."""
    raw = (api_key or "").strip()
    if not raw:
        return "__none__", "(no key)"
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]
    if len(raw) <= 8:
        label = raw[:2] + "…" + raw[-2:] if len(raw) > 4 else "****"
    else:
        label = raw[:4] + "…" + raw[-4:]
    return digest, label


def utc_hour_bucket(ts: float | None = None) -> str:
    dt = datetime.fromtimestamp(ts if ts is not None else time.time(), tz=timezone.utc)
    return dt.replace(minute=0, second=0, microsecond=0).strftime("%Y-%m-%dT%H:00:00Z")


def _parse_usage(usage: dict[str, Any] | None) -> tuple[int, int, int]:
    if not isinstance(usage, dict):
        return 0, 0, 0
    pt = int(
        usage.get("prompt_tokens")
        or usage.get("input_tokens")
        or 0
    )
    ct = int(
        usage.get("completion_tokens")
        or usage.get("output_tokens")
        or 0
    )
    total = int(usage.get("total_tokens") or (pt + ct))
    return max(0, pt), max(0, ct), max(0, total)


@dataclass
class _Counters:
    requests: int = 0
    success: int = 0
    errors: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    key_label: str = ""

    def add(
        self,
        *,
        ok: bool,
        prompt_tokens: int,
        completion_tokens: int,
        total_tokens: int,
        key_label: str,
    ) -> None:
        self.requests += 1
        if ok:
            self.success += 1
        else:
            self.errors += 1
        self.prompt_tokens += max(0, prompt_tokens)
        self.completion_tokens += max(0, completion_tokens)
        self.total_tokens += max(0, total_tokens)
        if key_label:
            self.key_label = key_label


# Key: (hour_ts, model, key_id)
_BufKey = tuple[str, str, str]


class UsageRecorder:
    """Process-local usage aggregator."""

    def __init__(self, db_path: Path | None = None) -> None:
        self._db_path = db_path or data_path("usage_stats.db")
        self._lock = threading.Lock()
        self._buf: dict[_BufKey, _Counters] = {}
        self._task: asyncio.Task | None = None
        self._stopped = False
        self._db_ready = False

    # ── config helpers ──────────────────────────────────────────────────

    @staticmethod
    def is_enabled() -> bool:
        try:
            from app.platform.config.snapshot import get_config

            return bool(get_config().get_bool("features.usage_stats_enabled", False))
        except Exception:
            return False

    @staticmethod
    def flush_interval_sec() -> int:
        try:
            from app.platform.config.snapshot import get_config

            n = int(get_config().get_int("features.usage_stats_flush_sec", 60))
        except Exception:
            n = 60
        return 30 if n <= 30 else 60

    @staticmethod
    def retention_days() -> int:
        try:
            from app.platform.config.snapshot import get_config

            return max(1, int(get_config().get_int("features.usage_stats_retention_days", 90)))
        except Exception:
            return 90

    # ── lifecycle ───────────────────────────────────────────────────────

    def start(self) -> None:
        self._stopped = False
        self._ensure_db()
        if self._task is None or self._task.done():
            self._task = asyncio.create_task(self._loop(), name="usage-stats-flush")
            logger.info("usage stats recorder started: db={}", self._db_path)

    async def stop(self) -> None:
        self._stopped = True
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        try:
            await asyncio.to_thread(self.flush_sync)
        except Exception as exc:
            logger.warning("usage stats final flush failed: {}", exc)

    async def _loop(self) -> None:
        while not self._stopped:
            try:
                await asyncio.sleep(self.flush_interval_sec())
                if not self.is_enabled():
                    continue
                await asyncio.to_thread(self.flush_sync)
                await asyncio.to_thread(self.purge_old_sync)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.warning("usage stats flush loop error: {}", exc)

    # ── hot path ────────────────────────────────────────────────────────

    def record(
        self,
        *,
        model: str,
        api_key: str | None = None,
        prompt_tokens: int = 0,
        completion_tokens: int = 0,
        total_tokens: int | None = None,
        ok: bool = True,
        usage: dict[str, Any] | None = None,
    ) -> None:
        if not self.is_enabled():
            return
        model_name = (model or "unknown").strip() or "unknown"
        if usage is not None:
            pt, ct, tt = _parse_usage(usage)
            if pt or ct or tt:
                prompt_tokens, completion_tokens, total_tokens = pt, ct, tt
        if total_tokens is None:
            total_tokens = max(0, int(prompt_tokens)) + max(0, int(completion_tokens))

        key = api_key if api_key is not None else get_request_api_key()
        key_id, key_label = key_identity(key)
        hour = utc_hour_bucket()
        buf_key: _BufKey = (hour, model_name, key_id)

        with self._lock:
            c = self._buf.get(buf_key)
            if c is None:
                c = _Counters(key_label=key_label)
                self._buf[buf_key] = c
            c.add(
                ok=ok,
                prompt_tokens=int(prompt_tokens),
                completion_tokens=int(completion_tokens),
                total_tokens=int(total_tokens),
                key_label=key_label,
            )

    def record_usage(
        self,
        model: str,
        usage: dict[str, Any] | None,
        *,
        ok: bool = True,
        api_key: str | None = None,
    ) -> None:
        """Convenience: prefer usage dict fields."""
        self.record(model=model, usage=usage, ok=ok, api_key=api_key)

    # ── persistence ─────────────────────────────────────────────────────

    def _ensure_db(self) -> None:
        if self._db_ready:
            return
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS usage_hourly (
                    hour_ts TEXT NOT NULL,
                    model TEXT NOT NULL,
                    key_id TEXT NOT NULL,
                    key_label TEXT NOT NULL DEFAULT '',
                    requests INTEGER NOT NULL DEFAULT 0,
                    success INTEGER NOT NULL DEFAULT 0,
                    errors INTEGER NOT NULL DEFAULT 0,
                    prompt_tokens INTEGER NOT NULL DEFAULT 0,
                    completion_tokens INTEGER NOT NULL DEFAULT 0,
                    total_tokens INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY (hour_ts, model, key_id)
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_usage_hour ON usage_hourly(hour_ts)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_usage_model ON usage_hourly(model)"
            )
            conn.commit()
        self._db_ready = True

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self._db_path), timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        return conn

    def flush_sync(self) -> int:
        with self._lock:
            if not self._buf:
                return 0
            snapshot = self._buf
            self._buf = {}

        self._ensure_db()
        rows = 0
        try:
            with self._connect() as conn:
                for (hour, model, key_id), c in snapshot.items():
                    conn.execute(
                        """
                        INSERT INTO usage_hourly (
                            hour_ts, model, key_id, key_label,
                            requests, success, errors,
                            prompt_tokens, completion_tokens, total_tokens
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(hour_ts, model, key_id) DO UPDATE SET
                            key_label=excluded.key_label,
                            requests=requests+excluded.requests,
                            success=success+excluded.success,
                            errors=errors+excluded.errors,
                            prompt_tokens=prompt_tokens+excluded.prompt_tokens,
                            completion_tokens=completion_tokens+excluded.completion_tokens,
                            total_tokens=total_tokens+excluded.total_tokens
                        """,
                        (
                            hour,
                            model,
                            key_id,
                            c.key_label,
                            c.requests,
                            c.success,
                            c.errors,
                            c.prompt_tokens,
                            c.completion_tokens,
                            c.total_tokens,
                        ),
                    )
                    rows += 1
                conn.commit()
        except Exception:
            # Put data back so we do not lose it on transient I/O failure.
            with self._lock:
                for k, c in snapshot.items():
                    existing = self._buf.get(k)
                    if existing is None:
                        self._buf[k] = c
                        continue
                    existing.requests += c.requests
                    existing.success += c.success
                    existing.errors += c.errors
                    existing.prompt_tokens += c.prompt_tokens
                    existing.completion_tokens += c.completion_tokens
                    existing.total_tokens += c.total_tokens
                    if c.key_label:
                        existing.key_label = c.key_label
            raise
        if rows:
            logger.debug("usage stats flushed: buckets={}", rows)
        return rows

    def purge_old_sync(self) -> int:
        days = self.retention_days()
        cutoff = (
            datetime.now(tz=timezone.utc) - timedelta(days=days)
        ).replace(minute=0, second=0, microsecond=0).strftime("%Y-%m-%dT%H:00:00Z")
        self._ensure_db()
        with self._connect() as conn:
            cur = conn.execute(
                "DELETE FROM usage_hourly WHERE hour_ts < ?", (cutoff,)
            )
            conn.commit()
            return int(cur.rowcount or 0)

    # ── query ───────────────────────────────────────────────────────────

    def query(
        self,
        *,
        start_hour: str | None = None,
        end_hour: str | None = None,
        model: str | None = None,
        key_id: str | None = None,
        granularity: str = "hour",
    ) -> list[dict[str, Any]]:
        """Return merged (disk + pending buffer) rows.

        granularity: "hour" | "day"
        """
        # Best-effort include pending buffer without forcing full flush lock long.
        pending: list[dict[str, Any]] = []
        with self._lock:
            for (hour, m, kid), c in self._buf.items():
                pending.append(
                    {
                        "hour_ts": hour,
                        "model": m,
                        "key_id": kid,
                        "key_label": c.key_label,
                        "requests": c.requests,
                        "success": c.success,
                        "errors": c.errors,
                        "prompt_tokens": c.prompt_tokens,
                        "completion_tokens": c.completion_tokens,
                        "total_tokens": c.total_tokens,
                    }
                )

        self._ensure_db()
        clauses: list[str] = []
        args: list[Any] = []
        if start_hour:
            clauses.append("hour_ts >= ?")
            args.append(start_hour)
        if end_hour:
            clauses.append("hour_ts <= ?")
            args.append(end_hour)
        if model:
            clauses.append("model = ?")
            args.append(model)
        if key_id:
            clauses.append("key_id = ?")
            args.append(key_id)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""

        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM usage_hourly{where}",
                args,
            ).fetchall()

        merged: dict[tuple[str, str, str], dict[str, Any]] = {}
        for row in rows:
            item = dict(row)
            k = (item["hour_ts"], item["model"], item["key_id"])
            merged[k] = item
        for item in pending:
            if start_hour and item["hour_ts"] < start_hour:
                continue
            if end_hour and item["hour_ts"] > end_hour:
                continue
            if model and item["model"] != model:
                continue
            if key_id and item["key_id"] != key_id:
                continue
            k = (item["hour_ts"], item["model"], item["key_id"])
            if k not in merged:
                merged[k] = item
            else:
                base = merged[k]
                for col in (
                    "requests",
                    "success",
                    "errors",
                    "prompt_tokens",
                    "completion_tokens",
                    "total_tokens",
                ):
                    base[col] = int(base.get(col) or 0) + int(item.get(col) or 0)
                if item.get("key_label"):
                    base["key_label"] = item["key_label"]

        items = list(merged.values())
        if granularity == "day":
            items = _aggregate_day(items)
        items.sort(
            key=lambda r: (r.get("hour_ts") or r.get("day") or "", r.get("model") or "", r.get("key_id") or ""),
            reverse=True,
        )
        return items

    def list_models(self) -> list[str]:
        self._ensure_db()
        names: set[str] = set()
        with self._lock:
            for (_, m, _) in self._buf:
                names.add(m)
        with self._connect() as conn:
            for row in conn.execute(
                "SELECT DISTINCT model FROM usage_hourly ORDER BY model"
            ):
                names.add(row["model"])
        return sorted(names)

    def list_keys(self) -> list[dict[str, str]]:
        self._ensure_db()
        labels: dict[str, str] = {}
        with self._lock:
            for (_, _, kid), c in self._buf.items():
                labels[kid] = c.key_label or labels.get(kid, kid)
        with self._connect() as conn:
            for row in conn.execute(
                "SELECT key_id, key_label FROM usage_hourly GROUP BY key_id"
            ):
                labels[row["key_id"]] = row["key_label"] or labels.get(row["key_id"], row["key_id"])
        return [
            {"key_id": kid, "key_label": labels[kid]}
            for kid in sorted(labels.keys())
        ]

    def pending_buckets(self) -> int:
        with self._lock:
            return len(self._buf)


def _aggregate_day(items: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    buckets: dict[tuple[str, str, str], dict[str, Any]] = {}
    for item in items:
        hour = str(item.get("hour_ts") or "")
        day = hour[:10] if len(hour) >= 10 else hour
        k = (day, str(item.get("model") or ""), str(item.get("key_id") or ""))
        if k not in buckets:
            buckets[k] = {
                "day": day,
                "hour_ts": day,
                "model": k[1],
                "key_id": k[2],
                "key_label": item.get("key_label") or "",
                "requests": 0,
                "success": 0,
                "errors": 0,
                "prompt_tokens": 0,
                "completion_tokens": 0,
                "total_tokens": 0,
            }
        b = buckets[k]
        for col in (
            "requests",
            "success",
            "errors",
            "prompt_tokens",
            "completion_tokens",
            "total_tokens",
        ):
            b[col] = int(b[col]) + int(item.get(col) or 0)
        if item.get("key_label"):
            b["key_label"] = item["key_label"]
    return list(buckets.values())


# Process singleton
_recorder: UsageRecorder | None = None
_recorder_lock = threading.Lock()


def get_usage_recorder() -> UsageRecorder:
    global _recorder
    if _recorder is None:
        with _recorder_lock:
            if _recorder is None:
                _recorder = UsageRecorder()
    return _recorder


def record_usage(
    model: str,
    usage: dict[str, Any] | None = None,
    *,
    ok: bool = True,
    prompt_tokens: int = 0,
    completion_tokens: int = 0,
    api_key: str | None = None,
) -> None:
    """Public hot-path helper — no-op when stats disabled."""
    try:
        get_usage_recorder().record(
            model=model,
            usage=usage,
            ok=ok,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            api_key=api_key,
        )
    except Exception as exc:
        logger.debug("usage stats record skipped: {}", exc)


__all__ = [
    "UsageRecorder",
    "get_usage_recorder",
    "record_usage",
    "set_request_api_key",
    "get_request_api_key",
    "key_identity",
    "utc_hour_bucket",
]
