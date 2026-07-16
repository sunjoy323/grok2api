#!/usr/bin/env python3
"""Batch-convert SSO cookies → OIDC, write CLIProxyAPI xAI auth JSON files.

Pipeline for each SSO:
  1. Device-flow convert (same as sso_to_oidc / Grok CLI client)
  2. Optionally cache into data/oidc_auth.json
  3. Write one CLIProxyAPI credential file: xai-<sub|email>.json

CLIProxyAPI file shape (internal/auth/xai/token.go TokenStorage):
  {
    "type": "xai",
    "access_token": "...",
    "refresh_token": "...",
    "token_type": "Bearer",
    "expires_in": 21600,
    "expired": "RFC3339",
    "last_refresh": "RFC3339",
    "email": "",
    "sub": "<user_id>",
    "base_url": "https://api.x.ai/v1",
    "token_endpoint": "https://auth.x.ai/oauth2/token",
    "auth_kind": "oauth"
  }

Input SSO formats (one per line in --sso-file):
  eyJ...                          # raw JWT
  sso=eyJ...
  email----eyJ...
  email:password:eyJ...           # last segment treated as SSO
  # comments and blank lines ignored

Examples:

  # From a list file, 4 concurrent, batches of 8, 2s between batches
  uv run python scripts/sso_to_cliproxy_xai.py \\
    --sso-file ./sso.txt --out-dir ./data/cliproxy-xai \\
    --workers 4 --batch-size 8 --batch-delay 2

  # From accounts.db (active tokens only)
  uv run python scripts/sso_to_cliproxy_xai.py \\
    --from-db --out-dir ./data/cliproxy-xai --workers 2

  # Skip SSO that already has a CLIProxyAPI file for the same sub
  uv run python scripts/sso_to_cliproxy_xai.py \\
    --sso-file ./sso.txt --out-dir ~/.cli-proxy-api --skip-existing-file

  # Also refresh grok2api oidc_auth.json cache
  uv run python scripts/sso_to_cliproxy_xai.py \\
    --sso-file ./sso.txt --out-dir ./data/cliproxy-xai --save-oidc-cache
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sqlite3
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from app.dataplane.reverse.protocol.xai_oidc import (  # noqa: E402
    cache_put,
    decode_jwt_claims,
    load_disk_cache,
    save_disk_entry,
    sso_key,
    sso_to_oidc,
)
from app.platform.errors import UpstreamError  # noqa: E402

OIDC_ISSUER = "https://auth.x.ai"
TOKEN_ENDPOINT = f"{OIDC_ISSUER}/oauth2/token"
DEFAULT_BASE_URL = "https://api.x.ai/v1"
CLIENT_ID = "b1a00492-073a-47ea-816f-4c329264a828"

_NAME_LOCK = threading.Lock()
_USED_NAMES: set[str] = set()


# ---------------------------------------------------------------------------
# Input helpers
# ---------------------------------------------------------------------------

def _normalize_sso(raw: str) -> str:
    s = (raw or "").strip()
    if s.startswith("sso="):
        s = s[4:]
    return s.strip()


def load_sso_file(path: Path) -> list[tuple[str, str]]:
    """Return list of (label, sso)."""
    out: list[tuple[str, str]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        label = ""
        if "----" in line:
            parts = line.split("----")
            label = parts[0].strip()
            line = parts[-1].strip()
        elif ":" in line and not line.startswith("eyJ"):
            parts = line.rsplit(":", 1)
            label = parts[0].strip()
            line = parts[-1].strip()
        out.append((label, _normalize_sso(line)))
    return out


def load_sso_from_db(
    db_path: Path,
    *,
    limit: int = 0,
    status: str = "active",
) -> list[tuple[str, str]]:
    con = sqlite3.connect(str(db_path))
    try:
        sql = (
            "SELECT token FROM accounts WHERE status = ? "
            "AND (deleted_at IS NULL OR deleted_at = 0)"
        )
        params: list[object] = [status]
        if limit and limit > 0:
            sql += " LIMIT ?"
            params.append(int(limit))
        rows = con.execute(sql, params).fetchall()
    finally:
        con.close()
    return [("", _normalize_sso(r[0])) for r in rows if r and r[0]]


def chunked(items: list, size: int) -> list[list]:
    if size <= 0:
        return [items]
    return [items[i : i + size] for i in range(0, len(items), size)]


# ---------------------------------------------------------------------------
# CLIProxyAPI file helpers
# ---------------------------------------------------------------------------

def sanitize_file_segment(value: str) -> str:
    value = (value or "").strip()
    if not value:
        return ""
    out: list[str] = []
    for r in value:
        if ("a" <= r <= "z") or ("A" <= r <= "Z") or ("0" <= r <= "9"):
            out.append(r)
        elif r in "@._-":
            out.append(r)
        else:
            out.append("-")
    return "".join(out).strip("-")


def credential_file_name(email: str, subject: str) -> str:
    email = sanitize_file_segment(email)
    if email:
        return f"xai-{email}.json"
    subject = sanitize_file_segment(subject)
    if subject:
        return f"xai-{subject}.json"
    return f"xai-{int(time.time() * 1000)}.json"


def to_cliproxy_entry(cred: dict, *, email: str = "") -> dict:
    access = str(cred.get("access_token") or "")
    claims = decode_jwt_claims(access) if access else {}
    if not isinstance(claims, dict):
        claims = {}
    sub = str(
        cred.get("user_id")
        or claims.get("principal_id")
        or claims.get("sub")
        or ""
    ).strip()
    email = (email or claims.get("email") or "").strip()
    exp_at = float(cred.get("expires_at") or claims.get("exp") or 0)
    now = time.time()
    expires_in = max(0, int(exp_at - now)) if exp_at else 0
    if exp_at > 0:
        expired = datetime.fromtimestamp(exp_at, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    else:
        expired = ""
    last_refresh = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {
        "type": "xai",
        "access_token": access,
        "refresh_token": str(cred.get("refresh_token") or ""),
        "id_token": str(cred.get("id_token") or ""),
        "token_type": "Bearer",
        "expires_in": expires_in,
        "expired": expired,
        "last_refresh": last_refresh,
        "email": email,
        "sub": sub,
        "base_url": DEFAULT_BASE_URL,
        "token_endpoint": TOKEN_ENDPOINT,
        "auth_kind": "oauth",
        "team_id": str(cred.get("team_id") or claims.get("team_id") or ""),
        "scope": str(cred.get("scope") or claims.get("scope") or ""),
        "oidc_client_id": CLIENT_ID,
        "oidc_issuer": OIDC_ISSUER,
    }


def _allocate_filename(out_dir: Path, email: str, subject: str) -> Path:
    """Thread-safe unique filename under out_dir."""
    with _NAME_LOCK:
        name = credential_file_name(email, subject)
        if name in _USED_NAMES or (out_dir / name).exists():
            stem = name[:-5] if name.endswith(".json") else name
            n = 2
            while True:
                cand = f"{stem}-{n}.json"
                if cand not in _USED_NAMES and not (out_dir / cand).exists():
                    name = cand
                    break
                n += 1
        _USED_NAMES.add(name)
        return out_dir / name


def _seed_used_names(out_dir: Path) -> None:
    if not out_dir.is_dir():
        return
    with _NAME_LOCK:
        for p in out_dir.glob("xai-*.json"):
            _USED_NAMES.add(p.name)


def _existing_sub_files(out_dir: Path) -> set[str]:
    """Map of sub values already present in out_dir (for skip-existing-file)."""
    subs: set[str] = set()
    if not out_dir.is_dir():
        return subs
    for p in out_dir.glob("xai-*.json"):
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            sub = str(data.get("sub") or "").strip()
            if sub:
                subs.add(sub)
        except Exception:
            continue
    return subs


# ---------------------------------------------------------------------------
# Convert one
# ---------------------------------------------------------------------------

def process_one(
    index: int,
    total: int,
    label: str,
    sso: str,
    *,
    out_dir: Path,
    save_oidc_cache: bool,
    oidc_disk: Path | None,
    skip_existing_file: bool,
    existing_subs: set[str],
    reuse_oidc_cache: bool,
) -> dict:
    tag = label or f"sso#{index}"
    result: dict = {"index": index, "label": tag, "status": "failed"}
    try:
        # Reuse disk OIDC if present and still has refresh (or always when asked).
        cred = None
        if reuse_oidc_cache and oidc_disk is not None:
            try:
                entries = load_disk_cache(oidc_disk).get("entries") or {}
                cached = entries.get(sso_key(sso))
                if isinstance(cached, dict) and cached.get("access_token") and cached.get("refresh_token"):
                    cred = cached
                    print(f"[{index}/{total}] reuse oidc cache {tag}", flush=True)
            except Exception:
                cred = None

        if cred is None:
            print(f"[{index}/{total}] converting {tag} ...", flush=True)
            cred = sso_to_oidc(sso)
            cache_put(sso, cred)
            if save_oidc_cache and oidc_disk is not None:
                save_disk_entry(sso, cred, path=oidc_disk)
        elif save_oidc_cache and oidc_disk is not None:
            # keep cache warm / timestamps optional — no-op
            pass

        entry = to_cliproxy_entry(cred, email=label if "@" in (label or "") else "")
        sub = entry.get("sub") or ""
        if skip_existing_file and sub and sub in existing_subs:
            result["status"] = "skipped"
            result["user_id"] = sub
            result["reason"] = "xai file for sub already exists"
            print(f"  ⏭  [{index}] skip existing sub={sub[:12]}", flush=True)
            return result

        if not entry.get("access_token"):
            result["error"] = "missing access_token after convert"
            print(f"  ❌ [{index}] {result['error']}", flush=True)
            return result

        path = _allocate_filename(out_dir, entry.get("email") or "", sub)
        path.write_text(
            json.dumps(entry, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        if sub:
            existing_subs.add(sub)

        result["status"] = "ok"
        result["user_id"] = sub
        result["team_id"] = entry.get("team_id")
        result["file"] = str(path)
        result["expires_at"] = entry.get("expired")
        print(
            f"  ✅ [{index}] user={sub[:12]} file={path.name}",
            flush=True,
        )
        return result
    except UpstreamError as exc:
        result["error"] = str(exc)
        print(f"  ❌ [{index}] {exc}", flush=True)
        return result
    except Exception as exc:  # noqa: BLE001
        result["error"] = f"{type(exc).__name__}: {exc}"
        print(f"  ❌ [{index}] {result['error']}", flush=True)
        return result


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(
        description="SSO → OIDC → CLIProxyAPI xai-*.json (batched)"
    )
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument(
        "--from-db",
        action="store_true",
        help="Read SSO from data/accounts.db (status=active)",
    )
    src.add_argument("--sso-file", type=Path, help="SSO list file (one per line)")
    src.add_argument("--sso-cookie", help="Single SSO JWT")

    ap.add_argument(
        "--db",
        type=Path,
        default=_ROOT / "data" / "accounts.db",
        help="SQLite path when --from-db",
    )
    ap.add_argument("--limit", type=int, default=0, help="Max SSO to process (0=all)")
    ap.add_argument(
        "--out-dir",
        type=Path,
        required=True,
        help="Directory for CLIProxyAPI xai-*.json files",
    )
    ap.add_argument(
        "--workers",
        type=int,
        default=2,
        help="Concurrency within each batch (default 2, max 8)",
    )
    ap.add_argument(
        "--batch-size",
        type=int,
        default=8,
        help="SSO count per batch before pause (default 8; 0=no batching)",
    )
    ap.add_argument(
        "--batch-delay",
        type=float,
        default=2.0,
        help="Seconds to sleep between batches (default 2)",
    )
    ap.add_argument(
        "--item-delay",
        type=float,
        default=0.0,
        help="Extra delay after each item when workers=1 (default 0)",
    )
    ap.add_argument(
        "--save-oidc-cache",
        action="store_true",
        help="Also upsert into grok2api oidc_auth.json",
    )
    ap.add_argument(
        "--oidc-disk",
        type=Path,
        default=_ROOT / "data" / "oidc_auth.json",
        help="oidc_auth.json path when --save-oidc-cache",
    )
    ap.add_argument(
        "--skip-existing-file",
        action="store_true",
        help="Skip if out-dir already has a file for the same sub",
    )
    ap.add_argument(
        "--reuse-oidc-cache",
        action="store_true",
        help="If oidc_auth.json already has this SSO, reuse it instead of device-flow",
    )
    ap.add_argument(
        "--summary",
        type=Path,
        default=None,
        help="Write run summary JSON (default: <out-dir>/sso_to_cliproxy_summary.json)",
    )
    args = ap.parse_args()

    if args.sso_cookie:
        items = [("", _normalize_sso(args.sso_cookie))]
    elif args.sso_file:
        if not args.sso_file.is_file():
            print(f"SSO file not found: {args.sso_file}", file=sys.stderr)
            return 2
        items = load_sso_file(args.sso_file)
    else:
        if not args.db.is_file():
            print(f"DB not found: {args.db}", file=sys.stderr)
            return 2
        items = load_sso_from_db(args.db, limit=args.limit)

    if args.limit and args.limit > 0 and not args.from_db:
        items = items[: int(args.limit)]
    elif args.limit and args.limit > 0 and args.from_db and len(items) > args.limit:
        # already applied in SQL when from-db + limit; keep for safety
        items = items[: int(args.limit)]

    # Deduplicate SSO while keeping first label
    seen: set[str] = set()
    unique_items: list[tuple[str, str]] = []
    for label, sso in items:
        if not sso or sso in seen:
            continue
        seen.add(sso)
        unique_items.append((label, sso))
    items = unique_items

    if not items:
        print("No SSO tokens to convert", file=sys.stderr)
        return 2

    out_dir: Path = args.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    _seed_used_names(out_dir)
    existing_subs = _existing_sub_files(out_dir) if args.skip_existing_file else set()
    # thread-safe add via GIL + set.add is fine for CPython for membership; use lock if needed
    existing_subs_lock = threading.Lock()

    workers = max(1, min(int(args.workers or 2), 8))
    batch_size = max(0, int(args.batch_size or 0))
    batch_delay = max(0.0, float(args.batch_delay or 0))
    item_delay = max(0.0, float(args.item_delay or 0))
    total = len(items)
    batches = chunked(list(enumerate(items, 1)), batch_size if batch_size > 0 else total)

    print(
        f"SSO → CLIProxyAPI xAI: total={total} workers={workers} "
        f"batch_size={batch_size or 'all'} batch_delay={batch_delay}s "
        f"out={out_dir}",
        flush=True,
    )

    ok = skip = fail = 0
    results: list[dict] = []
    global_index_base = 0

    # oidc disk path for reuse and/or cache write
    oidc_disk_path = args.oidc_disk if (args.save_oidc_cache or args.reuse_oidc_cache) else None

    def _run_one(index: int, label: str, sso: str) -> dict:
        with existing_subs_lock:
            subs_ref = existing_subs
        res = process_one(
            index,
            total,
            label,
            sso,
            out_dir=out_dir,
            save_oidc_cache=bool(args.save_oidc_cache),
            oidc_disk=oidc_disk_path,
            skip_existing_file=bool(args.skip_existing_file),
            existing_subs=subs_ref,
            reuse_oidc_cache=bool(args.reuse_oidc_cache),
        )
        if res.get("status") == "ok" and res.get("user_id"):
            with existing_subs_lock:
                existing_subs.add(str(res["user_id"]))
        return res

    for bi, batch in enumerate(batches, 1):
        print(f"\n--- batch {bi}/{len(batches)} size={len(batch)} ---", flush=True)
        if workers <= 1:
            for index, (label, sso) in batch:
                res = _run_one(index, label, sso)
                results.append(res)
                st = res.get("status")
                if st == "ok":
                    ok += 1
                elif st == "skipped":
                    skip += 1
                else:
                    fail += 1
                if item_delay > 0:
                    time.sleep(item_delay)
        else:
            with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="sso2cpa") as pool:
                futs = {
                    pool.submit(_run_one, index, label, sso): index
                    for index, (label, sso) in batch
                }
                for fut in as_completed(futs):
                    res = fut.result()
                    results.append(res)
                    st = res.get("status")
                    if st == "ok":
                        ok += 1
                    elif st == "skipped":
                        skip += 1
                    else:
                        fail += 1

        if bi < len(batches) and batch_delay > 0:
            print(f"  sleep {batch_delay}s before next batch...", flush=True)
            time.sleep(batch_delay)

    summary_path = args.summary or (out_dir / "sso_to_cliproxy_summary.json")
    summary = {
        "finished_at": time.time(),
        "ok": ok,
        "skipped": skip,
        "fail": fail,
        "total": total,
        "out_dir": str(out_dir),
        "results": sorted(results, key=lambda r: int(r.get("index") or 0)),
    }
    summary_path.write_text(
        json.dumps(summary, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    print(
        f"\nDone: ok={ok} skipped={skip} fail={fail} total={total}\n"
        f"Files:   {out_dir}/xai-*.json\n"
        f"Summary: {summary_path}",
        flush=True,
    )
    if fail and ok == 0:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
