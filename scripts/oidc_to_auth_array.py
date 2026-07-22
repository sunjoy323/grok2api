#!/usr/bin/env python3
"""Convert data/oidc_auth.json → grok CLI style auth array JSON.

Input (runtime OIDC disk cache written by scripts/sso_to_oidc.py):

  {
    "version": 1,
    "entries": {
      "<sso_sha256>": {
        "access_token": "...",
        "refresh_token": "...",
        "expires_at": 1783765907.0,
        "user_id": "...",
        "team_id": "...",
        "scope": "...",
        ...
      }
    },
    "updated_at": ...
  }

Output: a JSON array whose items match ~/.grok/auth.json entry shape:

  [
    {
      "auth_mode": "oidc",
      "coding_data_retention_opt_out": false,
      "create_time": "2026-07-12T11:11:25.958899Z",
      "email": "",
      "expires_at": "2026-07-13T11:06:01+00:00",
      "first_name": "",
      "key": "<access_token>",
      "oidc_client_id": "b1a00492-...",
      "oidc_issuer": "https://auth.x.ai",
      "principal_id": "<user_id>",
      "principal_type": "User",
      "profile_image_asset_id": "",
      "refresh_token": "...",
      "team_id": "...",
      "user_id": "..."
    },
    ...
  ]

Examples:

  # Default: data/oidc_auth.json → data/auth_array.json
  uv run python scripts/oidc_to_auth_array.py

  # Custom paths
  uv run python scripts/oidc_to_auth_array.py \\
    --input data/oidc_auth.json \\
    --output data/auth_array.json

  # Also emit grokcli object map (issuer::user_id → entry)
  uv run python scripts/oidc_to_auth_array.py --also-map data/auth.json

  # Compact JSON (no indent)
  uv run python scripts/oidc_to_auth_array.py --compact
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Allow `uv run python scripts/oidc_to_auth_array.py` from repo root
_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from app.dataplane.reverse.protocol.xai_oidc import (  # noqa: E402
    GROK_CLI_CLIENT_ID,
    OIDC_ISSUER,
    decode_jwt_claims,
)


def _ts_to_iso_offset(ts: Any) -> str:
    """Unix timestamp → `2026-07-13T11:06:01+00:00` (matches ~/.grok/auth.json)."""
    try:
        t = float(ts)
    except (TypeError, ValueError):
        if isinstance(ts, str) and ts.strip():
            return ts.strip()
        return ""
    if t <= 0:
        return ""
    return datetime.fromtimestamp(t, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+00:00")


def _ts_to_create_time(ts: Any) -> str:
    """Unix timestamp → `2026-07-12T11:11:25.958899Z`."""
    try:
        t = float(ts)
    except (TypeError, ValueError):
        t = time.time()
    if t <= 0:
        t = time.time()
    return datetime.fromtimestamp(t, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def to_grok_auth_item(cred: dict[str, Any], *, email: str = "") -> dict[str, Any]:
    """Map one oidc_auth entry → ~/.grok/auth.json value shape."""
    access = str(cred.get("access_token") or cred.get("key") or "")
    claims = decode_jwt_claims(access) if access else {}

    user_id = str(
        cred.get("user_id")
        or claims.get("sub")
        or claims.get("principal_id")
        or ""
    )
    team_id = str(cred.get("team_id") or claims.get("team_id") or "")
    exp = cred.get("expires_at")
    if exp is None and claims.get("exp") is not None:
        exp = claims.get("exp")
    create_src = cred.get("updated_at") or claims.get("iat") or time.time()

    return {
        "auth_mode": "oidc",
        "coding_data_retention_opt_out": bool(
            cred.get("coding_data_retention_opt_out", False)
        ),
        "create_time": _ts_to_create_time(create_src),
        "email": str(
            email
            or cred.get("email")
            or claims.get("email")
            or ""
        ),
        "expires_at": _ts_to_iso_offset(exp),
        "first_name": str(
            cred.get("first_name")
            or claims.get("given_name")
            or claims.get("first_name")
            or claims.get("name")
            or ""
        ),
        "key": access,
        "oidc_client_id": str(
            cred.get("oidc_client_id")
            or claims.get("client_id")
            or GROK_CLI_CLIENT_ID
        ),
        "oidc_issuer": str(cred.get("oidc_issuer") or OIDC_ISSUER),
        "principal_id": str(claims.get("principal_id") or user_id),
        "principal_type": str(
            cred.get("principal_type") or claims.get("principal_type") or "User"
        ),
        "profile_image_asset_id": str(
            cred.get("profile_image_asset_id")
            or claims.get("profile_image_asset_id")
            or ""
        ),
        "refresh_token": str(cred.get("refresh_token") or ""),
        "team_id": team_id,
        "user_id": user_id,
    }


def auth_map_key(item: dict[str, Any]) -> str:
    """Object-map key used by grokcli / ~/.grok/auth.json."""
    issuer = str(item.get("oidc_issuer") or OIDC_ISSUER)
    uid = str(item.get("user_id") or item.get("principal_id") or GROK_CLI_CLIENT_ID)
    return f"{issuer}::{uid}"


def load_oidc_entries(path: Path) -> list[dict[str, Any]]:
    """Load oidc_auth.json; return list of raw credential dicts."""
    raw = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(raw, list):
        return [e for e in raw if isinstance(e, dict)]
    if not isinstance(raw, dict):
        raise ValueError(f"unsupported oidc auth JSON type: {type(raw).__name__}")

    # disk cache: {version, entries: {...}, updated_at}
    entries = raw.get("entries")
    if isinstance(entries, dict):
        return [e for e in entries.values() if isinstance(e, dict)]
    if isinstance(entries, list):
        return [e for e in entries if isinstance(e, dict)]

    # already a grokcli object map: { "issuer::uid": {...}, ... }
    if raw and all(isinstance(v, dict) for v in raw.values()):
        # skip non-entry top-level meta keys if mixed
        out: list[dict[str, Any]] = []
        for k, v in raw.items():
            if k in {"version", "updated_at", "entries"}:
                continue
            if isinstance(v, dict) and (v.get("access_token") or v.get("key") or v.get("refresh_token")):
                out.append(v)
        if out:
            return out

    raise ValueError(f"no entries found in {path}")


def convert(
    creds: list[dict[str, Any]],
    *,
    skip_empty_key: bool = True,
    sort: bool = True,
) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    skipped = 0
    for cred in creds:
        item = to_grok_auth_item(cred)
        if skip_empty_key and not item.get("key"):
            skipped += 1
            continue
        items.append(item)
    if sort:
        items.sort(key=lambda x: (x.get("user_id") or "", x.get("team_id") or ""))
    return items


def _write_json(path: Path, payload: Any, *, compact: bool) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if compact:
        text = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    else:
        text = json.dumps(payload, indent=2, ensure_ascii=False)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text + "\n", encoding="utf-8")
    tmp.replace(path)


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Convert oidc_auth.json disk cache → ~/.grok/auth.json-style array"
    )
    ap.add_argument(
        "--input",
        "-i",
        type=Path,
        default=_ROOT / "data" / "oidc_auth.json",
        help="Source OIDC cache (default: data/oidc_auth.json)",
    )
    ap.add_argument(
        "--output",
        "-o",
        type=Path,
        default=_ROOT / "data" / "auth_array.json",
        help="Output array JSON (default: data/auth_array.json)",
    )
    ap.add_argument(
        "--also-map",
        type=Path,
        default=None,
        help="Also write object-map auth.json (issuer::user_id → entry)",
    )
    ap.add_argument(
        "--compact",
        action="store_true",
        help="Write minified JSON (no indent)",
    )
    ap.add_argument(
        "--keep-empty-key",
        action="store_true",
        help="Keep entries missing access_token/key (default: skip)",
    )
    ap.add_argument(
        "--no-sort",
        action="store_true",
        help="Do not sort by user_id",
    )
    args = ap.parse_args()

    if not args.input.is_file():
        print(f"input not found: {args.input}", file=sys.stderr)
        return 2

    try:
        creds = load_oidc_entries(args.input)
    except Exception as exc:  # noqa: BLE001
        print(f"failed to load {args.input}: {exc}", file=sys.stderr)
        return 2

    items = convert(
        creds,
        skip_empty_key=not args.keep_empty_key,
        sort=not args.no_sort,
    )
    _write_json(args.output, items, compact=bool(args.compact))

    print(
        f"converted {len(items)}/{len(creds)} entries\n"
        f"  input:  {args.input}\n"
        f"  output: {args.output}  ({args.output.stat().st_size} bytes)",
        flush=True,
    )

    if args.also_map is not None:
        obj: dict[str, Any] = {}
        for item in items:
            obj[auth_map_key(item)] = item
        _write_json(args.also_map, obj, compact=bool(args.compact))
        print(f"  map:    {args.also_map}  ({args.also_map.stat().st_size} bytes)", flush=True)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
