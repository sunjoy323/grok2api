#!/usr/bin/env python3
"""Export grok2api SSO/OIDC credentials into CLIProxyAPI xAI auth JSON files.

CLIProxyAPI (router-for-me/CLIProxyAPI) stores each Grok/xAI OAuth account as one
JSON file under the auth directory, e.g. ~/.cli-proxy-api/xai-<sub>.json.

Source data (grok2api):
  - data/accounts.db        SSO tokens (accounts.token)
  - data/oidc_auth.json     OIDC cache: entries[sso_sha256] -> {
        access_token, refresh_token, expires_at, user_id, team_id, scope
    }

Output (CLIProxyAPI TokenStorage shape, internal/auth/xai/token.go):
  {
    "type": "xai",
    "access_token": "...",
    "refresh_token": "...",
    "token_type": "Bearer",
    "expires_in": 21600,
    "expired": "2026-01-01T00:00:00Z",
    "last_refresh": "2026-01-01T00:00:00Z",
    "email": "",
    "sub": "<user_id>",
    "base_url": "https://api.x.ai/v1",
    "token_endpoint": "https://auth.x.ai/oauth2/token",
    "auth_kind": "oauth"
  }

Filename: xai-<email>.json  or  xai-<sub>.json  (CLIProxyAPI CredentialFileName)

Usage:
  # All accounts that have OIDC on disk
  uv run python scripts/export_cliproxy_xai.py --out-dir ./data/cliproxy-xai

  # Only fresh OIDC (expires_at > now+120s)
  uv run python scripts/export_cliproxy_xai.py --out-dir ./data/cliproxy-xai --fresh-only

  # Single combined JSON map (debug)
  uv run python scripts/export_cliproxy_xai.py --out-dir ./data/cliproxy-xai --also-bundle

Notes:
  - access_token may already be expired; CLIProxyAPI will refresh via refresh_token
    if the token is still valid at xAI.
  - SSO cookie alone is not what CLIProxyAPI reads; it needs OAuth access/refresh.
  - Put files into CLIProxyAPI auth-dir (often ~/.cli-proxy-api or config auth-dir).
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import sqlite3
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

OIDC_ISSUER = "https://auth.x.ai"
TOKEN_ENDPOINT = f"{OIDC_ISSUER}/oauth2/token"
# CLIProxyAPI default for OAuth Grok credentials (api.x.ai). Chat may still use
# cli-chat-proxy depending on using_api; leave default official base_url.
DEFAULT_BASE_URL = "https://api.x.ai/v1"
CLIENT_ID = "b1a00492-073a-47ea-816f-4c329264a828"


def _normalize_sso(raw: str) -> str:
    s = (raw or "").strip()
    if s.startswith("sso="):
        s = s[4:]
    return s.strip()


def sso_key(sso_token: str) -> str:
    return hashlib.sha256(_normalize_sso(sso_token).encode("utf-8")).hexdigest()


def decode_jwt_claims(token: str) -> dict:
    try:
        part = token.split(".")[1]
        pad = "=" * (-len(part) % 4)
        data = json.loads(base64.urlsafe_b64decode(part + pad))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def sanitize_file_segment(value: str) -> str:
    value = (value or "").strip()
    if not value:
        return ""
    out = []
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


def load_accounts(db_path: Path) -> list[str]:
    if not db_path.is_file():
        return []
    con = sqlite3.connect(str(db_path))
    try:
        rows = con.execute(
            "SELECT token FROM accounts WHERE status = 'active' "
            "AND (deleted_at IS NULL OR deleted_at = 0)"
        ).fetchall()
    finally:
        con.close()
    return [_normalize_sso(r[0]) for r in rows if r and r[0]]


def load_oidc(path: Path) -> dict[str, dict]:
    if not path.is_file():
        return {}
    raw = json.loads(path.read_text(encoding="utf-8"))
    entries = raw.get("entries") if isinstance(raw, dict) else None
    if not isinstance(entries, dict):
        return {}
    out: dict[str, dict] = {}
    for k, v in entries.items():
        if isinstance(v, dict) and v.get("access_token"):
            out[str(k)] = v
    return out


def to_cliproxy_entry(cred: dict, *, email: str = "") -> dict:
    access = str(cred.get("access_token") or "")
    claims = decode_jwt_claims(access)
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
        # optional extras (harmless if ignored by CLIProxyAPI)
        "team_id": str(cred.get("team_id") or claims.get("team_id") or ""),
        "scope": str(cred.get("scope") or claims.get("scope") or ""),
        "oidc_client_id": CLIENT_ID,
        "oidc_issuer": OIDC_ISSUER,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Export grok2api OIDC → CLIProxyAPI xai-*.json")
    ap.add_argument("--db", type=Path, default=_ROOT / "data" / "accounts.db")
    ap.add_argument("--oidc", type=Path, default=_ROOT / "data" / "oidc_auth.json")
    ap.add_argument("--out-dir", type=Path, required=True, help="Directory for xai-*.json files")
    ap.add_argument(
        "--fresh-only",
        action="store_true",
        help="Only export entries with expires_at > now+120s",
    )
    ap.add_argument(
        "--require-refresh",
        action="store_true",
        default=False,
        help="Skip entries without refresh_token (recommended for long-lived use)",
    )
    ap.add_argument(
        "--also-bundle",
        action="store_true",
        help="Also write cliproxy_xai_bundle.json (filename -> entry map)",
    )
    ap.add_argument("--limit", type=int, default=0, help="Max files to write (0=all)")
    args = ap.parse_args()

    accounts = load_accounts(args.db)
    oidc = load_oidc(args.oidc)
    now = time.time()

    # Prefer pairing via sso hash when account list available; else dump all oidc entries.
    pairs: list[tuple[str | None, dict]] = []
    if accounts:
        for sso in accounts:
            ent = oidc.get(sso_key(sso))
            if ent:
                pairs.append((sso, ent))
        # Also include orphan oidc entries not in accounts.db
        known = {sso_key(s) for s, _ in pairs if s}
        for k, ent in oidc.items():
            if k not in known:
                pairs.append((None, ent))
    else:
        pairs = [(None, ent) for ent in oidc.values()]

    args.out_dir.mkdir(parents=True, exist_ok=True)
    written = 0
    skipped = 0
    bundle: dict[str, dict] = {}
    used_names: set[str] = set()

    for sso, cred in pairs:
        if args.require_refresh and not cred.get("refresh_token"):
            skipped += 1
            continue
        exp_at = float(cred.get("expires_at") or 0)
        if args.fresh_only and exp_at <= now + 120:
            skipped += 1
            continue
        if not cred.get("access_token"):
            skipped += 1
            continue

        entry = to_cliproxy_entry(cred)
        if not entry["sub"] and not entry["access_token"]:
            skipped += 1
            continue

        name = credential_file_name(entry.get("email") or "", entry.get("sub") or "")
        # avoid overwrite collisions
        if name in used_names:
            stem = name[:-5] if name.endswith(".json") else name
            n = 2
            while f"{stem}-{n}.json" in used_names:
                n += 1
            name = f"{stem}-{n}.json"
        used_names.add(name)

        path = args.out_dir / name
        path.write_text(json.dumps(entry, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        bundle[name] = entry
        written += 1
        if args.limit and written >= args.limit:
            break

    if args.also_bundle:
        bp = args.out_dir / "cliproxy_xai_bundle.json"
        bp.write_text(json.dumps(bundle, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    print(
        f"Done: written={written} skipped={skipped} "
        f"accounts={len(accounts)} oidc_entries={len(oidc)} out={args.out_dir}"
    )
    print(
        "Copy *.json into CLIProxyAPI auth directory (e.g. ~/.cli-proxy-api), "
        "then restart CLIProxyAPI."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
