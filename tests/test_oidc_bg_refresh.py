"""Unit tests for OIDC background refresh-only warm-up (rotate_warm)."""

from __future__ import annotations

import time
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from app.dataplane.reverse.protocol import xai_oidc as oidc
from app.platform.errors import UpstreamError


class _Cfg:
    def __init__(self, data: dict[str, Any] | None = None):
        self._d = data or {}

    def get_bool(self, key: str, default: bool = False) -> bool:
        return bool(self._d.get(key, default))

    def get_str(self, key: str, default: str = "") -> str:
        return str(self._d.get(key, default))

    def get_float(self, key: str, default: float = 0.0) -> float:
        return float(self._d.get(key, default))

    def get_int(self, key: str, default: int = 0) -> int:
        return int(self._d.get(key, default))


@pytest.fixture(autouse=True)
def _clean_bg_state():
    oidc._BG_INVALID_GRANT.clear()
    oidc._BG_REFRESH_CURSOR = 0
    for k in list(oidc._BG_STATS):
        oidc._BG_STATS[k] = 0
    yield
    oidc._BG_INVALID_GRANT.clear()
    oidc._BG_REFRESH_CURSOR = 0


def test_bg_refresh_enabled_by_rotate_warm():
    assert oidc._bg_refresh_enabled(_Cfg({"chat.cli_account_selection": "rotate_warm"}))
    assert oidc._bg_refresh_enabled(_Cfg({"chat.cli_account_selection": "rotate-warm"}))
    assert not oidc._bg_refresh_enabled(_Cfg({"chat.cli_account_selection": "rotate"}))
    assert not oidc._bg_refresh_enabled(
        _Cfg({"chat.cli_account_selection": "warm_prefer"})
    )


def test_bg_refresh_enabled_by_force_flag():
    assert oidc._bg_refresh_enabled(
        _Cfg(
            {
                "chat.cli_account_selection": "warm_prefer",
                "chat.cli_oidc_bg_refresh": True,
            }
        )
    )


def test_needs_bg_refresh_lead_window():
    now = time.time()
    # Fresh beyond lead → skip
    assert not oidc._needs_bg_refresh(
        {"refresh_token": "r", "expires_at": now + 7200, "access_token": "a"},
        lead_s=3600,
        now=now,
    )
    # Within lead → need refresh
    assert oidc._needs_bg_refresh(
        {"refresh_token": "r", "expires_at": now + 1800, "access_token": "a"},
        lead_s=3600,
        now=now,
    )
    # Expired but has refresh → need
    assert oidc._needs_bg_refresh(
        {"refresh_token": "r", "expires_at": now - 10, "access_token": "a"},
        lead_s=3600,
        now=now,
    )
    # No refresh_token → skip
    assert not oidc._needs_bg_refresh(
        {"expires_at": now + 100, "access_token": "a"},
        lead_s=3600,
        now=now,
    )


def test_cli_prefer_tokens_rotate_warm_is_none():
    from app.products.openai.cli_chat import _cli_prefer_tokens

    cfg = _Cfg({"chat.cli_account_selection": "rotate_warm"})
    with patch(
        "app.products.openai.cli_chat._prefer_warm_tokens", return_value=["sso1"]
    ):
        assert _cli_prefer_tokens(cfg) is None


def test_refresh_one_entry_ok_with_sso():
    sso = "sso-token-for-bg-test"
    sk = oidc.sso_key(sso)
    now = time.time()
    live = {
        "access_token": "old",
        "refresh_token": "rt-old",
        "expires_at": now + 600,
    }
    refreshed = {
        "access_token": "new",
        "refresh_token": "rt-new",
        "expires_at": now + 21600,
    }
    oidc._OIDC_CACHE[sso] = live
    oidc._HASH_TO_SSO[sk] = sso

    with (
        patch.object(oidc, "refresh_oidc", return_value=refreshed) as m_refresh,
        patch.object(oidc, "save_disk_entry") as m_save,
    ):
        status = oidc._refresh_one_entry(sk, sso, live, lead_s=3600.0)

    assert status == "ok"
    m_refresh.assert_called_once()
    m_save.assert_called_once()
    assert oidc._OIDC_CACHE[sso]["access_token"] == "new"
    oidc._OIDC_CACHE.pop(sso, None)
    oidc._HASH_TO_SSO.pop(sk, None)
    oidc._WARM_HASHES.discard(sk)


def test_refresh_one_entry_invalid_grant_skipped_next():
    sso = "sso-invalid-grant-bg"
    sk = oidc.sso_key(sso)
    now = time.time()
    live = {
        "access_token": "old",
        "refresh_token": "rt-dead",
        "expires_at": now + 100,
    }
    oidc._OIDC_CACHE[sso] = dict(live)

    err = UpstreamError("token refresh failed", body="invalid_grant")
    with (
        patch.object(oidc, "refresh_oidc", side_effect=err),
        patch.object(oidc, "_drop_cred") as m_drop,
    ):
        status = oidc._refresh_one_entry(sk, sso, live, lead_s=3600.0)

    assert status == "invalid_grant"
    assert sk in oidc._BG_INVALID_GRANT
    m_drop.assert_called_once()
    # Second call short-circuits without network.
    with patch.object(oidc, "refresh_oidc") as m2:
        assert oidc._refresh_one_entry(sk, sso, live, lead_s=3600.0) == "invalid_grant"
        m2.assert_not_called()

    oidc._OIDC_CACHE.pop(sso, None)
    oidc._BG_INVALID_GRANT.discard(sk)


def test_collect_candidates_round_robin_and_cap():
    now = time.time()
    entries: dict[str, dict[str, Any]] = {}
    for i in range(5):
        sk = f"hash{i:02d}"
        entries[sk] = {
            "access_token": f"a{i}",
            "refresh_token": f"r{i}",
            # All within lead → candidates
            "expires_at": now + 600,
        }
    # One far-future → not a candidate
    entries["hash99"] = {
        "access_token": "afresh",
        "refresh_token": "rfresh",
        "expires_at": now + 100000,
    }

    with (
        patch.object(oidc, "_ensure_disk_loaded"),
        patch.object(oidc, "load_disk_cache", return_value={"entries": entries}),
    ):
        cands, cursor = oidc._collect_bg_refresh_candidates(
            lead_s=3600.0, max_n=2, start=0
        )
        assert len(cands) == 2
        assert all(c[0].startswith("hash") for c in cands)
        # Next cycle continues from cursor
        cands2, _ = oidc._collect_bg_refresh_candidates(
            lead_s=3600.0, max_n=10, start=cursor
        )
        # Remaining near-expiry (3) + no wrap of fresh-only if still within lead set
        assert len(cands2) >= 1


def test_run_cycle_refreshes_candidates():
    now = time.time()
    sk = "deadbeef" * 4  # 32 hex-like
    entries = {
        sk: {
            "access_token": "a",
            "refresh_token": "r",
            "expires_at": now + 300,
        }
    }
    refreshed = {
        "access_token": "a2",
        "refresh_token": "r2",
        "expires_at": now + 20000,
    }
    cfg = _Cfg(
        {
            "chat.cli_account_selection": "rotate_warm",
            "chat.cli_oidc_bg_refresh_max_per_cycle": 8,
            "chat.cli_oidc_bg_refresh_concurrency": 1,
            "chat.cli_oidc_bg_refresh_item_delay_sec": 0,
            "chat.cli_oidc_bg_refresh_lead_sec": 3600,
            "chat.cli_oidc_bg_refresh_interval_sec": 120,
        }
    )

    with (
        patch.object(oidc, "_ensure_disk_loaded"),
        patch.object(oidc, "load_disk_cache", return_value={"entries": entries}),
        patch.object(oidc, "refresh_oidc", return_value=refreshed) as m_ref,
        patch.object(oidc, "save_disk_entry"),
        patch.object(oidc, "_HASH_TO_SSO", {sk: "sso-x"}),
        patch.dict(oidc._OIDC_CACHE, {"sso-x": entries[sk]}, clear=False),
    ):
        # Ensure memory has the entry under full SSO for lock path
        oidc._OIDC_CACHE["sso-x"] = dict(entries[sk])
        stats = oidc.run_oidc_bg_refresh_cycle(cfg)

    assert stats["candidates"] == 1
    assert stats["ok"] == 1
    m_ref.assert_called_once()
    oidc._OIDC_CACHE.pop("sso-x", None)
