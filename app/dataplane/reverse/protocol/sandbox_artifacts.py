"""Extract media files produced by Grok code_execution / bash sandboxes.

Grok's code interpreter writes files under ``/home/workdir/artifacts/`` but the
SSE API does **not** expose a download URL.  Within the same turn the model can
still ``base64`` those files; we harvest that base64 (from tool stdout or the
final answer), persist bytes locally, and rewrite paths to signed proxy URLs.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import re
from typing import Any

from app.platform.auth.media_sign import build_signed_media_url
from app.platform.config.snapshot import get_config
from app.platform.logging.logger import logger
from app.platform.storage import save_local_image, save_local_video

_VIDEO_EXTS = (".mp4", ".webm", ".mov", ".m4v", ".mkv", ".avi", ".ogg")
_IMAGE_EXTS = (".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp")
_MEDIA_EXTS = _VIDEO_EXTS + _IMAGE_EXTS

# Absolute sandbox paths written by Grok code_execution / bash tools.
_SANDBOX_PATH_RE = re.compile(
    r"(?<![\w./-])(/home/workdir/artifacts/[^\s`\"'<>\]\)]+?(?:"
    + "|".join(re.escape(ext) for ext in _MEDIA_EXTS)
    + r"))",
    re.IGNORECASE,
)

# Explicit client-friendly markers we ask the model to emit.
_B64_FILE_RE = re.compile(
    r"B64_FILE:([^\s:]+):([A-Za-z0-9+/=\s]+)",
    re.IGNORECASE,
)
_B64_INLINE_RE = re.compile(
    r"B64:([A-Za-z0-9+/=\s]{64,})",
    re.IGNORECASE,
)
# Model sometimes dumps bare base64 in fenced code blocks or long lines.
_B64_FENCE_RE = re.compile(
    r"```(?:base64|text|plain|bin|mp4|data)?\s*\n([A-Za-z0-9+/=\s]{64,})\n```",
    re.IGNORECASE,
)
_B64_LINE_RE = re.compile(r"(?m)^[A-Za-z0-9+/]{80,}={0,2}\s*$")
_DATA_VIDEO_RE = re.compile(
    r"data:video/[\w.+-]+;base64,[A-Za-z0-9+/=]+",
    re.IGNORECASE,
)
_DATA_IMAGE_RE = re.compile(
    r"data:image/[\w.+-]+;base64,[A-Za-z0-9+/=]+",
    re.IGNORECASE,
)

# bash / shell writes that target artifact media paths
_WRITE_REDIRECT_RE = re.compile(
    r"(?:(?:>|>>)\s*|tee\s+(?:-a\s+)?)(['\"]?)(/home/workdir/artifacts/[^\s'\"|;&]+)\1",
    re.IGNORECASE,
)
_FFMPEG_OUT_RE = re.compile(
    r"ffmpeg\b[^\n]*?\s(['\"]?)(/home/workdir/artifacts/[^\s'\"|;&]+)\1\s*$",
    re.IGNORECASE | re.MULTILINE,
)
_BASE64_CMD_RE = re.compile(
    r"\bbase64\b(?:\s+-w0)?\s+(['\"]?)(/home/workdir/artifacts/[^\s'\"]+)\1",
    re.IGNORECASE,
)

_ARTIFACT_HINT = (
    "When you create media files (mp4/webm/mov/png/jpg/gif/webp) under "
    "/home/workdir/artifacts via code_execution or bash, always also run "
    "`base64 -w0 <file>` and include the complete base64 in your final answer as "
    "`B64_FILE:<filename>:<base64>` so the client can download the binary. "
    "Do not only report the sandbox path."
)


def artifact_retrieval_hint() -> str:
    """Instruction merged into customPersonality so models emit base64."""
    return _ARTIFACT_HINT


def find_sandbox_media_paths(text: str) -> list[str]:
    if not text:
        return []
    seen: set[str] = set()
    out: list[str] = []
    for match in _SANDBOX_PATH_RE.finditer(text):
        path = match.group(1).rstrip(".,;:)")
        if path not in seen:
            seen.add(path)
            out.append(path)
    return out


def paths_from_bash_command(command: str) -> list[str]:
    """Return artifact media paths referenced as outputs in a bash command."""
    if not command:
        return []
    found: list[str] = []
    seen: set[str] = set()
    for rx in (_WRITE_REDIRECT_RE, _FFMPEG_OUT_RE):
        for match in rx.finditer(command):
            path = match.group(2)
            if _is_media_path(path) and path not in seen:
                seen.add(path)
                found.append(path)
    # also plain path mentions for ffmpeg -i input - output style last arg
    for path in find_sandbox_media_paths(command):
        if path not in seen:
            # only treat as output if appears after redirect-ish tokens or as trailing arg
            if re.search(
                rf"(?:>|>>|tee\s+|ffmpeg\b[^\n]*\s){re.escape(path)}",
                command,
                re.IGNORECASE,
            ):
                seen.add(path)
                found.append(path)
    return found


def base64_target_from_bash_command(command: str) -> str | None:
    if not command:
        return None
    match = _BASE64_CMD_RE.search(command)
    if not match:
        return None
    path = match.group(2)
    return path if _is_media_path(path) else None


def looks_like_base64(value: str) -> bool:
    s = re.sub(r"\s+", "", value or "")
    if len(s) < 64 or len(s) % 4 not in {0, 1}:  # allow slight padding issues
        # base64 length usually multiple of 4; still accept long alnum runs
        if len(s) < 64:
            return False
    if not re.fullmatch(r"[A-Za-z0-9+/]+=*", s):
        return False
    return True


def decode_base64_media(value: str) -> tuple[bytes, str] | None:
    """Decode base64 and classify as video/image. Returns (raw, kind) or None."""
    s = re.sub(r"\s+", "", value or "")
    if not looks_like_base64(s):
        return None
    try:
        raw = base64.b64decode(s, validate=False)
    except Exception:
        return None
    if len(raw) < 16:
        return None
    kind = classify_media_bytes(raw)
    if kind is None:
        return None
    return raw, kind


def classify_media_bytes(raw: bytes) -> str | None:
    if len(raw) >= 12 and raw[4:8] == b"ftyp":
        return "video"
    if raw.startswith(b"\x1aE\xdf\xa3"):  # EBML / webm
        return "video"
    if raw.startswith(b"\x00\x00\x00\x14ftypqt") or raw.startswith(b"\x00\x00\x00\x18ftyp"):
        return "video"
    if raw.startswith(b"\xff\xd8\xff"):
        return "image"
    if raw.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image"
    if raw.startswith(b"GIF8"):
        return "image"
    if raw.startswith(b"RIFF") and b"WEBP" in raw[:16]:
        return "image"
    # mp4 sometimes without checking offset 4
    if b"ftyp" in raw[:64]:
        return "video"
    return None


def extract_b64_file_markers(text: str) -> dict[str, str]:
    """Parse ``B64_FILE:<name>:<b64>`` markers → {path_or_name: b64}."""
    out: dict[str, str] = {}
    if not text:
        return out
    for match in _B64_FILE_RE.finditer(text):
        name = match.group(1).strip()
        b64 = re.sub(r"\s+", "", match.group(2))
        if not name or not looks_like_base64(b64):
            continue
        path = name if name.startswith("/") else f"/home/workdir/artifacts/{name}"
        out[path] = b64
        out[name] = b64
    return out


def extract_inline_b64_blobs(text: str) -> list[str]:
    if not text:
        return []
    blobs: list[str] = []
    for rx in (_B64_INLINE_RE, _B64_FENCE_RE):
        for match in rx.finditer(text):
            b64 = re.sub(r"\s+", "", match.group(1))
            if looks_like_base64(b64):
                blobs.append(b64)
    for match in _B64_LINE_RE.finditer(text):
        b64 = re.sub(r"\s+", "", match.group(0))
        if looks_like_base64(b64):
            blobs.append(b64)
    # de-dupe while preserving order
    seen: set[str] = set()
    out: list[str] = []
    for b in blobs:
        if b not in seen:
            seen.add(b)
            out.append(b)
    return out


def strip_b64_markers(text: str) -> str:
    """Remove bulky base64 markers / dumps from user-visible answer text."""
    if not text:
        return text
    text = _B64_FILE_RE.sub("", text)
    text = _B64_INLINE_RE.sub("", text)
    text = _B64_FENCE_RE.sub("", text)
    text = _B64_LINE_RE.sub("", text)
    text = _DATA_VIDEO_RE.sub("", text)
    # Keep data:image only when short (tiny icons); drop huge dumps
    def _drop_huge_data_image(match: re.Match[str]) -> str:
        return "" if len(match.group(0)) > 200 else match.group(0)

    text = _DATA_IMAGE_RE.sub(_drop_huge_data_image, text)
    # collapse leftover blank lines
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def media_kind_for_path(path: str) -> str | None:
    lower = path.lower()
    if any(lower.endswith(ext) for ext in _VIDEO_EXTS):
        return "video"
    if any(lower.endswith(ext) for ext in _IMAGE_EXTS):
        return "image"
    return None


def _is_media_path(path: str) -> bool:
    return media_kind_for_path(path) is not None


def _file_id_for(path: str, raw: bytes) -> str:
    stem = path.rsplit("/", 1)[-1]
    # drop extension — save_local_* appends its own suffix
    if "." in stem:
        stem = stem.rsplit(".", 1)[0]
    stem = re.sub(r"[^0-9a-zA-Z_-]+", "_", stem)[:32] or "artifact"
    digest = hashlib.sha1(raw).hexdigest()[:16]
    # media routes accept [0-9a-f\-]{16,36}; use pure hex id for proxy URLs
    return digest


def _render_video_embed(url: str) -> str:
    """Return markdown-style video link.

    Do **not** emit raw ``<video>`` HTML here: chat UIs escape HTML before
    rendering markdown, which would turn tags into unplayable plain text.
    Clients convert ``[video](url)`` into a real ``<video>`` element.
    """
    return f"[video]({url})"


def _render_image_embed(url: str) -> str:
    """Always return markdown image so clients render <img>, not bare <a> links."""
    return f"![image]({url})"


async def materialize_sandbox_media(
    text: str,
    *,
    known_paths: set[str] | None = None,
    known_b64: dict[str, str] | None = None,
) -> tuple[str, list[str]]:
    """Persist harvested sandbox media and rewrite *text*.

    Returns ``(rewritten_text, embeds)``:
      - *rewritten_text*: sandbox paths replaced with local embeds; B64 markers stripped
      - *embeds*: every materialised media snippet (for streaming append)
    """
    known_paths = set(known_paths or ())
    known_b64 = dict(known_b64 or {})

    # markers in text
    known_b64.update(extract_b64_file_markers(text))
    paths = list(known_paths)
    for path in find_sandbox_media_paths(text):
        if path not in paths:
            paths.append(path)

    # associate unscoped inline B64: blobs with the first path lacking b64
    inline_blobs = extract_inline_b64_blobs(text)
    orphan_paths = [
        p
        for p in paths
        if p not in known_b64
        and not any(k.endswith(p.rsplit("/", 1)[-1]) for k in known_b64)
    ]
    for path, blob in zip(orphan_paths, inline_blobs):
        known_b64.setdefault(path, blob)

    # if only blobs and no paths, invent artifact names from media type
    if not paths and inline_blobs:
        for i, blob in enumerate(inline_blobs):
            decoded = decode_base64_media(blob)
            if not decoded:
                continue
            _raw, kind = decoded
            ext = ".mp4" if kind == "video" else ".png"
            path = f"/home/workdir/artifacts/generated_{i}{ext}"
            paths.append(path)
            known_b64[path] = blob

    if not paths and not known_b64:
        return text, []

    cfg = get_config()
    app_url = cfg.get_str("app.app_url", "").rstrip("/")
    rewritten = text
    embeds: list[str] = []

    for path in paths:
        b64 = known_b64.get(path) or known_b64.get(path.rsplit("/", 1)[-1])
        if not b64:
            continue
        decoded = decode_base64_media(b64)
        if not decoded:
            try:
                raw = base64.b64decode(re.sub(r"\s+", "", b64), validate=False)
            except Exception:
                continue
            kind = media_kind_for_path(path) or classify_media_bytes(raw)
            if kind is None or len(raw) < 16:
                continue
        else:
            raw, kind = decoded
            path_kind = media_kind_for_path(path)
            if path_kind:
                kind = path_kind

        file_id = _file_id_for(path, raw)
        try:
            if kind == "video":
                await asyncio.to_thread(save_local_video, raw, file_id)
                url = build_signed_media_url("video", file_id, app_url=app_url)
                embed = _render_video_embed(url)
            else:
                mime = "image/png"
                if raw.startswith(b"\xff\xd8\xff"):
                    mime = "image/jpeg"
                elif raw.startswith(b"GIF8"):
                    mime = "image/gif"
                elif raw.startswith(b"RIFF"):
                    mime = "image/webp"
                await asyncio.to_thread(save_local_image, raw, mime, file_id)
                url = build_signed_media_url("image", file_id, app_url=app_url)
                embed = _render_image_embed(url)
        except Exception as exc:
            logger.warning(
                "sandbox media materialize failed: path={} error={}", path, exc
            )
            continue

        embeds.append(embed)
        # Prefer replacing fenced path `.../file.mp4` with bare embed (no nested ticks)
        rewritten = rewritten.replace(f"`{path}`", embed)
        if path in rewritten:
            rewritten = rewritten.replace(path, embed)
        basename = path.rsplit("/", 1)[-1]
        if basename:
            rewritten = rewritten.replace(f"`{basename}`", embed)

        logger.info(
            "sandbox media materialized: path={} kind={} bytes={} file_id={}",
            path,
            kind,
            len(raw),
            file_id,
        )

    rewritten = strip_b64_markers(rewritten)
    return rewritten, embeds


def merge_personality_with_artifact_hint(custom: str) -> str:
    custom = (custom or "").strip()
    hint = artifact_retrieval_hint()
    if not custom:
        return hint
    if "B64_FILE:" in custom or "base64 -w0" in custom:
        return custom
    return f"{custom}\n\n{hint}"


__all__ = [
    "artifact_retrieval_hint",
    "find_sandbox_media_paths",
    "paths_from_bash_command",
    "base64_target_from_bash_command",
    "looks_like_base64",
    "decode_base64_media",
    "classify_media_bytes",
    "extract_b64_file_markers",
    "extract_inline_b64_blobs",
    "strip_b64_markers",
    "materialize_sandbox_media",
    "merge_personality_with_artifact_hint",
    "media_kind_for_path",
]
