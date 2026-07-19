"""Sandbox code_execution media harvest + local materialisation."""

from __future__ import annotations

import base64
import unittest
from unittest.mock import AsyncMock, patch

from app.dataplane.reverse.protocol.sandbox_artifacts import (
    base64_target_from_bash_command,
    classify_media_bytes,
    extract_b64_file_markers,
    find_sandbox_media_paths,
    looks_like_base64,
    materialize_sandbox_media,
    merge_personality_with_artifact_hint,
    paths_from_bash_command,
    strip_b64_markers,
)


# Minimal ISO BMFF / ftyp fragment (enough for classify)
_MINI_MP4 = (
    b"\x00\x00\x00\x18ftypisom\x00\x00\x00\x00isomiso2"
    + b"\x00" * 64
)


class PathAndBashParsingTests(unittest.TestCase):
    def test_find_sandbox_paths(self) -> None:
        text = "saved to `/home/workdir/artifacts/cute_kitten_1s.mp4` done"
        paths = find_sandbox_media_paths(text)
        self.assertEqual(paths, ["/home/workdir/artifacts/cute_kitten_1s.mp4"])

    def test_paths_from_ffmpeg_and_redirect(self) -> None:
        cmd = 'ffmpeg -y -i in.mp4 /home/workdir/artifacts/out.mp4'
        self.assertIn(
            "/home/workdir/artifacts/out.mp4", paths_from_bash_command(cmd)
        )
        cmd2 = 'echo x > /home/workdir/artifacts/a.webm'
        self.assertIn(
            "/home/workdir/artifacts/a.webm", paths_from_bash_command(cmd2)
        )

    def test_base64_target(self) -> None:
        cmd = "base64 -w0 /home/workdir/artifacts/demo.mp4"
        self.assertEqual(
            base64_target_from_bash_command(cmd),
            "/home/workdir/artifacts/demo.mp4",
        )

    def test_b64_markers(self) -> None:
        b64 = base64.b64encode(_MINI_MP4).decode()
        text = f"file ready\nB64_FILE:demo.mp4:{b64}\n"
        markers = extract_b64_file_markers(text)
        self.assertIn("demo.mp4", markers)
        self.assertTrue(looks_like_base64(markers["demo.mp4"]))
        self.assertEqual(classify_media_bytes(_MINI_MP4), "video")
        stripped = strip_b64_markers(text)
        self.assertNotIn("B64_FILE", stripped)


class MaterializeTests(unittest.IsolatedAsyncioTestCase):
    async def test_materialize_rewrites_path_to_local_video(self) -> None:
        b64 = base64.b64encode(_MINI_MP4).decode()
        path = "/home/workdir/artifacts/cute_kitten_1s.mp4"
        text = f"Video at {path}\nB64:{b64}\n"

        with (
            patch(
                "app.dataplane.reverse.protocol.sandbox_artifacts.save_local_video",
                return_value=None,
            ) as save,
            patch(
                "app.dataplane.reverse.protocol.sandbox_artifacts.build_signed_media_url",
                return_value="http://localhost:8000/v1/files/video?id=abc&exp=1&sig=s",
            ),
            patch(
                "app.dataplane.reverse.protocol.sandbox_artifacts.get_config",
            ) as cfg,
        ):
            cfg.return_value.get_str.side_effect = lambda key, default="": {
                "app.app_url": "http://localhost:8000",
                "features.video_format": "local_url",
                "features.image_format": "local_url",
            }.get(key, default)

            rewritten, embeds = await materialize_sandbox_media(
                text,
                known_paths={path},
                known_b64={path: b64},
            )

        save.assert_called_once()
        self.assertIn("/v1/files/video?", rewritten)
        self.assertIn("<video", rewritten)
        self.assertNotIn(path, rewritten)
        self.assertNotIn("B64:", rewritten)
        self.assertTrue(embeds)
        self.assertIn("/v1/files/video?", embeds[0])
        self.assertIn("<video", embeds[0])

    async def test_strips_fenced_and_line_base64(self) -> None:
        b64 = base64.b64encode(_MINI_MP4).decode()
        path = "/home/workdir/artifacts/clip.mp4"
        text = (
            f"done {path}\n"
            f"```base64\n{b64}\n```\n"
            f"{b64}\n"
        )
        with (
            patch(
                "app.dataplane.reverse.protocol.sandbox_artifacts.save_local_video",
                return_value=None,
            ),
            patch(
                "app.dataplane.reverse.protocol.sandbox_artifacts.build_signed_media_url",
                return_value="http://localhost:8000/v1/files/video?id=x&exp=1&sig=s",
            ),
            patch(
                "app.dataplane.reverse.protocol.sandbox_artifacts.get_config",
            ) as cfg,
        ):
            cfg.return_value.get_str.side_effect = lambda key, default="": {
                "app.app_url": "http://localhost:8000",
                "features.video_format": "local_url",
                "features.image_format": "local_url",
            }.get(key, default)
            rewritten, embeds = await materialize_sandbox_media(text)

        self.assertNotIn(b64[:40], rewritten)
        self.assertIn("<video", rewritten)
        self.assertTrue(embeds)

    def test_personality_hint_merged(self) -> None:
        merged = merge_personality_with_artifact_hint("be concise")
        self.assertIn("be concise", merged)
        self.assertIn("B64_FILE:", merged)


if __name__ == "__main__":
    unittest.main()
