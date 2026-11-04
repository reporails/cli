"""What an image costs in tokens: the header readers of the four formats, the resize rule and the model tiers."""

from __future__ import annotations

import base64

import pytest

from reporails_cli.core.eventbus.adapters.claude_images import (
    count_image_tokens,
    high_resolution,
    price_image,
    resized_size,
)
from reporails_cli.core.platform.dto.events import ImageTokens

pytestmark = [pytest.mark.unit, pytest.mark.subsys_eventbus]


def _png(width: int, height: int) -> bytes:
    return (
        b"\x89PNG\r\n\x1a\n" + (13).to_bytes(4, "big") + b"IHDR" + width.to_bytes(4, "big") + height.to_bytes(4, "big")
    )


def _gif(width: int, height: int) -> bytes:
    return b"GIF89a" + width.to_bytes(2, "little") + height.to_bytes(2, "little") + b"\x00\x00\x00"


def _webp_lossy(width: int, height: int) -> bytes:
    frame = b"\x00\x00\x00" + b"\x9d\x01\x2a" + width.to_bytes(2, "little") + height.to_bytes(2, "little")
    return b"RIFF" + bytes(4) + b"WEBP" + b"VP8 " + bytes(4) + frame


def _webp_lossless(width: int, height: int) -> bytes:
    bits = (width - 1) | ((height - 1) << 14)
    return b"RIFF" + bytes(4) + b"WEBP" + b"VP8L" + bytes(4) + b"\x2f" + bits.to_bytes(4, "little") + bytes(4)


def _webp_extended(width: int, height: int) -> bytes:
    canvas = bytes(4) + (width - 1).to_bytes(3, "little") + (height - 1).to_bytes(3, "little")
    return b"RIFF" + bytes(4) + b"WEBP" + b"VP8X" + bytes(4) + canvas


def _jpeg(width: int, height: int) -> bytes:
    app0 = b"\xff\xe0" + (16).to_bytes(2, "big") + bytes(14)
    # A define-huffman-table segment comes first: its marker is C4, not a frame header.
    dht = b"\xff\xc4" + (5).to_bytes(2, "big") + bytes(3)
    frame = b"\xff\xc2" + (11).to_bytes(2, "big") + b"\x08" + height.to_bytes(2, "big") + width.to_bytes(2, "big")
    return b"\xff\xd8" + app0 + dht + frame + bytes(20)


def _source(data: bytes, media_type: str) -> dict[str, str | list[str] | None]:
    return {"type": "base64", "media_type": media_type, "data": base64.b64encode(data).decode()}


@pytest.mark.parametrize(
    ("data", "media_type"),
    [
        (_png(1920, 1080), "image/png"),
        (_gif(1920, 1080), "image/gif"),
        (_webp_lossy(1920, 1080), "image/webp"),
        (_webp_lossless(1920, 1080), "image/webp"),
        (_webp_extended(1920, 1080), "image/webp"),
        (_jpeg(1920, 1080), "image/jpeg"),
    ],
    ids=["png", "gif", "webp lossy", "webp lossless", "webp extended", "jpeg"],
)
def test_the_size_is_read_from_the_header_of_each_format(data: bytes, media_type: str) -> None:
    assert price_image(_source(data, media_type)) == ImageTokens(1560, 2691)


def test_a_header_that_does_not_read_is_unpriced() -> None:
    assert price_image(_source(_png(10, 10), "image/jpeg")) is None
    assert price_image(_source(b"\x89PNG", "image/png")) is None
    assert price_image({"type": "url", "url": "http://x"}) is None


@pytest.mark.parametrize(
    ("width", "height", "standard", "high"),
    [
        (200, 200, 64, 64),
        (1000, 1000, 1296, 1296),
        (1092, 1092, 1521, 1521),
        (1920, 1080, 1560, 2691),
        (2000, 1500, 1564, 3888),
        (3840, 2160, 1560, 4784),
    ],
)
def test_the_token_cost_matches_the_docs_table_at_both_tiers(width: int, height: int, standard: int, high: int) -> None:
    got = price_image(_source(_png(width, height), "image/png"))
    assert got == ImageTokens(standard, high)


def test_a_portrait_image_is_resized_like_the_docs_reference() -> None:
    assert resized_size(1075, 1520, 1568, 1568) == (924, 1307)
    assert count_image_tokens(200, 200) == 64


@pytest.mark.parametrize(
    ("model", "tier"),
    [
        ("claude-opus-4-7", True),
        ("claude-opus-4-8", True),
        ("claude-opus-5-5", True),
        ("claude-haiku-5-5", True),
        ("claude-fable-5-1", True),
        ("claude-mythos-5", True),
        ("us.anthropic.claude-opus-4-7-v1", True),
        ("claude-opus-4-7@20260101", True),
        ("claude-sonnet-4-6", False),
        ("claude-opus-4-6", False),
        ("claude-haiku-4-5-20251001", False),
        ("claude-sonnet-4-5-20250929", False),
        ("claude-opus-4-20250514", False),
        ("claude-3-5-sonnet-20241022", False),
        ("claude-3-opus-20240229", False),
        ("gpt-5", None),
        ("", None),
    ],
)
def test_the_tier_follows_the_model_generation(model: str, tier: bool | None) -> None:
    assert high_resolution(model) is tier
