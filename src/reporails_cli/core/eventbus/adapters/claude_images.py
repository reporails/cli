"""What an image in an API request costs in tokens, worked out from the picture's own size.

An image costs `ceil(width / 28) * ceil(height / 28)` visual tokens
(https://platform.claude.com/docs/en/build-with-claude/vision, "Resolution and token cost"). A picture larger than
the model's limits is first resized to the largest aspect-preserving size that fits both its longest edge and its
token budget (https://platform.claude.com/docs/en/build-with-claude/vision-coordinates, "How Claude resizes and
pads images"). Claude 4.7 and later models use the high-resolution limits (2,576 px, 4,784 tokens), every other
model the standard ones (1,568 px, 1,568 tokens).

The pixel size is read from the picture's header: PNG, GIF, WebP and JPEG. All but JPEG need only the first few
bytes of the base64 data; JPEG is decoded whole so its markers can be walked to the frame header. Picture data is
never stored, only the numbers.
"""

from __future__ import annotations

import base64
import binascii
import math
import re

from reporails_cli.core.platform.contract.json_value import JsonObject
from reporails_cli.core.platform.dto.events import ImageTokens

_PATCH = 28
_STANDARD = (1568, 1568)
_HIGH = (2576, 4784)
# Base64 characters that decode to the 48 bytes every header but JPEG's fits in.
_PREFIX_CHARS = 64
# The first Claude generation that prices images at the high-resolution tier.
_HIGH_FROM = (4, 7)
_FAMILY_FIRST = re.compile(r"claude-[a-z]+-(\d+)(?:-(\d{1,2})(?!\d))?")
_VERSION_FIRST = re.compile(r"claude-(\d+)(?:-(\d{1,2})(?!\d))?-[a-z]+")
_JPEG_STANDALONE = frozenset({0x01, 0xD8, *range(0xD0, 0xD8)})
_JPEG_NOT_FRAME = frozenset({0xC4, 0xC8, 0xCC})


def count_image_tokens(width: int, height: int) -> int:
    """The visual tokens of an image of `width` by `height` pixels as sent."""
    return math.ceil(width / _PATCH) * math.ceil(height / _PATCH)


def resized_size(width: int, height: int, max_edge: int, max_tokens: int) -> tuple[int, int]:
    """The size an image of `width` by `height` is resized to: itself when it fits `max_edge` and `max_tokens`,
    else the largest aspect-preserving size that does."""

    def fits(w: int, h: int) -> bool:
        return (
            math.ceil(w / _PATCH) * _PATCH <= max_edge
            and math.ceil(h / _PATCH) * _PATCH <= max_edge
            and count_image_tokens(w, h) <= max_tokens
        )

    if fits(width, height):
        return (width, height)
    if height > width:
        flipped = resized_size(width=height, height=width, max_edge=max_edge, max_tokens=max_tokens)
        return (flipped[1], flipped[0])
    aspect_ratio = width / height
    low, high = 1, width
    while low + 1 < high:
        mid = (low + high) // 2
        if fits(mid, max(round(mid / aspect_ratio), 1)):
            low = mid
        else:
            high = mid
    return (low, max(round(low / aspect_ratio), 1))


def _tokens(width: int, height: int, limits: tuple[int, int]) -> int:
    return count_image_tokens(*resized_size(width, height, *limits))


def tokens_at_both_tiers(width: int, height: int) -> ImageTokens:
    """The cost of an image of `width` by `height` pixels at the standard and the high-resolution tier."""
    return ImageTokens(_tokens(width, height, _STANDARD), _tokens(width, height, _HIGH))


def high_resolution(model: str) -> bool | None:
    """Whether `model` prices images at the high-resolution tier (Claude 4.7 and later); None when no
    `claude-<family>-<major>[-<minor>]` or `claude-<major>[-<minor>]-<family>` part is found in the id. A
    Bedrock or Vertex id wraps the part; a trailing 8-digit date is not a minor version."""
    found = _FAMILY_FIRST.search(model) or _VERSION_FIRST.search(model)
    if found is None:
        return None
    return (int(found.group(1)), int(found.group(2) or 0)) >= _HIGH_FROM


def _png(data: bytes) -> tuple[int, int] | None:
    if len(data) < 24 or not data.startswith(b"\x89PNG\r\n\x1a\n") or data[12:16] != b"IHDR":
        return None
    return int.from_bytes(data[16:20], "big"), int.from_bytes(data[20:24], "big")


def _gif(data: bytes) -> tuple[int, int] | None:
    if len(data) < 10 or data[:6] not in (b"GIF87a", b"GIF89a"):
        return None
    return int.from_bytes(data[6:8], "little"), int.from_bytes(data[8:10], "little")


def _webp(data: bytes) -> tuple[int, int] | None:
    if len(data) < 25 or data[:4] != b"RIFF" or data[8:12] != b"WEBP":
        return None
    chunk = data[12:16]
    if len(data) >= 30 and chunk == b"VP8 " and data[23:26] == b"\x9d\x01\x2a":
        return int.from_bytes(data[26:28], "little") & 0x3FFF, int.from_bytes(data[28:30], "little") & 0x3FFF
    if chunk == b"VP8L" and data[20] == 0x2F:
        bits = int.from_bytes(data[21:25], "little")
        return (bits & 0x3FFF) + 1, ((bits >> 14) & 0x3FFF) + 1
    if len(data) >= 30 and chunk == b"VP8X":
        return int.from_bytes(data[24:27], "little") + 1, int.from_bytes(data[27:30], "little") + 1
    return None


def _jpeg(data: bytes) -> tuple[int, int] | None:
    if not data.startswith(b"\xff\xd8"):
        return None
    at = 2
    while at + 4 <= len(data):
        if data[at] != 0xFF:
            return None
        marker = data[at + 1]
        if marker == 0xFF:
            at += 1
            continue
        if marker in _JPEG_STANDALONE:
            at += 2
            continue
        if 0xC0 <= marker <= 0xCF and marker not in _JPEG_NOT_FRAME:
            if at + 9 > len(data):
                return None
            return int.from_bytes(data[at + 7 : at + 9], "big"), int.from_bytes(data[at + 5 : at + 7], "big")
        at += 2 + int.from_bytes(data[at + 2 : at + 4], "big")
    return None


def _dimensions(media_type: str, data: str) -> tuple[int, int] | None:
    """The pixel width and height from the header of base64 `data`; None when the media type is not one of the
    four, the data is not base64 or the header does not read."""
    try:
        if media_type == "image/jpeg":
            return _jpeg(base64.b64decode(data, validate=True))
        prefix = base64.b64decode(data[:_PREFIX_CHARS], validate=True)
    except (binascii.Error, ValueError):
        return None
    reader = {"image/png": _png, "image/gif": _gif, "image/webp": _webp}.get(media_type)
    return None if reader is None else reader(prefix)


def price_image(source: JsonObject) -> ImageTokens | None:
    """The cost of the image a block's `source` holds; None when it cannot be worked out: the source is not
    base64 data, the media type is not PNG, GIF, WebP or JPEG, or the header does not read."""
    media_type, data = source.get("media_type"), source.get("data")
    if source.get("type") != "base64" or not isinstance(media_type, str) or not isinstance(data, str):
        return None
    size = _dimensions(media_type, data)
    if size is None or size[0] <= 0 or size[1] <= 0:
        return None
    return tokens_at_both_tiers(*size)
