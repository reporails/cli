"""The size of an API request message: the visual tokens of its images and its parts in characters."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ImageTokens:
    """The visual tokens of images, priced at both resolution tiers: a message is sized before the request that
    names its model is read, so each image carries its cost at the standard and the high-resolution tier."""

    standard: int = 0
    high: int = 0

    def __add__(self, other: ImageTokens) -> ImageTokens:
        return ImageTokens(self.standard + other.standard, self.high + other.high)

    def at(self, *, high_resolution: bool) -> int:
        """The tokens at the tier of a request."""
        return self.high if high_resolution else self.standard


@dataclass(frozen=True)
class MessageSize:
    """The size of one message of an API request, by part: characters of text, and the visual tokens of its images;
    never its text. `images` are the images of the message's own content, `result_images` those inside a tool
    result, `unpriced_images` the image and document blocks whose cost could not be worked out."""

    user_text: int = 0
    notes: int = 0
    assistant_text: int = 0
    thinking: int = 0
    tool_calls: int = 0
    tool_results: int = 0
    images: ImageTokens = field(default_factory=ImageTokens)
    result_images: ImageTokens = field(default_factory=ImageTokens)
    unpriced_images: int = 0

    def __add__(self, other: MessageSize) -> MessageSize:
        return MessageSize(
            self.user_text + other.user_text,
            self.notes + other.notes,
            self.assistant_text + other.assistant_text,
            self.thinking + other.thinking,
            self.tool_calls + other.tool_calls,
            self.tool_results + other.tool_results,
            self.images + other.images,
            self.result_images + other.result_images,
            self.unpriced_images + other.unpriced_images,
        )

    @property
    def text_chars(self) -> int:
        """The characters of every text part; images are not in it."""
        return self.user_text + self.notes + self.assistant_text + self.thinking + self.tool_calls + self.tool_results
