"""The files Claude Code attaches to the context: the kinds it writes and what each puts in."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, TypeGuard, get_args

AttachmentKind = Literal["file", "compact_file_reference", "edited_text_file", "relevant_memories"]
# The kinds that put a file's whole text into the context.
WHOLE_FILE_ATTACHMENT_KINDS: frozenset[AttachmentKind] = frozenset({"file", "relevant_memories"})
# The kind that names a file read before a compaction without putting its text back.
NAMED_ATTACHMENT_KINDS: frozenset[AttachmentKind] = frozenset({"compact_file_reference"})
# `edited_text_file` puts only a snippet of the file in.


def is_attachment_kind(value: object) -> TypeGuard[AttachmentKind]:
    """Whether `value` is one of the attachment kinds."""
    return value in get_args(AttachmentKind)


@dataclass(frozen=True)
class FileAttachment:
    """One file Claude Code put into the context: its path and how (`kind`); never content."""

    path: str
    kind: AttachmentKind
