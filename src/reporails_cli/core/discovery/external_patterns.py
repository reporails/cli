"""External path patterns (`~/...`, `/abs`, `C:/...`) resolved to the folders they stand for.

A pattern's `/projects/*/` segment is the project's folder under `~/.claude/projects/`, and its `/synced/*/`
segment is the folder of the signed-in claude.ai account under `~/.claude/skills/synced/`.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from reporails_cli.core.discovery.walk import Pruner
from reporails_cli.core.platform.config.claude_settings import claude_synced_account_folder
from reporails_cli.core.platform.contract.glob_pattern import escape_glob, literal_segment

# The scope of the skills synced from the signed-in claude.ai account.
SYNCED_SCOPE = "synced"
_PROJECT_SEGMENT = "/projects/*/"
_SYNCED_ACCOUNT_SEGMENT = "/synced/*/"


def resolve_external_pattern(pattern: str, project_folder: str) -> str | None:
    """An external pattern with its `/projects/*/` segment narrowed to `project_folder` and its `/synced/*/`
    segment to the signed-in account's folder; None when the pattern names the account's folder and no account is
    signed in."""
    pattern = pattern.replace(_PROJECT_SEGMENT, f"/projects/{escape_glob(project_folder)}/")
    if _SYNCED_ACCOUNT_SEGMENT not in pattern:
        return pattern
    account = claude_synced_account_folder()
    if account is None:
        return None
    return pattern.replace(_SYNCED_ACCOUNT_SEGMENT, f"/synced/{escape_glob(account)}/")


def external_anchor(pattern: str) -> tuple[Path, str]:
    """Split a resolved external pattern into the folder it is anchored at (the home folder, the filesystem root
    or a drive, then each leading segment that names a plain folder) and the glob left under it."""
    parts = PurePosixPath(pattern).parts
    head = parts[0]
    anchor = Path(head).expanduser() if head.startswith("~") else Path(head + ("/" if head.endswith(":") else ""))
    used = 1
    for segment in parts[1:-1]:
        folder = literal_segment(segment)
        if folder is None:
            break
        anchor /= folder
        used += 1
    return anchor, "/".join(parts[used:])


@dataclass(frozen=True)
class OwnAccountOnly:
    """A pruner that also skips the synced-skills folder of every account but the signed-in one, so a walk of the
    user's skills folder never lists another account's files."""

    inner: Pruner

    def prunes(self, path: str, name: str, real: str) -> bool:
        """True when `inner` prunes the folder, or it is another account's folder under `skills/synced/`."""
        if self.inner.prunes(path, name, real):
            return True
        return Path(path).parts[-2:] == ("skills", "synced") and name != claude_synced_account_folder()
