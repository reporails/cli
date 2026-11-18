"""Data shapes for signing a machine in through the browser.

Pure data: the adapters build these from the website's and the server's replies;
the sign-in command reads them. No I/O.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from reporails_cli.core.platform.dto.diagnostics import Notice


@dataclass(frozen=True)
class SignInGrant:
    """A started sign-in: the code to poll with, the link and code to show, and the time allowed."""

    device_code: str
    user_code: str
    verification_url: str
    expires_in: int
    interval: int


@dataclass(frozen=True)
class SignedIn:
    """A finished sign-in: the credential the website issued and the account it belongs to."""

    access_token: str
    login: str
    tier: str
    machine: str = ""
    notices: tuple[Notice, ...] = ()


PollStatus = Literal["pending", "slow_down", "retry", "denied", "expired", "failed", "signed_in"]


@dataclass(frozen=True)
class PollOutcome:
    """The answer to one poll.

    `pending` and `retry` mean ask again after the interval, `slow_down` means ask again after a
    longer one, `denied` and `expired` end the sign-in, and `failed` carries the error code the
    website named in `code`. `signed_in` holds the credential only when the status is `signed_in`.
    """

    status: PollStatus
    signed_in: SignedIn | None = None
    code: str = ""


@dataclass(frozen=True)
class KeyCheck:
    """Outcome of a credential check: accepted with a tier, rejected with a reason, or unavailable."""

    status: Literal["accepted", "rejected", "unavailable"]
    tier: str = ""
    error: str = ""
    reason: str = ""
    notices: tuple[Notice, ...] = ()


# The command or tool asking the server about this caller.
Surface = Literal["cli", "mcp", "xray", "ci"]

HandshakeStatus = Literal["ok", "refused", "rejected", "unreachable", "no_verdict"]


@dataclass(frozen=True)
class Handshake:
    """The server's answer to "will you serve this caller?".

    `ok` and `refused` carry the server's verdict (`refused` names its `reason` and `message`);
    `rejected` means the credential was refused, with the server's `error` and `message`;
    `unreachable` means no reply came; `no_verdict` means a reply that holds no verdict.
    """

    status: HandshakeStatus
    reason: str = ""
    message: str = ""
    tier: str = ""
    error: str = ""
