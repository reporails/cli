"""Whether the server serves this caller, asked before any local work starts."""

from __future__ import annotations

from reporails_cli.core.platform.config.bootstrap import env_flag, offline_requested
from reporails_cli.core.platform.dto.diagnostics import FunnelError
from reporails_cli.core.platform.dto.pipeline import Refusal
from reporails_cli.core.platform.dto.ports import Handshaker
from reporails_cli.core.platform.dto.sign_in import Surface

_UNREACHABLE_MESSAGE = (
    "Could not reach the reporails service. Check your connection, "
    "or run with `--offline` (or `AILS_OFFLINE=1`) for local checks only."
)

# An MCP caller passes no flag: the setting belongs to the environment the server was started in.
_UNREACHABLE_MCP_MESSAGE = (
    "Could not reach the reporails service. Check your connection, "
    "or set `AILS_OFFLINE=1` in the MCP server's environment for local checks only."
)

_DECLINED_MESSAGE = "The reporails service declined this request."

_REJECTED_MESSAGE = (
    "The reporails service rejected your credential. Run `ails login` to sign in again, or set a valid `AILS_API_KEY`."
)


def server_gate(surface: Surface, handshake: Handshaker) -> Refusal | None:
    """The `Refusal` when the server will not serve this caller, else `None`.

    `handshake` asks the server. Nothing is asked when local checks only were requested or the run talks to a
    local server (`AILS_DEV_MODE`). A reply that holds no verdict, or a key rejected moments after sign-in, lets
    the run go on.
    """
    if offline_requested() or env_flag("AILS_DEV_MODE"):
        return None
    answer = handshake(surface)
    match answer.status:
        case "refused":
            return Refusal("server_refused", answer.message or _DECLINED_MESSAGE)
        case "rejected":
            if FunnelError(error=answer.error, message=answer.message).still_reaching:
                return None
            return Refusal("server_refused", _REJECTED_MESSAGE)
        case "unreachable":
            return Refusal("server_unreachable", _UNREACHABLE_MCP_MESSAGE if surface == "mcp" else _UNREACHABLE_MESSAGE)
        case "ok" | "no_verdict":
            return None
