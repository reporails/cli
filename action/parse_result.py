#!/usr/bin/env python3
"""Parse CombinedResult JSON and emit shell variables for GitHub Actions.

Usage: echo '<json>' | python3 parse_result.py
Outputs: _SCORE=X.X  _LEVEL=LN  _VIOLATIONS=N  _RESULT=ok|server-unavailable
         _SERVER_REASON=<reason-token-or-empty>  (one per line, eval-safe)

_SCORE is the analysis service's whole-project Quality verdict (the same number
`ails check` prints), read verbatim from the `quality` key — never recomputed here.
It is empty when no score is available: a designed offline run, or a request that
was rejected, timed out, or never reached the service. `_RESULT` and
`_SERVER_REASON` carry that distinction: `_RESULT=server-unavailable` marks the
second case and `_SERVER_REASON` names the reason
(`rate_limit_exceeded`, `payload_too_large`, `invalid_api_key`-style `unknown_error`,
`timeout`, `network_error`, `malformed_response`, `http_error`) so a caller can name
the warning after the reason instead of a generic "offline run".

Every value below is `eval`-ed by the calling shell (`eval "$(... | parse_result.py)"`),
so `_SERVER_REASON` is restricted to a bare `[A-Za-z0-9_]+` token even though
`server_error.error` already comes from a fixed vocabulary server- and client-side —
free text (the `message` field) is deliberately never put on an eval'd line; it
reaches the workflow only through the full JSON `result` output (already emitted via
a quoted heredoc) and `action/summary.py` (parses JSON directly, no shell eval).
"""

from __future__ import annotations

import json
import re
import sys

_TOKEN_RE = re.compile(r"[A-Za-z0-9_]+")


def _server_error_token(server_error: object) -> str:
    """Return the outage/rejection reason as a bare eval-safe token, or '' when absent."""
    if not isinstance(server_error, dict):
        return ""
    token = str(server_error.get("error", ""))
    return token if _TOKEN_RE.fullmatch(token) else "unknown_error"


def main() -> None:
    d = json.load(sys.stdin)
    files = d.get("files", {})
    stats = d.get("stats", {})

    quality = d.get("quality")  # float, or None when offline / no server score
    level = d.get("level", "L0")
    violations = stats.get("total_findings", sum(f.get("count", 0) for f in files.values()))
    server_error_token = _server_error_token(d.get("server_error"))

    score_out = "" if quality is None else f"{float(quality):.1f}"
    result_out = "server-unavailable" if server_error_token else "ok"

    print(f"_SCORE={score_out}")
    print(f"_LEVEL={level}")
    print(f"_VIOLATIONS={violations}")
    print(f"_RESULT={result_out}")
    print(f"_SERVER_REASON={server_error_token}")


if __name__ == "__main__":
    main()
