#!/usr/bin/env python3
"""Parse CombinedResult JSON and emit shell variables for GitHub Actions.

Usage: echo '<json>' | python3 parse_result.py
Outputs: _SCORE=X.X  _LEVEL=LN  _VIOLATIONS=N  _RESULT=ok|server-unavailable
         _SERVER_REASON=<reason-token-or-empty>  _CONTENT_SKIPPED=true|false  (one per line, eval-safe)

When the input is not JSON, or is the service-unreachable error object (a top-level
`error`), the same lines print with `_SCORE`, `_LEVEL` and `_VIOLATIONS` empty,
`_RESULT=server-unavailable` and `_SERVER_REASON` set to the error value (or
`unparsed_output`); the exit code stays 0.

_CONTENT_SKIPPED is true when the result carries `content_checks_skipped` (no model on
disk): the score then does not reflect the content checks, so the min-score gate fails.

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


def _emit(score: str, level: str, violations: object, result: str, reason: str, content_skipped: bool) -> None:
    print(f"_SCORE={score}")
    print(f"_LEVEL={level}")
    print(f"_VIOLATIONS={violations}")
    print(f"_RESULT={result}")
    print(f"_SERVER_REASON={reason}")
    print(f"_CONTENT_SKIPPED={'true' if content_skipped else 'false'}")


def main() -> None:
    try:
        d = json.load(sys.stdin)
    except json.JSONDecodeError:
        _emit("", "", "", "server-unavailable", "unparsed_output", False)
        return
    if not isinstance(d, dict) or "error" in d:
        # A reply that is not a result: the service-unreachable error object, or other output.
        reason = _server_error_token(d) if isinstance(d, dict) else "unparsed_output"
        _emit("", "", "", "server-unavailable", reason or "unparsed_output", False)
        return
    files = d.get("files", {})
    stats = d.get("stats", {})

    quality = d.get("quality")  # float, or None when offline / no server score
    level = d.get("level", "L0")
    violations = stats.get("total_findings", sum(f.get("count", 0) for f in files.values()))
    server_error_token = _server_error_token(d.get("server_error"))

    score_out = "" if quality is None else f"{float(quality):.1f}"
    result_out = "server-unavailable" if server_error_token else "ok"
    _emit(score_out, level, violations, result_out, server_error_token, d.get("content_checks_skipped") is True)


if __name__ == "__main__":
    main()
