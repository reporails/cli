"""Heal command output formatting — interactive judgment prompt rendering."""

from __future__ import annotations

from reporails_cli.core.models import JudgmentRequest
from reporails_cli.formatters.text.chars import get_chars
from reporails_cli.formatters.text.components import get_severity_label


def format_judgment_prompt(
    jr: JudgmentRequest,
    index: int,
    total: int,
    ascii_mode: bool | None = None,
    max_content_lines: int = 40,
) -> str:
    """Render an interactive judgment prompt box for a single JudgmentRequest."""
    chars = get_chars(ascii_mode)
    w = 64  # inner width (between vertical bars)
    v = chars["v"]

    lines: list[str] = []

    # Top border
    lines.append(f"{chars['tl']}{chars['h'] * w}{chars['tr']}")

    # Header
    header = f"Rule {index}/{total}: {jr.rule_id} — {jr.rule_title}"
    lines.append(_pad(header, get_severity_label(jr.severity.value, chars), w, v))
    lines.append(_empty(w, v))

    # Question
    lines.extend(_padl(ql, w, v) for ql in _wrap(f"Question: {jr.question}", w - 6))
    lines.append(_empty(w, v))

    # Criteria
    if jr.criteria:
        lines.append(_padl("Criteria:", w, v))
        for desc in jr.criteria.values():
            lines.extend(_padl(bl, w, v) for bl in _wrap(f"  {chars['med']} {desc}", w - 6))

    lines.append(_empty(w, v))

    # File content snippet
    _append_content_section(lines, jr, w, chars, max_content_lines)

    lines.append(_empty(w, v))
    lines.append(_padl("[p]ass  [f]ail  [s]kip  [d]ismiss", w, v))
    lines.append(_empty(w, v))

    # Bottom border
    lines.append(f"{chars['bl']}{chars['h'] * w}{chars['br']}")

    return "\n".join(lines)


def _append_content_section(
    lines: list[str],
    jr: JudgmentRequest,
    w: int,
    chars: dict[str, str],
    max_lines: int,
) -> None:
    """Append file content snippet section to lines."""
    v = chars["v"]
    file_path = jr.location.rsplit(":", 1)[0] if ":" in jr.location else jr.location
    all_lines = jr.content.splitlines()
    content_lines = all_lines[:max_lines]
    suffix = f" (first {max_lines} lines)" if len(all_lines) > max_lines else ""
    lines.append(_padl(f"File: {file_path}{suffix}", w, v))

    sep = f"{v}   {chars['sep'] * (w - 6)}   {v}"
    lines.append(sep)
    for cl in content_lines:
        display = cl[: w - 8] + "..." if len(cl) > w - 8 else cl
        lines.append(_padl(f"  {display}", w, v))
    lines.append(sep)


def format_heal_summary(
    passed: int,
    failed: int,
    skipped: int,
    dismissed: int,
    *,
    auto_fixed: int = 0,
) -> str:
    """Format the end-of-heal summary line."""
    parts = []
    if auto_fixed:
        parts.append(f"{auto_fixed} auto-fixed")
    if passed:
        parts.append(f"{passed} passed")
    if failed:
        parts.append(f"{failed} failed")
    if skipped:
        parts.append(f"{skipped} skipped")
    if dismissed:
        parts.append(f"{dismissed} dismissed")
    return "Heal complete: " + ", ".join(parts) if parts else "No semantic rules to evaluate."


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _pad(left: str, right: str, width: int, v: str) -> str:
    """Pad a line with left and right content inside vertical bars."""
    inner = f"   {left}"
    gap = max(1, width - len(inner) - len(right) - 1)
    return f"{v}{inner}{' ' * gap}{right} {v}"


def _padl(content: str, width: int, v: str) -> str:
    """Left-padded content line inside vertical bars."""
    inner = f"   {content}"
    if len(inner) > width:
        inner = inner[: width - 3] + "..."
    return f"{v}{inner.ljust(width)}{v}"


def _empty(width: int, v: str) -> str:
    """Empty line inside vertical bars."""
    return f"{v}{' ' * width}{v}"


def _wrap(text: str, max_width: int) -> list[str]:
    """Simple word wrap that respects max_width."""
    if len(text) <= max_width:
        return [text]
    words = text.split()
    lines: list[str] = []
    current = ""
    for word in words:
        candidate = f"{current} {word}" if current else word
        if len(candidate) <= max_width:
            current = candidate
        else:
            if current:
                lines.append(current)
            current = word
    if current:
        lines.append(current)
    return lines or [text]
