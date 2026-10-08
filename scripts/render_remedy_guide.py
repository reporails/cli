#!/usr/bin/env python3
"""Print the ideal-instruction guide as Markdown, for the remedy agent definition.

The text comes from `ideal_instruction_markdown` and nothing else: run it and paste the
output into the agent's generated guide section.
"""

from __future__ import annotations

import sys

from reporails_cli.interfaces.mcp.remedy_brief import ideal_instruction_markdown


def main() -> int:
    sys.stdout.write(ideal_instruction_markdown())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
