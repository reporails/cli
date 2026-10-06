"""Surface-agnostic check-pipeline core shared by the CLI and MCP surfaces.

The ``ails check`` flow (``interfaces/cli/check_flow.py``) and the MCP ``validate``
tool (``interfaces/mcp/tools.py``) each drove their own post-lint assembly, which
let coverage drift between the two surfaces. This package factors the
surface-agnostic spine out of the CLI-coupled shells so both surfaces consume one
implementation and cannot diverge by construction.
"""
