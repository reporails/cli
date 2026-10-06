"""A hardened `MCPServer` that rejects a `tools/call` carrying an argument its tool does not
declare, instead of the SDK's own default — its generated argument model ignores an
unknown key rather than rejecting it (pydantic's own `extra: "ignore"`), so a typo'd or
retired argument was silently dropped with no signal at all.
"""

from __future__ import annotations

from typing import Any

from mcp.server.mcpserver import MCPServer


class StrictArgsMCPServer(MCPServer):
    """`call_tool` is the one seam every call path shares — the real stdio dispatch
    (`_handle_call_tool` calls `self.call_tool`, so this override binds there too via normal
    Python method resolution) and a module's own convenience shim alike — so overriding it
    here covers both."""

    async def call_tool(self, name: str, arguments: dict[str, Any], context: Any = None) -> Any:
        from mcp.server.mcpserver.exceptions import ToolError

        tool = next((t for t in await self.list_tools() if t.name == name), None)
        if tool is not None:
            known = set((tool.input_schema or {}).get("properties") or {})
            unknown = sorted(set(arguments or {}) - known)
            if unknown:
                raise ToolError(f"Error executing tool {name}: unknown argument(s) {unknown}; known: {sorted(known)}")
        return await super().call_tool(name, arguments, context)
