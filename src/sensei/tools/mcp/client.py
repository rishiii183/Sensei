"""MCP (Model Context Protocol) integration extension hook."""

from typing import Dict, List, Optional
from sensei.tools.schemas import ToolInfo, ToolOutput


class MCPToolClient:
    """Client for loading and executing tools from external MCP servers."""

    def __init__(self, server_url: Optional[str] = None):
        self.server_url = server_url
        self._connected = False

    def connect(self) -> bool:
        """Connect to MCP server endpoint if configured."""
        if not self.server_url:
            return False
        # MCP server connection hook for future phase
        self._connected = False
        return self._connected

    def discover_tools(self) -> List[ToolInfo]:
        """Discover tools exposed by MCP server."""
        return []

    def execute_tool(self, tool_name: str, arguments: Dict) -> ToolOutput:
        """Execute tool via MCP transport."""
        return ToolOutput(
            tool_name=tool_name,
            success=False,
            error_message="MCP client execution not connected.",
        )
