"""Dynamic tool registry for Sensei security tools."""

from typing import Dict, List, Optional
from sensei.tools.base import BaseToolAdapter
from sensei.tools.schemas import ToolCategory, ToolInfo
from sensei.tools.adapters.nuclei import NucleiAdapter
from sensei.tools.adapters.http_audit import HttpAuditAdapter
from sensei.tools.adapters.nmap import NmapAdapter
from sensei.tools.adapters.semgrep import SemgrepAdapter
from sensei.tools.adapters.trivy import TrivyAdapter
from sensei.tools.adapters.gitleaks import GitleaksAdapter


class ToolRegistry:
    """Manages the discovery, status, and retrieval of security tool adapters."""

    def __init__(self):
        self._tools: Dict[str, BaseToolAdapter] = {}
        self._register_default_adapters()

    def _register_default_adapters(self) -> None:
        """Register the verified core tool adapters."""
        # Web Security
        self.register(NucleiAdapter())
        self.register(HttpAuditAdapter())

        # Network Security
        self.register(NmapAdapter())

        # Code Security
        self.register(SemgrepAdapter())
        self.register(GitleaksAdapter())

        # Infrastructure Security
        self.register(TrivyAdapter())

    def register(self, adapter: BaseToolAdapter) -> None:
        """Register an adapter instance."""
        self._tools[adapter.info.name] = adapter

    def get(self, name: str) -> Optional[BaseToolAdapter]:
        """Fetch tool adapter by name."""
        return self._tools.get(name)

    def list_all(self) -> List[ToolInfo]:
        """Return metadata for all registered tools."""
        # Refresh availability status before listing
        for adapter in self._tools.values():
            adapter.check_availability()
        return [adapter.info for adapter in self._tools.values()]

    def list_available(self) -> List[ToolInfo]:
        """Return only tools that are verified as available on host system."""
        all_tools = self.list_all()
        return [t for t in all_tools if t.is_available]

    def list_by_category(self, category: ToolCategory) -> List[ToolInfo]:
        """Return tools belonging to a specific category."""
        return [t for t in self.list_all() if t.category == category]


_global_registry: Optional[ToolRegistry] = None


def get_tool_registry() -> ToolRegistry:
    """Get the global ToolRegistry singleton."""
    global _global_registry
    if _global_registry is None:
        _global_registry = ToolRegistry()
    return _global_registry
