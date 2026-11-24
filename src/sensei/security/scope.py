"""Target scope and authorization registry."""

import ipaddress
import re
from typing import List, Optional
from urllib.parse import urlparse
from pydantic import BaseModel, Field


class TargetScope(BaseModel):
    """Represents an authorized target scope definition."""
    target: str = Field(..., description="Target URL, hostname, or IP address")
    is_authorized: bool = Field(default=False, description="Whether target has explicit user authorization")
    authorized_by: Optional[str] = Field(default="user", description="Who authorized this assessment")
    notes: Optional[str] = Field(default="", description="Context e.g. Local test lab or staging")
    allowed_ports: List[int] = Field(default_factory=list, description="Specific permitted ports, empty=all safe standard")
    excluded_paths: List[str] = Field(default_factory=list, description="Paths forbidden from testing")

    def get_hostname_or_ip(self) -> str:
        """Extract plain hostname or IP from target."""
        raw = self.target.strip()
        if "://" in raw:
            parsed = urlparse(raw)
            return parsed.hostname or raw
        # Remove trailing port or path if any
        raw = raw.split("/")[0]
        if ":" in raw and not raw.startswith("["):
            raw = raw.split(":")[0]
        return raw


class ScopeRegistry:
    """Manages registered authorized targets and enforces boundary rules."""

    def __init__(self) -> None:
        self._scopes: List[TargetScope] = []

    def add_scope(self, scope: TargetScope) -> None:
        """Register a new target scope."""
        # Check if already registered
        for existing in self._scopes:
            if existing.target.lower() == scope.target.lower():
                existing.is_authorized = scope.is_authorized
                existing.authorized_by = scope.authorized_by
                existing.notes = scope.notes
                return
        self._scopes.append(scope)

    def remove_scope(self, target: str) -> bool:
        """Remove a target from the scope registry."""
        initial_len = len(self._scopes)
        self._scopes = [s for s in self._scopes if s.target.lower() != target.lower()]
        return len(self._scopes) < initial_len

    def list_scopes(self) -> List[TargetScope]:
        """Return all registered target scopes."""
        return list(self._scopes)

    def clear(self) -> None:
        """Clear all registered scopes."""
        self._scopes.clear()

    def is_in_scope(self, candidate_target: str) -> tuple[bool, Optional[str]]:
        """
        Validate whether a candidate target is within registered and authorized scope.
        Returns (is_allowed, reason).
        """
        if not candidate_target:
            return False, "Target is empty"

        candidate_clean = candidate_target.strip()
        candidate_host = self._extract_host(candidate_clean)

        if not self._scopes:
            return False, "No authorized targets in scope registry. Use '/scope add <target>' to register."

        # Check against registered scopes
        for scope in self._scopes:
            if not scope.is_authorized:
                continue

            scope_host = scope.get_hostname_or_ip().lower()

            # Exact hostname match
            if candidate_host.lower() == scope_host:
                return True, f"Target matches authorized scope '{scope.target}'"

            # Check for local loopback equivalence
            if self._is_local_equivalence(candidate_host, scope_host):
                return True, f"Target matches authorized local test scope '{scope.target}'"

            # CIDR / IP subnetwork check
            try:
                cand_ip = ipaddress.ip_address(candidate_host)
                if "/" in scope.target:
                    network = ipaddress.ip_network(scope.target, strict=False)
                    if cand_ip in network:
                        return True, f"Target IP {candidate_host} within authorized network {scope.target}"
                elif scope_host:
                    scope_ip = ipaddress.ip_address(scope_host)
                    if cand_ip == scope_ip:
                        return True, f"Target matches authorized IP '{scope.target}'"
            except ValueError:
                pass

            # Wildcard domain check (e.g. *.example.com)
            if scope_host.startswith("*."):
                suffix = scope_host[2:]
                if candidate_host.lower().endswith("." + suffix) or candidate_host.lower() == suffix:
                    return True, f"Target matches authorized domain pattern '{scope.target}'"

        return False, f"Target '{candidate_target}' is NOT in any authorized scope! Assessment blocked."

    def _extract_host(self, target: str) -> str:
        """Helper to extract clean host."""
        if "://" in target:
            parsed = urlparse(target)
            return parsed.hostname or target
        host_part = target.split("/")[0]
        if ":" in host_part:
            host_part = host_part.split(":")[0]
        return host_part

    def _is_local_equivalence(self, host1: str, host2: str) -> bool:
        """Check if both hosts represent local loopback / development."""
        locals_set = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}
        return host1.lower() in locals_set and host2.lower() in locals_set


# Global default scope registry
_global_scope_registry = ScopeRegistry()


def get_scope_registry() -> ScopeRegistry:
    """Return the global scope registry."""
    return _global_scope_registry
