"""Sensei Execution Engine."""

from sensei.execution.rate_limiter import RateLimiter, get_rate_limiter
from sensei.execution.docker import DockerSandbox, get_docker_sandbox

__all__ = [
    "RateLimiter",
    "get_rate_limiter",
    "DockerSandbox",
    "get_docker_sandbox",
    "ToolExecutionRunner",
]


def __getattr__(name: str):
    if name == "ToolExecutionRunner":
        from sensei.execution.runner import ToolExecutionRunner
        return ToolExecutionRunner
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
