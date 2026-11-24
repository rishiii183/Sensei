"""Base adapter interface for security tools."""

import abc
import time
from typing import Any, Dict, Optional
from sensei.tools.schemas import ToolInfo, ToolOutput
from sensei.security.sanitizer import truncate_tool_output
from sensei.config import get_config


class BaseToolAdapter(abc.ABC):
    """Abstract base class for all security tool integrations."""

    def __init__(self, info: ToolInfo):
        self.info = info

    @abc.abstractmethod
    def check_availability(self) -> bool:
        """Check if the tool's binary or runtime environment is available."""
        pass

    @abc.abstractmethod
    def validate_input(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Validate input parameters against the tool's expected schema."""
        pass

    @abc.abstractmethod
    def _run_internal(self, input_data: Dict[str, Any], timeout: int) -> ToolOutput:
        """Internal execution method implemented by concrete adapters."""
        pass

    def execute(self, input_data: Dict[str, Any], timeout: Optional[int] = None) -> ToolOutput:
        """
        Execute the tool with rate-limiting, input validation, and output truncation.
        Never allows arbitrary shell injection.
        """
        config = get_config()
        effective_timeout = timeout or self.info.timeout_seconds

        # 1. Check availability
        if not self.check_availability():
            return ToolOutput(
                tool_name=self.info.name,
                success=False,
                exit_code=-1,
                error_message=(
                    f"Tool '{self.info.name}' is not installed or available. "
                    f"Install guide: {self.info.install_guide}"
                ),
            )

        # 2. Validate input
        try:
            validated_input = self.validate_input(input_data)
        except Exception as e:
            return ToolOutput(
                tool_name=self.info.name,
                success=False,
                exit_code=-1,
                error_message=f"Invalid input arguments for tool '{self.info.name}': {str(e)}",
            )

        # 3. Apply rate-limiting (applies in all operating modes)
        from sensei.execution.rate_limiter import get_rate_limiter
        target = str(validated_input.get("target", "global"))
        get_rate_limiter().acquire(target)

        # 4. Execute tool
        start_time = time.monotonic()
        try:
            output = self._run_internal(validated_input, effective_timeout)
        except TimeoutError:
            duration = time.monotonic() - start_time
            return ToolOutput(
                tool_name=self.info.name,
                success=False,
                exit_code=-2,
                duration_seconds=duration,
                error_message=f"Tool execution timed out after {effective_timeout}s.",
            )
        except Exception as e:
            duration = time.monotonic() - start_time
            return ToolOutput(
                tool_name=self.info.name,
                success=False,
                exit_code=-3,
                duration_seconds=duration,
                error_message=f"Execution error in '{self.info.name}': {str(e)}",
            )

        output.duration_seconds = time.monotonic() - start_time

        # 5. Output truncation and budget protection
        max_chars = config.max_tool_output_chars
        truncated_raw, was_truncated = truncate_tool_output(output.raw_output, max_chars=max_chars)
        output.raw_output = truncated_raw
        output.is_truncated = was_truncated

        return output
