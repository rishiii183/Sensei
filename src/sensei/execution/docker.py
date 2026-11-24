"""Docker execution isolation manager."""

import shutil
import subprocess
from typing import List, Optional
from sensei.config import get_config


class DockerSandbox:
    """Manages isolated containerized execution of external security tools."""

    def __init__(self):
        self.config = get_config()

    def is_docker_available(self) -> bool:
        """Verify whether docker daemon is reachable."""
        if not self.config.docker_enabled:
            return False
        if not shutil.which("docker"):
            return False
        try:
            res = subprocess.run(["docker", "info"], capture_output=True, timeout=5)
            return res.returncode == 0
        except Exception:
            return False

    def build_secure_run_args(
        self,
        image: str,
        command_args: List[str],
        memory_limit: str = "512m",
        cpu_limit: str = "1.0",
        read_only: bool = True,
    ) -> List[str]:
        """Construct secure Docker run command with strict security constraints."""
        args = [
            "docker", "run", "--rm",
            "--network", "bridge",
            "--memory", memory_limit,
            "--cpus", cpu_limit,
            "--user", "1000:1000",
            "--security-opt", "no-new-privileges",
        ]
        if read_only:
            args.extend(["--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m"])

        args.append(image)
        args.extend(command_args)
        return args


_docker_sandbox = DockerSandbox()


def get_docker_sandbox() -> DockerSandbox:
    """Return the global Docker sandbox manager."""
    return _docker_sandbox
