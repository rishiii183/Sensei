"""Sensei — Autonomous AI Security Engineer."""

__version__ = "0.1.0"
__all__ = ["main", "__version__"]


def main() -> None:
    """Entry point wrapper."""
    from sensei.cli import main as cli_main
    cli_main()
