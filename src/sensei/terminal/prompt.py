"""Interactive command prompt using prompt_toolkit with graceful non-TTY fallback."""

import sys
from typing import List
from prompt_toolkit import PromptSession
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.history import InMemoryHistory

SENSEI_COMMANDS: List[str] = [
    "/help",
    "/exit",
    "/clear",
    "/status",
    "/target",
    "/scope",
    "/scan",
    "/tools",
    "/findings",
    "/report",
    "/permissions",
    "/approve",
    "/deny",
    "/plan",
    "/agents",
    "/skills",
    "/memory",
    "/history",
    "/resume",
    "/sessions",
]


class SenseiPrompt:
    """Wrapper around prompt_toolkit PromptSession supporting slash-command completion."""

    def __init__(self):
        self.completer = WordCompleter(SENSEI_COMMANDS, ignore_case=True, sentence=True)
        self.history = InMemoryHistory()
        self._session = None
        if sys.stdin.isatty():
            try:
                self._session = PromptSession(
                    history=self.history,
                    completer=self.completer,
                    complete_while_typing=True,
                )
            except Exception:
                self._session = None

    def read_command(self, prompt_text: str = "sensei > ") -> str:
        """Read next line of input from user."""
        if self._session is not None:
            return self._session.prompt(prompt_text)
        return input(prompt_text)
