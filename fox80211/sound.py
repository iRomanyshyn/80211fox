from __future__ import annotations

import curses
from typing import Protocol


class SoundBackend(Protocol):
    """Small boundary for replacing terminal bell with real audio later."""

    name: str

    def beep(self) -> None: ...


class TerminalBell:
    name = "terminal bell"

    def beep(self) -> None:
        curses.beep()


class DisabledSound:
    name = "disabled"

    def beep(self) -> None:
        pass
