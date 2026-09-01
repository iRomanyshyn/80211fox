from __future__ import annotations

import argparse
import curses
import os
import shutil
import signal
import sys

from .sound import DisabledSound, TerminalBell
from .system import cleanup_orphan_monitors, discover_adapters
from .tui import Application, configure_colors, select_adapter


def _install_signal_handlers() -> None:
    def terminate(_signum: int, _frame: object) -> None:
        raise KeyboardInterrupt

    # Closing a terminal normally sends SIGHUP rather than SIGTERM. Route both
    # through the regular exception unwinding so monitor/network state is
    # restored by context managers.
    for signum in (signal.SIGHUP, signal.SIGTERM):
        signal.signal(signum, terminate)


def main() -> int:
    parser = argparse.ArgumentParser(description="Passively locate Wi-Fi access points")
    parser.add_argument("--interface", help="preselect a wireless interface")
    parser.add_argument(
        "--sound",
        choices=("terminal", "off"),
        default="terminal",
        help="beep backend (default: terminal)",
    )
    args = parser.parse_args()
    missing = [tool for tool in ("iw", "ip", "tshark") if not shutil.which(tool)]
    if missing:
        parser.error("missing required command(s): " + ", ".join(missing))
    if os.geteuid() != 0:
        parser.error(
            "MVP requires root (run with sudo); no privilege escalation is attempted"
        )
    _install_signal_handlers()
    cleanup_orphan_monitors()
    adapters = discover_adapters()
    if not adapters:
        parser.error("no nl80211 Wi-Fi interfaces found")

    def run(screen: curses.window) -> None:
        configure_colors()
        adapter = (
            next((a for a in adapters if a.interface == args.interface), None)
            if args.interface
            else select_adapter(screen, adapters)
        )
        if args.interface and adapter is None:
            raise RuntimeError(f"interface {args.interface!r} not found")
        assert adapter
        if not adapter.monitor:
            raise RuntimeError(f"{adapter.phy} does not advertise monitor mode")
        sound = TerminalBell() if args.sound == "terminal" else DisabledSound()
        Application(screen, adapter, sound).run()

    try:
        curses.wrapper(run)
    except KeyboardInterrupt:
        return 130
    except Exception as error:
        print(f"80211fox: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
