"""Structured, passive DFS events from Linux and bounded correlation state."""
from __future__ import annotations

import queue
import re
import subprocess
import tempfile
import threading
import time
from collections import deque
from dataclasses import dataclass
from enum import Enum


class DfsKind(str, Enum):
    RADAR = "RADAR"
    CAC_STARTED = "CAC"
    CAC_FINISHED = "CAC FINISHED"
    CAC_ABORTED = "CAC ABORTED"
    NOP_FINISHED = "NOP FINISHED"
    PRE_CAC_EXPIRED = "PRE-CAC EXPIRED"


@dataclass(frozen=True)
class DfsEvent:
    kind: DfsKind
    timestamp: float
    frequency: int | None = None
    channel: int | None = None


@dataclass(frozen=True)
class ChannelSwitch:
    timestamp: float
    bssid: str
    old_channel: int | None
    target_channel: int | None
    target_frequency: int | None = None
    from_dfs: bool = False

    @property
    def label(self) -> str:
        return "DFS MOVE" if self.from_dfs else "CSA"


def parse_iw_event(line: str, timestamp: float | None = None) -> DfsEvent | None:
    lower = line.casefold()
    kinds = (
        ("radar detected", DfsKind.RADAR), ("cac started", DfsKind.CAC_STARTED),
        ("cac finished", DfsKind.CAC_FINISHED), ("cac aborted", DfsKind.CAC_ABORTED),
        ("nop finished", DfsKind.NOP_FINISHED), ("pre-cac expired", DfsKind.PRE_CAC_EXPIRED),
    )
    kind = next((value for token, value in kinds if token in lower), None)
    if kind is None:
        return None
    freq = re.search(r"(?:freq(?:uency)?)[=: ]+(\d+)", line, re.IGNORECASE)
    chan = re.search(r"(?:chan(?:nel)?)[=: ]+(\d+)", line, re.IGNORECASE)
    return DfsEvent(kind, time.time() if timestamp is None else timestamp,
                    int(freq.group(1)) if freq else None,
                    int(chan.group(1)) if chan else None)


class EventHistory:
    def __init__(self, maximum: int = 50):
        self.items: deque[DfsEvent | ChannelSwitch] = deque(maxlen=maximum)

    def add(self, event: DfsEvent | ChannelSwitch) -> None:
        self.items.append(event)

    def radar_for(self, frequency: int | None, timestamp: float, window: float = 10.0) -> bool:
        # Raw events remain separate; this only answers a UI correlation query.
        return any(isinstance(e, DfsEvent) and e.kind is DfsKind.RADAR
                   and e.frequency == frequency and abs(timestamp - e.timestamp) <= window
                   for e in self.items)


class DfsEventMonitor:
    """Run ``iw event -t`` off the UI thread; unsupported drivers degrade cleanly."""
    def __init__(self, phy: str):
        self.phy = phy
        self.events: queue.Queue[DfsEvent] = queue.Queue(maxsize=128)
        self.process: subprocess.Popen[str] | None = None
        self.reader: threading.Thread | None = None
        self.stderr = tempfile.TemporaryFile(mode="w+t")
        self.available = False

    def start(self) -> None:
        self.process = subprocess.Popen(["iw", "event", "-t"], stdout=subprocess.PIPE,
                                        stderr=self.stderr, text=True)
        self.available = True
        self.reader = threading.Thread(target=self._read, name="80211fox-dfs", daemon=True)
        self.reader.start()

    def _read(self) -> None:
        assert self.process and self.process.stdout
        phy_number = self.phy.removeprefix("phy")
        for line in self.process.stdout:
            # iw prefixes wiphy-scoped messages differently across versions.
            explicit_phy = re.search(r"phy\s*#?\s*(\d+)", line, re.IGNORECASE)
            if explicit_phy and explicit_phy.group(1) != phy_number:
                continue
            if not explicit_phy and self.phy not in line:
                # A global event without a PHY identity cannot justify saying
                # that the selected local adapter detected radar.
                continue
            event = parse_iw_event(line)
            if event:
                try: self.events.put_nowait(event)
                except queue.Full:
                    try: self.events.get_nowait()
                    except queue.Empty: pass
                    try: self.events.put_nowait(event)
                    except queue.Full: pass

    def stop(self) -> None:
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try: self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.process.kill(); self.process.wait()
        if self.reader: self.reader.join(timeout=2)
        self.stderr.close()
