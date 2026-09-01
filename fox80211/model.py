from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
import time


def normalize_mac(value: str) -> str:
    return "".join(c for c in value.casefold() if c in "0123456789abcdef")


@dataclass
class Adapter:
    interface: str
    phy: str
    driver: str = "?"
    device: str = "?"
    mode: str = "?"
    connected: bool = False
    connection_known: bool = True
    monitor: bool = False


@dataclass
class AccessPoint:
    bssid: str
    ssid: str
    rssi: int
    channel: int | None
    frequency: int | None
    last_seen: float = field(default_factory=time.monotonic)
    samples: int = 1
    average: float | None = None
    minimum: int | None = None
    maximum: int | None = None
    signal_history: deque[tuple[float, int]] = field(default_factory=deque, repr=False)

    def __post_init__(self) -> None:
        if not self.signal_history:
            self.signal_history.append((self.last_seen, self.rssi))

    def update(self, rssi: int, channel: int | None, frequency: int | None) -> None:
        self.rssi = rssi
        self.channel = channel or self.channel
        self.frequency = frequency or self.frequency
        self.last_seen = time.monotonic()
        self.signal_history.append((self.last_seen, rssi))
        self.samples += 1
        self.average = rssi if self.average is None else 0.25 * rssi + 0.75 * self.average
        self.minimum = rssi if self.minimum is None else min(self.minimum, rssi)
        self.maximum = rssi if self.maximum is None else max(self.maximum, rssi)

    def recent_average(self, seconds: float, now: float | None = None) -> float:
        """Return mean RSSI from the recent window, retaining the latest sample."""
        cutoff = (time.monotonic() if now is None else now) - seconds
        while len(self.signal_history) > 1 and self.signal_history[0][0] < cutoff:
            self.signal_history.popleft()
        return sum(rssi for _, rssi in self.signal_history) / len(self.signal_history)

    def matches(self, query: str) -> bool:
        query = query.strip().casefold()
        if not query:
            return True
        mac_query = normalize_mac(query)
        mac_like = bool(mac_query) and all(c in "0123456789abcdef:-." for c in query)
        return query in self.ssid.casefold() or (mac_like and mac_query in normalize_mac(self.bssid))
