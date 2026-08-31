from __future__ import annotations

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

    def update(self, rssi: int, channel: int | None, frequency: int | None) -> None:
        self.rssi = rssi
        self.channel = channel or self.channel
        self.frequency = frequency or self.frequency
        self.last_seen = time.monotonic()
        self.samples += 1
        self.average = rssi if self.average is None else 0.25 * rssi + 0.75 * self.average
        self.minimum = rssi if self.minimum is None else min(self.minimum, rssi)
        self.maximum = rssi if self.maximum is None else max(self.maximum, rssi)

    def matches(self, query: str) -> bool:
        query = query.strip().casefold()
        if not query:
            return True
        mac_query = normalize_mac(query)
        mac_like = bool(mac_query) and all(c in "0123456789abcdef:-." for c in query)
        return query in self.ssid.casefold() or (mac_like and mac_query in normalize_mac(self.bssid))

