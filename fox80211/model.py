from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field

RSSI_HISTORY_SECONDS = 10.0
# An absent SSID is not proof that an AP is configured as a hidden network.
# Data frames do not carry an SSID, and dissector/version limitations can also
# leave the field empty, so use a deliberately observation-based label.
MISSING_SSID = "<MISSING>"


@dataclass(frozen=True)
class Channel:
    """One frequency in the kernel's current regulatory view."""

    frequency: int
    number: int
    disabled: bool = False
    no_ir: bool = False
    radar: bool = False
    dfs_state: str | None = None
    cac_ms: int | None = None
    restrictions: tuple[str, ...] = ()


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
    rssi_history: deque[tuple[float, int]] = field(default_factory=deque)
    event_label: str = "-"
    event_target: int | None = None
    event_seen: float | None = None

    def __post_init__(self) -> None:
        if not self.rssi_history:
            self.rssi_history.append((self.last_seen, self.rssi))
        if self.average is None:
            self.average = float(self.rssi)
        if self.minimum is None:
            self.minimum = self.rssi
        if self.maximum is None:
            self.maximum = self.rssi

    def update(
        self,
        rssi: int,
        channel: int | None,
        frequency: int | None,
        observed_at: float | None = None,
    ) -> None:
        self.rssi = rssi
        self.channel = channel or self.channel
        self.frequency = frequency or self.frequency
        self.last_seen = time.monotonic() if observed_at is None else observed_at
        self.rssi_history.append((self.last_seen, rssi))
        self._prune_rssi_history(self.last_seen - RSSI_HISTORY_SECONDS)
        self.samples += 1
        self.average = (
            rssi if self.average is None else 0.25 * rssi + 0.75 * self.average
        )
        self.minimum = rssi if self.minimum is None else min(self.minimum, rssi)
        self.maximum = rssi if self.maximum is None else max(self.maximum, rssi)

    def recent_rssi(self, seconds: float, now: float | None = None) -> float:
        """Return the mean RSSI observed within the rolling time window."""
        now = time.monotonic() if now is None else now
        cutoff = now - seconds
        self._prune_rssi_history(cutoff)
        samples = [rssi for timestamp, rssi in self.rssi_history if timestamp >= cutoff]
        return sum(samples) / len(samples) if samples else float(self.rssi)

    def _prune_rssi_history(self, cutoff: float) -> None:
        while self.rssi_history and self.rssi_history[0][0] < cutoff:
            self.rssi_history.popleft()

    def matches(self, query: str) -> bool:
        query = query.strip().casefold()
        if not query:
            return True
        mac_query = normalize_mac(query)
        mac_like = bool(mac_query) and all(c in "0123456789abcdef:-." for c in query)
        return query in self.ssid.casefold() or (
            mac_like and mac_query in normalize_mac(self.bssid)
        )
