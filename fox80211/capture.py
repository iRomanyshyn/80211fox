from __future__ import annotations

import csv
import queue
import re
import subprocess
import tempfile
import threading
import time
from functools import lru_cache

from .dfs import ChannelSwitch
from .model import MISSING_SSID

DISCOVERY_FILTER = "wlan.fc.type_subtype == 8 || wlan.fc.type_subtype == 5"
EVENT_QUEUE_SIZE = 1024
TARGET_EVENT_INTERVAL = 0.05
CaptureEvent = tuple[str, str, int, int | None, int | None, float]
CSA_FIELDS = (
    "wlan_mgt.tag.csa.new_channel",
    "wlan_mgt.extended_channel_switch_announcement.new_channel",
    "wlan_mgt.tag.ext_csa.new_channel",
    "wlan.csa.new_channel_number",
)
CSA_COUNT_FIELDS = (
    "wlan_mgt.tag.csa.channel_switch_count",
    "wlan_mgt.tag.ext_csa.channel_switch_count",
    "wlan.csa.channel_switch_count",
)
ECSA_CLASS_FIELDS = (
    "wlan_mgt.tag.ext_csa.new_reg_class",
    "wlan.extended_channel_switch_announcement.new_operating_class",
)


class TsharkCapture:
    """Thin, UI-independent stream of parsed Wi-Fi observations."""

    FIELDS = (
        "wlan.bssid",
        "wlan.ssid",
        "radiotap.dbm_antsignal",
        "wlan_radio.channel",
        "wlan_radio.frequency",
    )
    OPTIONAL_FIELDS = (
        "wlan.ssid_raw",
        *CSA_FIELDS,
        *CSA_COUNT_FIELDS,
        *ECSA_CLASS_FIELDS,
    )

    def __init__(self, interface: str, target_bssid: str | None = None):
        self.interface = interface
        self.target_bssid = _validated_bssid(target_bssid) if target_bssid else None
        self.events: queue.Queue[CaptureEvent] = queue.Queue(maxsize=EVENT_QUEUE_SIZE)
        self.channel_switches: queue.Queue[ChannelSwitch] = queue.Queue(maxsize=128)
        self.process: subprocess.Popen[str] | None = None
        self.reader: threading.Thread | None = None
        self.stderr = tempfile.TemporaryFile(mode="w+t")
        self.stopping = False
        self.fields = self.FIELDS
        self.ssid_is_bytes = False
        self.last_target_event = 0.0
        self.frames_parsed = 0
        self.frames_with_rssi = 0
        self.frames_without_rssi = 0
        self.parse_errors = 0

    def start(self) -> None:
        supported = _tshark_fields()
        optional = tuple(field for field in self.OPTIONAL_FIELDS if field in supported)
        self.fields = self.FIELDS + optional
        self.ssid_is_bytes = supported.get("wlan.ssid") == "FT_BYTES"
        display_filter = DISCOVERY_FILTER
        if self.target_bssid:
            # Discovery needs only management frames, but HUNT can refresh its
            # RSSI from every frame transmitted by the selected AP. Filtering
            # on wlan.ta avoids measuring uplink frames sent by nearby clients
            # that merely belong to the same BSSID.
            display_filter = f"({display_filter}) || wlan.ta == {self.target_bssid}"
        args = [
            "tshark",
            "-l",
            "-n",
            "-i",
            self.interface,
            "-Y",
            display_filter,
            "-T",
            "fields",
        ]
        for field in self.fields:
            args += ["-e", field]
        args += ["-E", "separator=\t", "-E", "quote=d"]
        self.process = subprocess.Popen(
            args, stdout=subprocess.PIPE, stderr=self.stderr, text=True
        )
        self.reader = threading.Thread(
            target=self._read, name="80211fox-capture", daemon=True
        )
        self.reader.start()

    def _read(self) -> None:
        assert self.process and self.process.stdout
        for row in csv.reader(self.process.stdout, delimiter="\t"):
            if len(row) != len(self.fields) or not row[0]:
                self.parse_errors += 1
                continue
            try:
                # Multiple antenna values are comma-separated; strongest is useful for hunting.
                signals = [int(x) for x in row[2].split(",") if x]
                self.frames_parsed += 1
                if not signals:
                    self.frames_without_rssi += 1
                    continue
                raw_ssid = row[5] if "wlan.ssid_raw" in self.fields else ""
                self._emit(
                    (
                        row[0].upper(),
                        _ssid(row[1], raw_ssid, self.ssid_is_bytes),
                        max(signals),
                        _integer(row[3]),
                        _integer(row[4]),
                        time.monotonic(),
                    )
                )
                values = dict(zip(self.fields, row))
                switch = extract_channel_switch(values, row[0], _integer(row[3]))
                if switch:
                    try:
                        self.channel_switches.put_nowait(switch)
                    except queue.Full:
                        try:
                            self.channel_switches.get_nowait()
                        except queue.Empty:
                            pass
                        try:
                            self.channel_switches.put_nowait(switch)
                        except queue.Full:
                            pass
                self.frames_with_rssi += 1
            except ValueError:
                self.parse_errors += 1
                continue

    def _emit(self, event: CaptureEvent) -> None:
        if self.target_bssid and event[0].casefold() == self.target_bssid:
            now = time.monotonic()
            if now - self.last_target_event < TARGET_EVENT_INTERVAL:
                return
            self.last_target_event = now
        try:
            self.events.put_nowait(event)
        except queue.Full:
            # Prefer recent signal data over an unbounded backlog. There is a
            # single producer, while the UI is the only consumer.
            try:
                self.events.get_nowait()
            except queue.Empty:
                pass
            try:
                self.events.put_nowait(event)
            except queue.Full:
                pass

    def stop(self) -> None:
        self.stopping = True
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
        if self.reader and self.reader is not threading.current_thread():
            self.reader.join(timeout=2)
        self.stderr.close()

    def raise_if_failed(self) -> None:
        if not self.process or self.stopping:
            return
        status = self.process.poll()
        if status is None:
            return
        self.stderr.flush()
        self.stderr.seek(0)
        detail = self.stderr.read().strip()
        # TShark commonly prints the actionable startup failure first and ends
        # with a generic packet count. Preserve a bounded diagnostic instead of
        # reducing it to that unhelpful final line.
        message = detail[-8192:] if detail else f"exit status {status}"
        raise RuntimeError(f"tshark capture stopped: {message}")


@lru_cache(maxsize=1)
def _tshark_fields() -> dict[str, str]:
    """Return advertised field names and types, or no fields on failure."""
    try:
        result = subprocess.run(
            ["tshark", "-G", "fields"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            check=False,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return {}
    if result.returncode:
        return {}
    return {
        columns[2]: columns[3]
        for line in result.stdout.splitlines()
        if len(columns := line.split("\t")) > 3 and columns[0] == "F"
    }


def _integer(value: str) -> int | None:
    try:
        return int(value.split(",")[0])
    except (ValueError, IndexError):
        return None


def _validated_bssid(value: str) -> str:
    normalized = value.strip().casefold()
    if not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", normalized):
        raise ValueError(f"invalid BSSID for TShark display filter: {value!r}")
    return normalized


def _ssid(value: str, raw_value: str = "", value_is_bytes: bool = False) -> str:
    """Decode the SSID octets emitted by TShark into safe display text.

    TShark builds disagree about whether ``wlan.ssid`` is a text or byte field.
    Decode it only when field discovery reports ``FT_BYTES``; otherwise an SSID
    such as ``Cafe`` or ``1234`` is indistinguishable from hexadecimal bytes.
    When available, ``wlan.ssid_raw`` is unambiguously byte-formatted.
    """
    encoded = raw_value if raw_value else value
    raw = _ssid_bytes(encoded) if raw_value or value_is_bytes else None
    if raw is None:
        # Be tolerant of versions/builds which render wlan.ssid as text.
        decoded = value
    else:
        if not raw or not any(raw):
            return MISSING_SSID
        decoded = raw.decode("utf-8", errors="replace")
    return (
        "".join(character if character.isprintable() else "�" for character in decoded)
        or MISSING_SSID
    )


def extract_channel_switch(
    values: dict[str, str],
    bssid: str,
    old_channel: int | None,
    timestamp: float | None = None,
) -> ChannelSwitch | None:
    """Extract CSA/ECSA without interpreting it as radar."""
    target = next(
        (
            _integer(values.get(name, ""))
            for name in CSA_FIELDS
            if _integer(values.get(name, "")) is not None
        ),
        None,
    )
    if target is None:
        return None
    count = next(
        (
            _integer(values.get(name, ""))
            for name in CSA_COUNT_FIELDS
            if _integer(values.get(name, "")) is not None
        ),
        None,
    )
    operating_class = next(
        (
            _integer(values.get(name, ""))
            for name in ECSA_CLASS_FIELDS
            if _integer(values.get(name, "")) is not None
        ),
        None,
    )
    return ChannelSwitch(
        time.time() if timestamp is None else timestamp,
        bssid.upper(),
        old_channel,
        target,
        switch_count=count,
        operating_class=operating_class,
    )


def _ssid_bytes(value: str) -> bytes | None:
    """Return bytes for a TShark hexadecimal byte field, or ``None`` for text."""
    stripped = value.strip()
    compact = stripped[2:] if stripped[:2].lower() == "0x" else stripped
    compact = compact.replace(":", "")
    if not compact or len(compact) % 2 or not re.fullmatch(r"[0-9a-fA-F]+", compact):
        return b"" if not compact else None
    return bytes.fromhex(compact)
