from __future__ import annotations

import csv
import queue
import re
import subprocess
import tempfile
import threading


class TsharkCapture:
    """Thin, UI-independent stream of parsed beacon/probe-response observations."""

    FIELDS = ("wlan.bssid", "wlan.ssid", "radiotap.dbm_antsignal", "wlan_radio.channel", "wlan_radio.frequency")
    OPTIONAL_FIELDS = ("wlan.ssid_raw",)

    def __init__(self, interface: str):
        self.interface = interface
        self.events: queue.Queue[tuple[str, str, int, int | None, int | None]] = queue.Queue()
        self.process: subprocess.Popen[str] | None = None
        self.reader: threading.Thread | None = None
        self.stderr = tempfile.TemporaryFile(mode="w+t")
        self.stopping = False
        self.fields = self.FIELDS

    def start(self) -> None:
        supported = _tshark_fields()
        optional = tuple(field for field in self.OPTIONAL_FIELDS if field in supported)
        self.fields = self.FIELDS + optional
        args = ["tshark", "-l", "-n", "-i", self.interface, "-Y", "wlan.fc.type_subtype == 8 || wlan.fc.type_subtype == 5", "-T", "fields"]
        for field in self.fields:
            args += ["-e", field]
        args += ["-E", "separator=\t", "-E", "quote=d"]
        self.process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=self.stderr, text=True)
        self.reader = threading.Thread(target=self._read, name="80211fox-capture", daemon=True)
        self.reader.start()

    def _read(self) -> None:
        assert self.process and self.process.stdout
        for row in csv.reader(self.process.stdout, delimiter="\t"):
            if len(row) != len(self.fields) or not row[0]:
                continue
            try:
                # Multiple antenna values are comma-separated; strongest is useful for hunting.
                signals = [int(x) for x in row[2].split(",") if x]
                raw_ssid = row[5] if "wlan.ssid_raw" in self.fields else ""
                self.events.put((row[0].upper(), _ssid(row[1], raw_ssid), max(signals), _integer(row[3]), _integer(row[4])))
            except ValueError:
                continue

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


def _tshark_fields() -> set[str]:
    """Return fields advertised by this TShark, or no optional fields on failure."""
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
        return set()
    if result.returncode:
        return set()
    return {
        columns[2]
        for line in result.stdout.splitlines()
        if len(columns := line.split("\t")) > 2 and columns[0] == "F"
    }


def _integer(value: str) -> int | None:
    try:
        return int(value.split(",")[0])
    except (ValueError, IndexError):
        return None


def _ssid(value: str, raw_value: str = "") -> str:
    """Decode the SSID octets emitted by TShark into safe display text.

    ``wlan.ssid`` is an FT_BYTES field and is therefore normally rendered as
    hexadecimal, despite its name.  Some TShark versions also expose the same
    bytes as ``wlan.ssid_raw`` while others do not.  Treating the former as
    already-decoded text is what produced long numeric strings in the UI.
    """
    encoded = raw_value or value
    raw = _ssid_bytes(encoded)
    if raw is None:
        # Be tolerant of versions/builds which render wlan.ssid as text.
        decoded = value
    else:
        if not raw or not any(raw):
            return "<hidden>"
        decoded = raw.decode("utf-8", errors="replace")
    return "".join(character if character.isprintable() else "�" for character in decoded) or "<hidden>"


def _ssid_bytes(value: str) -> bytes | None:
    """Return bytes for a TShark hexadecimal byte field, or ``None`` for text."""
    compact = value.strip().removeprefix("0x").replace(":", "")
    if not compact or len(compact) % 2 or not re.fullmatch(r"[0-9a-fA-F]+", compact):
        return b"" if not compact else None
    return bytes.fromhex(compact)
