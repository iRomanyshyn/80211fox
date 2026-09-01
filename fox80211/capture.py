from __future__ import annotations

import csv
import string
import queue
import subprocess
import tempfile
import threading


class TsharkCapture:
    """Thin, UI-independent stream of parsed beacon/probe-response observations."""

    FIELDS = ("wlan.bssid", "wlan.ssid", "radiotap.dbm_antsignal", "wlan_radio.channel", "wlan_radio.frequency")

    def __init__(self, interface: str):
        self.interface = interface
        self.events: queue.Queue[tuple[str, str, int, int | None, int | None]] = queue.Queue()
        self.process: subprocess.Popen[str] | None = None
        self.reader: threading.Thread | None = None
        self.stderr = tempfile.TemporaryFile(mode="w+t")
        self.stopping = False

    def start(self) -> None:
        args = ["tshark", "-l", "-n", "-i", self.interface, "-Y", "wlan.fc.type_subtype == 8 || wlan.fc.type_subtype == 5", "-T", "fields"]
        for field in self.FIELDS:
            args += ["-e", field]
        args += ["-E", "separator=\t", "-E", "quote=d"]
        self.process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=self.stderr, text=True)
        self.reader = threading.Thread(target=self._read, name="80211fox-capture", daemon=True)
        self.reader.start()

    def _read(self) -> None:
        assert self.process and self.process.stdout
        for row in csv.reader(self.process.stdout, delimiter="\t"):
            if len(row) != 5 or not row[0]:
                continue
            try:
                # Multiple antenna values are comma-separated; strongest is useful for hunting.
                signals = [int(x) for x in row[2].split(",") if x]
                self.events.put((row[0].upper(), _ssid(row[1]), max(signals), _integer(row[3]), _integer(row[4])))
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


def _integer(value: str) -> int | None:
    try:
        return int(value.split(",")[0])
    except (ValueError, IndexError):
        return None


def _ssid(value: str) -> str:
    """Decode TShark's hexadecimal rendering of the raw SSID bytes."""
    if not value:
        return "<hidden>"
    if len(value) % 2 == 0 and all(character in string.hexdigits for character in value):
        decoded = bytes.fromhex(value).decode("utf-8", errors="replace")
    else:
        # Retain compatibility with TShark versions/output modes that return
        # the already-decoded field value rather than its byte representation.
        decoded = value
    return "".join(character if character.isprintable() else "�" for character in decoded) or "<hidden>"
