from __future__ import annotations

import csv
import queue
import subprocess
import threading


class TsharkCapture:
    """Thin, UI-independent stream of parsed beacon/probe-response observations."""

    FIELDS = ("wlan.bssid", "wlan.ssid", "radiotap.dbm_antsignal", "wlan_radio.channel", "wlan_radio.frequency")

    def __init__(self, interface: str):
        self.interface = interface
        self.events: queue.Queue[tuple[str, str, int, int | None, int | None]] = queue.Queue()
        self.process: subprocess.Popen[str] | None = None

    def start(self) -> None:
        args = ["tshark", "-l", "-n", "-i", self.interface, "-Y", "wlan.fc.type_subtype == 8 || wlan.fc.type_subtype == 5", "-T", "fields"]
        for field in self.FIELDS:
            args += ["-e", field]
        args += ["-E", "separator=\t", "-E", "quote=d"]
        self.process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        threading.Thread(target=self._read, daemon=True).start()

    def _read(self) -> None:
        assert self.process and self.process.stdout
        for row in csv.reader(self.process.stdout, delimiter="\t"):
            if len(row) != 5 or not row[0]:
                continue
            try:
                # Multiple antenna values are comma-separated; strongest is useful for hunting.
                signals = [int(x) for x in row[2].split(",") if x]
                self.events.put((row[0].upper(), row[1] or "<hidden>", max(signals), _integer(row[3]), _integer(row[4])))
            except ValueError:
                continue

    def stop(self) -> None:
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.process.kill()


def _integer(value: str) -> int | None:
    try:
        return int(value.split(",")[0])
    except (ValueError, IndexError):
        return None
