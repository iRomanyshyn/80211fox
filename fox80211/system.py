from __future__ import annotations

import os
from pathlib import Path
import re
import subprocess

from .model import Adapter


def run(*args: str, check: bool = True) -> str:
    return subprocess.run(args, check=check, text=True, capture_output=True).stdout


def discover_adapters() -> list[Adapter]:
    """Discover nl80211 interfaces. sysfs supplies driver/device details."""
    output = run("iw", "dev")
    adapters: list[Adapter] = []
    phy = "?"
    for line in output.splitlines():
        match = re.match(r"phy#(\d+)", line.strip())
        if match:
            phy = f"phy{match.group(1)}"
        match = re.match(r"\s*Interface\s+(\S+)", line)
        if not match:
            continue
        name = match.group(1)
        block = output[output.find(line):]
        next_iface = block.find("\n\tInterface", 1)
        if next_iface >= 0:
            block = block[:next_iface]
        mode_match = re.search(r"\n\s*type\s+(\S+)", block)
        device_path = Path("/sys/class/net") / name / "device"
        driver_link = device_path / "driver"
        driver = driver_link.resolve().name if driver_link.exists() else "?"
        vendor = _read(device_path / "vendor")
        device = _read(device_path / "device")
        model = _read(device_path / "product")
        description = model or ":".join(x.removeprefix("0x") for x in (vendor, device) if x) or "?"
        adapters.append(Adapter(name, phy, driver, description, mode_match.group(1) if mode_match else "?"))

    connected = _connected_interfaces()
    monitor_phys = _monitor_phys()
    for adapter in adapters:
        adapter.connected = adapter.interface in connected
        adapter.monitor = adapter.phy in monitor_phys
    return adapters


def _read(path: Path) -> str:
    try:
        return path.read_text().strip()
    except OSError:
        return ""


def _connected_interfaces() -> set[str]:
    try:
        text = run("nmcli", "-t", "-f", "DEVICE,STATE", "device", "status")
    except (FileNotFoundError, subprocess.CalledProcessError):
        return set()
    return {line.split(":", 1)[0] for line in text.splitlines() if line.endswith(":connected")}


def _monitor_phys() -> set[str]:
    try:
        text = run("iw", "list")
    except subprocess.CalledProcessError:
        return set()
    result: set[str] = set()
    phy = "?"
    for line in text.splitlines():
        match = re.match(r"Wiphy\s+(\S+)", line)
        if match:
            phy = match.group(1)
        if re.match(r"\s*\*\s+monitor\s*$", line):
            result.add(phy)
    return result


def available_frequencies(phy: str) -> list[tuple[int, int]]:
    """Return enabled (frequency MHz, channel) pairs from the current regdomain."""
    text = run("iw", "phy", phy, "info")
    found: list[tuple[int, int]] = []
    for line in text.splitlines():
        match = re.search(r"\*\s+(\d+) MHz \[(\d+)\]", line)
        if match and "disabled" not in line:
            found.append((int(match.group(1)), int(match.group(2))))
    return found


class MonitorInterface:
    """Create a monitor VIF, falling back to reversible in-place conversion."""

    def __init__(self, adapter: Adapter):
        self.adapter = adapter
        self.name = f"whmon{os.getpid() % 10000}"
        self.created = False
        self.changed = False
        self.nm_managed = False

    def __enter__(self) -> "MonitorInterface":
        try:
            try:
                run("iw", "phy", self.adapter.phy, "interface", "add", self.name, "type", "monitor")
                self.created = True
            except subprocess.CalledProcessError:
                self.name = self.adapter.interface
                if self.adapter.connected:
                    raise RuntimeError("refusing in-place monitor mode on an active connection")
                self.nm_managed = self._set_nm(False)
                run("ip", "link", "set", self.name, "down")
                run("iw", "dev", self.name, "set", "type", "monitor")
                self.changed = True
            run("ip", "link", "set", self.name, "up")
            return self
        except Exception:
            self.close()
            raise

    def set_frequency(self, frequency: int) -> None:
        run("iw", "dev", self.name, "set", "freq", str(frequency))

    def _set_nm(self, managed: bool) -> bool:
        try:
            run("nmcli", "device", "set", self.name, "managed", "yes" if managed else "no")
            return True
        except (FileNotFoundError, subprocess.CalledProcessError):
            return False

    def close(self) -> None:
        if self.created:
            run("iw", "dev", self.name, "del", check=False)
        elif self.changed:
            run("ip", "link", "set", self.name, "down", check=False)
            run("iw", "dev", self.name, "set", "type", self.adapter.mode, check=False)
            run("ip", "link", "set", self.name, "up", check=False)
            if self.nm_managed:
                self._set_nm(True)

    def __exit__(self, *_: object) -> None:
        self.close()
