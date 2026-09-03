from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

from .model import Adapter, Channel

_APP_MONITOR = re.compile(r"^whmon(\d+)$")


def run(*args: str, check: bool = True) -> str:
    # iw/nmcli output is parsed below, so never let the invoking user's locale
    # translate stable tokens such as NetworkManager's `yes`/`no` values.
    environment = os.environ.copy()
    environment["LC_ALL"] = "C"
    return subprocess.run(
        args, check=check, text=True, capture_output=True, env=environment
    ).stdout


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
        # Monitor VIFs created by this application are implementation details,
        # not additional physical adapters a user should be asked to select.
        if _APP_MONITOR.fullmatch(name):
            continue
        block = output[output.find(line) :]
        next_iface = block.find("\n\tInterface", 1)
        if next_iface >= 0:
            block = block[:next_iface]
        mode_match = re.search(r"\n\s*type\s+(\S+)", block)
        device_path = Path("/sys/class/net") / name / "device"
        driver_link = device_path / "driver"
        driver = driver_link.resolve().name if driver_link.exists() else "?"
        vendor = _read(device_path / "vendor")
        device = _read(device_path / "device")
        model = _device_product(device_path)
        description = (
            model
            or ":".join(x.removeprefix("0x") for x in (vendor, device) if x)
            or "?"
        )
        adapters.append(
            Adapter(
                name,
                phy,
                driver,
                description,
                mode_match.group(1) if mode_match else "?",
            )
        )

    monitor_phys = _monitor_phys()
    for adapter in adapters:
        associated = _interface_associated(adapter.interface, adapter.mode)
        adapter.connected = associated is True
        adapter.connection_known = associated is not None
        adapter.monitor = adapter.phy in monitor_phys
    return adapters


def cleanup_orphan_monitors() -> list[str]:
    """Remove app-created monitor VIFs whose owning PID no longer exists."""
    output = run("iw", "dev")
    interfaces: list[tuple[str, str]] = []
    name: str | None = None
    for line in output.splitlines():
        match = re.match(r"\s*Interface\s+(\S+)", line)
        if match:
            name = match.group(1)
            continue
        mode = re.match(r"\s*type\s+(\S+)", line)
        if name is not None and mode:
            interfaces.append((name, mode.group(1)))
            name = None

    removed: list[str] = []
    for interface, mode in interfaces:
        match = _APP_MONITOR.fullmatch(interface)
        if mode != "monitor" or match is None:
            continue
        if (Path("/proc") / match.group(1)).exists():
            continue
        run("iw", "dev", interface, "del", check=False)
        removed.append(interface)
    return removed


def _read(path: Path) -> str:
    try:
        return path.read_text().strip()
    except OSError:
        return ""


def _device_product(path: Path) -> str:
    """Find a human-readable product on the device or a parent (common for USB)."""
    try:
        current = path.resolve()
    except OSError:
        return ""
    for candidate in (current, *current.parents):
        if candidate == Path("/sys"):
            break
        product = _read(candidate / "product")
        if product:
            return product
    return ""


def _link_is_up(interface: str) -> bool:
    try:
        flags = int(_read(Path("/sys/class/net") / interface / "flags"), 16)
    except ValueError:
        return False
    return bool(flags & 0x1)  # Linux IFF_UP (administrative state).


def _interface_associated(interface: str, mode: str = "managed") -> bool | None:
    """Ask nl80211 directly; unknown must never be treated as safe to disrupt."""
    if mode != "managed":
        # `iw dev … link` describes station association. In AP/P2P/mesh modes,
        # "Not connected" does not mean that the interface is idle.
        return None
    try:
        text = run("iw", "dev", interface, "link")
    except (FileNotFoundError, subprocess.CalledProcessError):
        return None
    if re.search(r"^Connected to ", text, re.MULTILINE):
        return True
    if "Not connected." in text:
        return False
    # Monitor/AP modes do not report managed association, but are not safe for
    # destructive fallback unless nl80211 gave an explicit answer.
    return None


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


def parse_channels(text: str) -> list[Channel]:
    """Parse frequency flags emitted by multiple generations of ``iw``."""
    result: list[Channel] = []
    for line in text.splitlines():
        match = re.search(r"\*\s+(\d+)(?:\.0+)?\s+MHz\s+\[(\d+)\](.*)", line)
        if not match:
            continue
        tail = match.group(3)
        flags = tuple(x.strip() for x in re.findall(r"\(([^()]*)\)", tail))
        lower = tail.casefold()
        state_match = re.search(
            r"dfs state:\s*([a-z_ -]+?)(?:\s*\(|,|$)", tail, re.IGNORECASE
        )
        cac_match = re.search(r"cac time:\s*(\d+)\s*ms", tail, re.IGNORECASE)
        result.append(
            Channel(
                int(match.group(1)),
                int(match.group(2)),
                "disabled" in lower,
                "no ir" in lower or "no-ir" in lower,
                "radar detection" in lower or bool(state_match),
                state_match.group(1).strip().upper().replace(" ", "_")
                if state_match
                else None,
                int(cac_match.group(1)) if cac_match else None,
                flags,
            )
        )
    return result


def available_channels(phy: str) -> list[Channel]:
    return parse_channels(run("iw", "phy", phy, "info"))


def available_frequencies(phy: str) -> list[tuple[int, int]]:
    """Return enabled (frequency MHz, channel) pairs from the current regdomain."""
    return [
        (item.frequency, item.number)
        for item in available_channels(phy)
        if not item.disabled
    ]


class MonitorInterface:
    """Create a monitor VIF, falling back to reversible in-place conversion."""

    def __init__(self, adapter: Adapter):
        self.adapter = adapter
        # Linux PIDs fit comfortably below IFNAMSIZ with this prefix. Keeping
        # the complete PID lets the next invocation distinguish a live owner
        # from a VIF orphaned by an uncatchable process termination.
        self.name = f"whmon{os.getpid()}"
        self.created = False
        self.type_changed = False
        self.link_changed = False
        self.original_managed: bool | None = None
        self.nm_changed = False
        self.was_up = False

    def _isolate_original(self) -> None:
        """Keep NetworkManager and the managed VIF from retuning this PHY."""
        self.was_up = _link_is_up(self.adapter.interface)
        self.original_managed = self._nm_managed(self.adapter.interface)
        if self.original_managed is True:
            self.nm_changed = True
            self._set_nm(self.adapter.interface, False)
        if self.was_up:
            self.link_changed = True
            run("ip", "link", "set", self.adapter.interface, "down")

    def __enter__(self) -> "MonitorInterface":
        try:
            self._isolate_original()
            try:
                run(
                    "iw",
                    "phy",
                    self.adapter.phy,
                    "interface",
                    "add",
                    self.name,
                    "type",
                    "monitor",
                )
                self.created = True
            except subprocess.CalledProcessError:
                self.name = self.adapter.interface
                if self.adapter.connected or not self.adapter.connection_known:
                    reason = (
                        "active connection"
                        if self.adapter.connected
                        else "unknown connection state"
                    )
                    raise RuntimeError(f"refusing in-place monitor mode: {reason}")
                # Record each mutation before the next command can fail so
                # __enter__ can reverse partially completed setup.
                if not self.link_changed:
                    run("ip", "link", "set", self.name, "down")
                self.type_changed = True
                run("iw", "dev", self.name, "set", "type", "monitor")
            run("ip", "link", "set", self.name, "up")
            return self
        except Exception:
            self.close()
            raise

    def set_frequency(self, frequency: int) -> None:
        run("iw", "dev", self.name, "set", "freq", str(frequency))

    def _nm_managed(self, interface: str) -> bool | None:
        # NetworkManager 1.56 renamed the terse-output field to
        # GENERAL.NM-MANAGED. Keep the older spelling as a compatibility
        # fallback so a failed status query cannot leave NetworkManager free
        # to retune the selected PHY during HUNT.
        for field in ("GENERAL.NM-MANAGED", "GENERAL.MANAGED"):
            try:
                value = (
                    run("nmcli", "-g", field, "device", "show", interface)
                    .strip()
                    .casefold()
                )
            except FileNotFoundError:
                return None
            except subprocess.CalledProcessError:
                continue
            return {"yes": True, "no": False}.get(value)
        return None

    def _set_nm(self, interface: str, managed: bool) -> None:
        run("nmcli", "device", "set", interface, "managed", "yes" if managed else "no")

    def close(self) -> None:
        if self.created:
            run("iw", "dev", self.name, "del", check=False)
        else:
            if self.type_changed:
                run("ip", "link", "set", self.name, "down", check=False)
                run(
                    "iw",
                    "dev",
                    self.name,
                    "set",
                    "type",
                    self.adapter.mode,
                    check=False,
                )
        if self.link_changed and self.was_up:
            run("ip", "link", "set", self.adapter.interface, "up", check=False)
        if self.nm_changed and self.original_managed is not None:
            try:
                self._set_nm(self.adapter.interface, self.original_managed)
            except (FileNotFoundError, subprocess.CalledProcessError):
                pass

    def __exit__(self, *_: object) -> None:
        self.close()
