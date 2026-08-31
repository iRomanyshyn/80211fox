from __future__ import annotations

import curses
import queue
import subprocess
import threading
import time

from .capture import TsharkCapture
from .model import AccessPoint, Adapter
from .system import MonitorInterface, available_frequencies
from .sound import SoundBackend, TerminalBell

STALE_AFTER = 10.0
EXPIRE_AFTER = 30.0
LOST_AFTER = 2.0


def select_adapter(screen: curses.window, adapters: list[Adapter]) -> Adapter:
    selected = 0
    while True:
        screen.erase()
        screen.addstr(0, 0, "Select Wi-Fi adapter (↑/↓, Enter, Q)", curses.A_BOLD)
        screen.addstr(2, 0, "IFACE        PHY    DRIVER       DEVICE              MODE       ACTIVE MONITOR")
        for i, item in enumerate(adapters):
            attr = curses.A_REVERSE if i == selected else 0
            active = "yes" if item.connected else ("no" if item.connection_known else "?")
            line = f"{item.interface:12.12} {item.phy:6} {item.driver:12.12} {item.device:19.19} {item.mode:10.10} {active:6} {'yes' if item.monitor else 'no'}"
            screen.addnstr(3 + i, 0, line, screen.getmaxyx()[1] - 1, attr)
        key = screen.get_wch()
        if key in ("q", "Q", "\x1b", 27):
            raise KeyboardInterrupt
        if key in (curses.KEY_UP, "k"):
            selected = max(0, selected - 1)
        elif key in (curses.KEY_DOWN, "j"):
            selected = min(len(adapters) - 1, selected + 1)
        elif key in ("\n", "\r", 10, 13):
            if adapters[selected].connected:
                screen.addstr(1, 0, "WARNING: this radio and its active connection will be taken offline. Enter to continue.", curses.A_BOLD)
                screen.refresh()
                if screen.get_wch() not in ("\n", "\r", 10, 13):
                    continue
            return adapters[selected]


class Application:
    def __init__(self, screen: curses.window, adapter: Adapter, sound: SoundBackend | None = None):
        self.screen = screen
        self.adapter = adapter
        self.aps: dict[str, AccessPoint] = {}
        self.filter = ""
        self.selected = 0
        self.running = True
        self.hunt: AccessPoint | None = None
        self.beep = False
        self.last_beep = 0.0
        self.stop_event = threading.Event()
        self.tune_lock = threading.Lock()
        self.sound = sound or TerminalBell()
        self.usable_frequencies: set[int] = set()
        self.rejected_frequencies: dict[int, str] = {}
        self.current_frequency: int | None = None
        self.tune_error: str | None = None
        self.channel_by_frequency: dict[int, int] = {}

    def run(self) -> None:
        frequencies = available_frequencies(self.adapter.phy)
        self.channel_by_frequency = dict(frequencies)
        if not frequencies:
            raise RuntimeError("the PHY reports no enabled channels")
        with MonitorInterface(self.adapter) as monitor:
            capture = TsharkCapture(monitor.name)
            capture.start()
            hopper = threading.Thread(target=self._hop, args=(monitor, frequencies), name="80211fox-hopper", daemon=True)
            hopper.start()
            try:
                self.screen.nodelay(True)
                while self.running:
                    capture.raise_if_failed()
                    self._events(capture)
                    self._keys(monitor)
                    self._draw()
                    time.sleep(0.05)
            finally:
                self.running = False
                self.stop_event.set()
                hopper.join(timeout=2)
                capture.stop()

    def _hop(self, monitor: MonitorInterface, frequencies: list[tuple[int, int]]) -> None:
        while not self.stop_event.is_set():
            if self.hunt is None:
                for frequency, _ in frequencies:
                    if self.stop_event.is_set() or self.hunt is not None:
                        break
                    try:
                        with self.tune_lock:
                            if self.hunt is None:
                                monitor.set_frequency(frequency)
                                self.current_frequency = frequency
                                self.usable_frequencies.add(frequency)
                                self.rejected_frequencies.pop(frequency, None)
                    except Exception as error:
                        self.rejected_frequencies[frequency] = command_error(error)
                    self.stop_event.wait(0.35)
            else:
                self.stop_event.wait(0.1)

    def _events(self, capture: TsharkCapture) -> None:
        while True:
            try:
                bssid, ssid, rssi, channel, frequency = capture.events.get_nowait()
            except queue.Empty:
                break
            ap = self.aps.get(bssid)
            if ap:
                if ssid != "<hidden>" or ap.ssid == "<hidden>":
                    ap.ssid = ssid
                ap.update(rssi, channel, frequency)
            else:
                self.aps[bssid] = AccessPoint(bssid, ssid, rssi, channel, frequency, average=float(rssi), minimum=rssi, maximum=rssi)
        now = time.monotonic()
        self.aps = {bssid: ap for bssid, ap in self.aps.items() if ap is self.hunt or now - ap.last_seen <= EXPIRE_AFTER}

    def _keys(self, monitor: MonitorInterface) -> None:
        try:
            key = self.screen.get_wch()
        except curses.error:
            return
        if key in ("q", "Q"):
            self.running = False
        elif self.hunt:
            if key in (27, "\x1b"):
                self.hunt = None
            elif key in ("b", "B"):
                self.beep = not self.beep
            elif key in ("r", "R"):
                ap = self.hunt
                ap.samples, ap.minimum, ap.maximum, ap.average = 1, ap.rssi, ap.rssi, float(ap.rssi)
        elif key == curses.KEY_UP:
            self.selected = max(0, self.selected - 1)
        elif key == curses.KEY_DOWN:
            self.selected += 1
        elif key in ("\n", "\r", 10, 13):
            visible = self._visible()
            if visible:
                target = visible[min(self.selected, len(visible) - 1)]
                # Publish HUNT first, then wait for an outstanding hopping tune
                # before locking the target frequency.
                self.hunt = target
                if target.frequency:
                    with self.tune_lock:
                        try:
                            monitor.set_frequency(target.frequency)
                            self.current_frequency = target.frequency
                            self.tune_error = None
                        except Exception as error:
                            self.tune_error = f"Unable to lock channel {target.channel or '?'}: {command_error(error)}"
                            self.hunt = None
        elif key in (curses.KEY_BACKSPACE, 127, 8):
            self.filter = self.filter[:-1]
        elif isinstance(key, str) and key.isprintable():
            self.filter += key

    def _visible(self) -> list[AccessPoint]:
        now = time.monotonic()
        return sorted((ap for ap in self.aps.values() if ap.matches(self.filter)), key=lambda ap: (now - ap.last_seen >= STALE_AFTER, -ap.rssi))

    def _draw(self) -> None:
        self.screen.erase()
        height, width = self.screen.getmaxyx()
        if height < 4 or width < 20:
            self.screen.addnstr(0, 0, "Terminal too small; resize", max(1, width - 1), curses.A_BOLD)
            self.screen.refresh()
            return
        if self.hunt:
            self._draw_hunt(self.hunt)
        else:
            self._draw_scan()
        self.screen.refresh()

    def _draw_scan(self) -> None:
        self.screen.addstr(0, 0, f"SCAN  {self.adapter.interface}/{self.adapter.phy}   filter: {self.filter}_", curses.A_BOLD)
        total = len(self.channel_by_frequency)
        current = self.channel_by_frequency.get(self.current_frequency or 0, "?")
        self.screen.addstr(1, 0, f"Channels: {total} available / {len(self.usable_frequencies)} usable / {len(self.rejected_frequencies)} rejected   Current: {current} ({self.current_frequency or '?'} MHz)")
        self.screen.addstr(2, 0, "RSSI   CH    FREQ   BSSID              SSID                       LAST")
        if self.tune_error:
            self.screen.addnstr(1, 0, self.tune_error, self.screen.getmaxyx()[1] - 1, curses.A_BOLD)
        visible = self._visible()
        self.selected = min(self.selected, max(0, len(visible) - 1))
        page_size = max(1, self.screen.getmaxyx()[0] - 4)
        offset = min(max(0, self.selected - page_size + 1), max(0, len(visible) - page_size))
        for row, ap in enumerate(visible[offset : offset + page_size]):
            index = offset + row
            age = time.monotonic() - ap.last_seen
            line = f"{ap.rssi:4}  {str(ap.channel or '?'):>4}  {str(ap.frequency or '?'):>5}  {ap.bssid:17}  {ap.ssid:25.25}  {age:5.1f}s"
            attr = curses.A_REVERSE if index == self.selected else (curses.A_DIM if age >= STALE_AFTER else 0)
            self.screen.addnstr(3 + row, 0, line, self.screen.getmaxyx()[1] - 1, attr)

    def _draw_hunt(self, ap: AccessPoint) -> None:
        height, terminal_width = self.screen.getmaxyx()
        if height < 15 or terminal_width < 40:
            message = f"HUNT {ap.ssid} {ap.rssi} dBm — resize to at least 40x15"
            self.screen.addnstr(1, 0, message, terminal_width - 1, curses.A_BOLD)
            return
        smooth = ap.average if ap.average is not None else ap.rssi
        age = time.monotonic() - ap.last_seen
        if age > LOST_AFTER:
            width = max(10, min(50, terminal_width - 4))
            self.screen.addstr(4, max(0, (terminal_width - 11) // 2), "SIGNAL LOST", curses.A_BOLD)
            self.screen.addstr(6, max(0, (terminal_width - 6) // 2), "-- dBm", curses.A_BOLD)
            self.screen.addstr(8, 2, "░" * width)
            self.screen.addstr(12, 2, f"last {age:5.2f}s")
            self.screen.addstr(14, 2, f"[B] beep {'ON' if self.beep else 'off'} ({self.sound.name})   [R] reset   [Esc] scan   [Q] quit")
            return
        label, color = proximity(smooth)
        width = max(10, min(50, terminal_width - 4))
        filled = round(width * max(0, min(1, (smooth + 90) / 65)))
        lines = [ap.ssid, ap.bssid, f"CH {ap.channel or '?'}  {ap.frequency or '?'} MHz", "", f"{ap.rssi} dBm", ""]
        for row, text in enumerate(lines, 1):
            self.screen.addstr(row, max(0, (self.screen.getmaxyx()[1] - len(text)) // 2), text, curses.A_BOLD)
        self.screen.addstr(7, 2, "█" * filled, curses.color_pair(color) | curses.A_BOLD)
        self.screen.addstr(7, 2 + filled, "░" * (width - filled))
        self.screen.addstr(9, 2, label, curses.color_pair(color) | curses.A_BOLD)
        minimum = ap.rssi if ap.minimum is None else ap.minimum
        maximum = ap.rssi if ap.maximum is None else ap.maximum
        self.screen.addstr(11, 2, f"current {ap.rssi:4}   avg {smooth:5.1f}   min {minimum:4}   max {maximum:4}")
        self.screen.addstr(12, 2, f"last {age:5.2f}s   samples {ap.samples}")
        self.screen.addstr(14, 2, f"[B] beep {'ON' if self.beep else 'off'} ({self.sound.name})   [R] reset   [Esc] scan   [Q] quit")
        if self.beep and time.monotonic() - self.last_beep >= beep_interval(smooth):
            self.sound.beep()
            self.last_beep = time.monotonic()


def command_error(error: Exception) -> str:
    if isinstance(error, subprocess.CalledProcessError):
        stderr = (error.stderr or "").strip()
        return stderr.rsplit("\n", 1)[-1] if stderr else f"command exited {error.returncode}"
    return str(error)


def proximity(rssi: float) -> tuple[str, int]:
    if rssi < -75:
        return "WEAK", 1
    if rssi < -60:
        return "MODERATE", 2
    if rssi < -45:
        return "GOOD", 3
    if rssi < -35:
        return "CLOSE", 4
    return "VERY CLOSE", 5


def beep_interval(rssi: float) -> float:
    return 1.8 - 1.65 * max(0.0, min(1.0, (rssi + 80) / 55))


def configure_colors() -> None:
    curses.start_color()
    curses.use_default_colors()
    for pair, color in enumerate((curses.COLOR_RED, curses.COLOR_YELLOW, curses.COLOR_GREEN, curses.COLOR_CYAN, curses.COLOR_MAGENTA), 1):
        curses.init_pair(pair, color, -1)
