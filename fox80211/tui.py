from __future__ import annotations

import curses
import queue
import threading
import time

from .capture import TsharkCapture
from .model import AccessPoint, Adapter
from .system import MonitorInterface, available_frequencies


def select_adapter(screen: curses.window, adapters: list[Adapter]) -> Adapter:
    selected = 0
    while True:
        screen.erase()
        screen.addstr(0, 0, "Select Wi-Fi adapter (↑/↓, Enter, Q)", curses.A_BOLD)
        screen.addstr(2, 0, "IFACE        PHY    DRIVER       DEVICE              MODE       ACTIVE MONITOR")
        for i, item in enumerate(adapters):
            attr = curses.A_REVERSE if i == selected else 0
            line = f"{item.interface:12.12} {item.phy:6} {item.driver:12.12} {item.device:19.19} {item.mode:10.10} {'yes' if item.connected else 'no':6} {'yes' if item.monitor else 'no'}"
            screen.addnstr(3 + i, 0, line, screen.getmaxyx()[1] - 1, attr)
        key = screen.getch()
        if key in (ord("q"), ord("Q"), 27):
            raise KeyboardInterrupt
        if key in (curses.KEY_UP, ord("k")):
            selected = max(0, selected - 1)
        elif key in (curses.KEY_DOWN, ord("j")):
            selected = min(len(adapters) - 1, selected + 1)
        elif key in (10, 13):
            if adapters[selected].connected:
                screen.addstr(1, 0, "WARNING: active connection. A separate VIF will be attempted. Enter to continue.", curses.A_BOLD)
                screen.refresh()
                if screen.getch() not in (10, 13):
                    continue
            return adapters[selected]


class Application:
    def __init__(self, screen: curses.window, adapter: Adapter):
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

    def run(self) -> None:
        frequencies = available_frequencies(self.adapter.phy)
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
                        monitor.set_frequency(frequency)
                    except Exception:
                        pass  # Regulatory/driver constraints are authoritative.
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
                ap.ssid = ssid
                ap.update(rssi, channel, frequency)
            else:
                self.aps[bssid] = AccessPoint(bssid, ssid, rssi, channel, frequency, average=float(rssi), minimum=rssi, maximum=rssi)

    def _keys(self, monitor: MonitorInterface) -> None:
        key = self.screen.getch()
        if key < 0:
            return
        if key in (ord("q"), ord("Q")):
            self.running = False
        elif self.hunt:
            if key == 27:
                self.hunt = None
            elif key in (ord("b"), ord("B")):
                self.beep = not self.beep
            elif key in (ord("r"), ord("R")):
                ap = self.hunt
                ap.samples, ap.minimum, ap.maximum, ap.average = 1, ap.rssi, ap.rssi, float(ap.rssi)
        elif key in (curses.KEY_UP, ord("k")):
            self.selected = max(0, self.selected - 1)
        elif key in (curses.KEY_DOWN, ord("j")):
            self.selected += 1
        elif key in (10, 13):
            visible = self._visible()
            if visible:
                self.hunt = visible[min(self.selected, len(visible) - 1)]
                if self.hunt.frequency:
                    monitor.set_frequency(self.hunt.frequency)
        elif key in (curses.KEY_BACKSPACE, 127, 8):
            self.filter = self.filter[:-1]
        elif 32 <= key < 127:
            self.filter += chr(key)

    def _visible(self) -> list[AccessPoint]:
        return sorted((ap for ap in self.aps.values() if ap.matches(self.filter)), key=lambda ap: ap.rssi, reverse=True)

    def _draw(self) -> None:
        self.screen.erase()
        if self.hunt:
            self._draw_hunt(self.hunt)
        else:
            self._draw_scan()
        self.screen.refresh()

    def _draw_scan(self) -> None:
        self.screen.addstr(0, 0, f"SCAN  {self.adapter.interface}/{self.adapter.phy}   filter: {self.filter}_", curses.A_BOLD)
        self.screen.addstr(2, 0, "RSSI   CH    FREQ   BSSID              SSID                       LAST")
        visible = self._visible()
        self.selected = min(self.selected, max(0, len(visible) - 1))
        for index, ap in enumerate(visible[: self.screen.getmaxyx()[0] - 4]):
            age = time.monotonic() - ap.last_seen
            line = f"{ap.rssi:4}  {str(ap.channel or '?'):>4}  {str(ap.frequency or '?'):>5}  {ap.bssid:17}  {ap.ssid:25.25}  {age:5.1f}s"
            self.screen.addnstr(3 + index, 0, line, self.screen.getmaxyx()[1] - 1, curses.A_REVERSE if index == self.selected else 0)

    def _draw_hunt(self, ap: AccessPoint) -> None:
        smooth = ap.average if ap.average is not None else ap.rssi
        label, color = proximity(smooth)
        width = max(10, min(50, self.screen.getmaxyx()[1] - 4))
        filled = round(width * max(0, min(1, (smooth + 90) / 65)))
        lines = [ap.ssid, ap.bssid, f"CH {ap.channel or '?'}  {ap.frequency or '?'} MHz", "", f"{ap.rssi} dBm", ""]
        for row, text in enumerate(lines, 1):
            self.screen.addstr(row, max(0, (self.screen.getmaxyx()[1] - len(text)) // 2), text, curses.A_BOLD)
        self.screen.addstr(7, 2, "█" * filled, curses.color_pair(color) | curses.A_BOLD)
        self.screen.addstr(7, 2 + filled, "░" * (width - filled))
        self.screen.addstr(9, 2, label, curses.color_pair(color) | curses.A_BOLD)
        age = time.monotonic() - ap.last_seen
        self.screen.addstr(11, 2, f"current {ap.rssi:4}   avg {smooth:5.1f}   min {ap.minimum:4}   max {ap.maximum:4}")
        self.screen.addstr(12, 2, f"last {age:5.2f}s   samples {ap.samples}")
        self.screen.addstr(14, 2, f"[B] beep {'ON' if self.beep else 'off'}   [R] reset   [Esc] scan   [Q] quit")
        if self.beep and time.monotonic() - self.last_beep >= beep_interval(smooth):
            curses.beep()
            self.last_beep = time.monotonic()


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
