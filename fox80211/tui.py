from __future__ import annotations

import curses
import queue
import subprocess
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass

from .capture import TsharkCapture
from .model import AccessPoint, Adapter
from .sound import SoundBackend, TerminalBell
from .system import MonitorInterface, available_frequencies

UNCERTAIN_AFTER = 60.0
BANDS = (2, 5, 6)
EXPIRE_AFTER = 30.0 * 60.0
LOST_AFTER = 2.0
HIGH_BAND_LOST_AFTER = 5.0
# Compatibility for callers which imported the old, overly narrow name.
FIVE_GHZ_LOST_AFTER = HIGH_BAND_LOST_AFTER
HOP_DWELL = 0.35
HOP_TUNE_BUDGET = 0.1
LOCK_RETRY_DELAY = 0.1
LOCK_ATTEMPTS = 20
EVENTS_PER_TICK = 64
KEYS_PER_TICK = 8
SCAN_GRADIENT_COLORS = (
    52,
    88,
    124,
    160,
    166,
    172,
    178,
    184,
    190,
    154,
    118,
    82,
    46,
    47,
    48,
    49,
)
SCAN_GRADIENT_PAIR_START = 16
scan_gradient_pairs: tuple[int, ...] = ()
color_pairs_configured = False


@dataclass
class TuneStatistics:
    """Runtime channel-switch measurements, in seconds."""

    latest: float | None = None
    ewma: float | None = None
    samples: int = 0
    last_sweep: float | None = None

    def record(self, elapsed: float) -> None:
        self.latest = elapsed
        self.ewma = elapsed if self.ewma is None else 0.25 * elapsed + 0.75 * self.ewma
        self.samples += 1


def select_adapter(screen: curses.window, adapters: list[Adapter]) -> Adapter:
    selected = 0
    while True:
        screen.erase()
        screen.addstr(0, 0, "Select Wi-Fi adapter (↑/↓, Enter, Q)", curses.A_BOLD)
        screen.addstr(
            2,
            0,
            "IFACE        PHY    DRIVER       DEVICE              MODE       ACTIVE MONITOR",
        )
        for i, item in enumerate(adapters):
            attr = curses.A_REVERSE if i == selected else 0
            active = (
                "yes" if item.connected else ("no" if item.connection_known else "?")
            )
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
                screen.addstr(
                    1,
                    0,
                    "WARNING: this radio and its active connection will be taken offline. Enter to continue.",
                    curses.A_BOLD,
                )
                screen.refresh()
                if screen.get_wch() not in ("\n", "\r", 10, 13):
                    continue
            return adapters[selected]


class Application:
    def __init__(
        self, screen: curses.window, adapter: Adapter, sound: SoundBackend | None = None
    ):
        self.screen = screen
        self.adapter = adapter
        self.aps: dict[str, AccessPoint] = {}
        self.filter = ""
        self.filter_editing = False
        self.filter_before_edit = ""
        self.enabled_bands = set(BANDS)
        self.clear_scan_requested = False
        self.selected = 0
        self.running = True
        self.hunt: AccessPoint | None = None
        self.locking_hunt = False
        self.beep = False
        self.paused = False
        self.paused_at: float | None = None
        self.last_beep = 0.0
        self.stop_event = threading.Event()
        self.tune_lock = threading.Lock()
        self.sound = sound or TerminalBell()
        self.usable_frequencies: set[int] = set()
        self.rejected_frequencies: dict[int, str] = {}
        self.current_frequency: int | None = None
        self.tune_error: str | None = None
        self.channel_by_frequency: dict[int, int] = {}
        self.expire_after = EXPIRE_AFTER
        self.tune_statistics = TuneStatistics()
        self.lock_attempt = 0
        self.lock_detail: str | None = None
        self.capture_statistics: TsharkCapture | None = None
        self.diagnostics = False

    def run(self) -> None:
        frequencies = available_frequencies(self.adapter.phy)
        self.channel_by_frequency = dict(frequencies)
        # Keep observations for longer than a complete sweep.  The extra dwell
        # leaves room for tune and scheduling overhead between revisits.
        self.expire_after = scan_expiry(len(frequencies))
        if not frequencies:
            raise RuntimeError("the PHY reports no enabled channels")
        with MonitorInterface(self.adapter) as monitor:
            capture = TsharkCapture(monitor.name)
            capture.start()
            self.capture_statistics = capture
            hopper = threading.Thread(
                target=self._hop,
                args=(monitor, frequencies),
                name="80211fox-hopper",
                daemon=True,
            )
            hopper.start()
            try:
                self.screen.nodelay(True)
                while self.running:
                    capture.raise_if_failed()
                    self._input(monitor)
                    if not self.running:
                        break
                    self._events(capture, apply=not self.paused)
                    desired_target = self.hunt.bssid if self.hunt else None
                    if capture.target_bssid != (
                        desired_target.casefold() if desired_target else None
                    ):
                        capture = self._replace_capture(
                            capture, monitor.name, desired_target
                        )
                        self.capture_statistics = capture
                    self._draw()
                    time.sleep(0.05)
            finally:
                self.running = False
                self.stop_event.set()
                hopper.join(timeout=2)
                capture.stop()

    @staticmethod
    def _replace_capture(
        current: TsharkCapture, interface: str, target_bssid: str | None
    ) -> TsharkCapture:
        """Switch capture filters with overlap so entering HUNT loses no frames."""
        replacement = TsharkCapture(interface, target_bssid)
        try:
            replacement.start()
        except Exception:
            replacement.stop()
            raise
        current.stop()
        return replacement

    def _hop(
        self, monitor: MonitorInterface, frequencies: list[tuple[int, int]]
    ) -> None:
        while not self.stop_event.is_set():
            if self.paused:
                self.stop_event.wait(0.1)
                continue
            if self.hunt is None:
                scanned_frequency = False
                sweep_started = time.monotonic()
                for frequency, _ in frequencies:
                    if self.stop_event.is_set() or self.hunt is not None or self.paused:
                        break
                    band = network_band(frequency)
                    if band is not None and band not in self.enabled_bands:
                        continue
                    scanned_frequency = True
                    try:
                        with self.tune_lock:
                            band = network_band(frequency)
                            if (
                                self.hunt is None
                                and not self.paused
                                and (band is None or band in self.enabled_bands)
                            ):
                                tune_started = time.monotonic()
                                monitor.set_frequency(frequency)
                                self.tune_statistics.record(
                                    time.monotonic() - tune_started
                                )
                                self.current_frequency = frequency
                                self.usable_frequencies.add(frequency)
                                self.rejected_frequencies.pop(frequency, None)
                    except Exception as error:
                        self.usable_frequencies.discard(frequency)
                        self.rejected_frequencies[frequency] = command_error(error)
                    self.stop_event.wait(HOP_DWELL)
                if (
                    scanned_frequency
                    and not self.stop_event.is_set()
                    and self.hunt is None
                    and not self.paused
                ):
                    self.tune_statistics.last_sweep = time.monotonic() - sweep_started
                    self.expire_after = scan_expiry(
                        len(frequencies), self.tune_statistics.last_sweep
                    )
                if not scanned_frequency:
                    # Avoid a busy loop when every known band is disabled.
                    self.stop_event.wait(0.1)
            else:
                target = self.hunt
                if target is None:
                    continue
                try:
                    with self.tune_lock:
                        if self.hunt is not target:
                            continue
                        # Capture the requested frequency while we own the
                        # radio. Capture events may update the target while an
                        # external tuning command is in progress.
                        requested_frequency = target.frequency
                        self.locking_hunt = (
                            self.current_frequency != requested_frequency
                        )
                        if self.locking_hunt and not self._lock_frequency(
                            monitor,
                            requested_frequency,
                            cancelled=lambda target=target: self.stop_event.is_set()
                            or self.hunt is not target,
                        ):
                            continue
                        if self.hunt is target:
                            self.current_frequency = requested_frequency
                            self.tune_error = None
                            # If capture learned a new channel while `iw` was
                            # running, keep the locking view visible until the
                            # next iteration tunes that newer frequency.
                            self.locking_hunt = target.frequency != requested_frequency
                except Exception as error:
                    if self.hunt is target:
                        self.tune_error = f"Unable to lock channel {target.channel or '?'}: {command_error(error)}"
                        self.hunt = None
                        self.locking_hunt = False
                self.stop_event.wait(0.1)

    def _events(self, capture: TsharkCapture, apply: bool = True) -> None:
        if self.clear_scan_requested:
            # Discard exactly the observations that were already queued when
            # reset was requested. Frames arriving after this snapshot belong
            # to the new scan and may be applied on the next UI tick.
            for _ in range(capture.events.qsize()):
                try:
                    capture.events.get_nowait()
                except queue.Empty:
                    break
            self.clear_scan_requested = False
            return
        for _ in range(EVENTS_PER_TICK):
            try:
                bssid, ssid, rssi, channel, frequency = capture.events.get_nowait()
            except queue.Empty:
                break
            # Keep draining the bounded capture path while paused, but do not
            # let packets received on the last tuned channel change the frozen
            # scan view.
            if not apply:
                continue
            ap = self.aps.get(bssid)
            if ap:
                if ssid != "<hidden>" or ap.ssid == "<hidden>":
                    ap.ssid = ssid
                ap.update(rssi, channel, frequency)
            else:
                self.aps[bssid] = AccessPoint(
                    bssid,
                    ssid,
                    rssi,
                    channel,
                    frequency,
                    average=float(rssi),
                    minimum=rssi,
                    maximum=rssi,
                )
        if apply:
            now = time.monotonic()
            self.aps = {
                bssid: ap
                for bssid, ap in self.aps.items()
                if ap is self.hunt or now - ap.last_seen <= self.expire_after
            }

    def _input(self, monitor: MonitorInterface) -> None:
        for _ in range(KEYS_PER_TICK):
            if not self._keys(monitor) or not self.running:
                break

    def _keys(self, monitor: MonitorInterface) -> bool:
        try:
            key = self.screen.get_wch()
        except curses.error:
            return False
        if self.filter_editing:
            if key in ("\n", "\r", 10, 13):
                self.filter_editing = False
            elif key in (27, "\x1b"):
                self.filter = self.filter_before_edit
                self.filter_editing = False
                self.selected = 0
            elif key in (curses.KEY_BACKSPACE, 127, 8, "\x7f", "\b"):
                self.filter = self.filter[:-1]
                self.selected = 0
            elif isinstance(key, str) and key.isprintable():
                self.filter += key
                self.selected = 0
            return True
        if self.diagnostics:
            if key in (27, "\x1b", "d", "D"):
                self.diagnostics = False
            elif key in ("q", "Q", "\x03", 3):
                self.running = False
            return True
        if key in ("q", "Q", "\x03", 3):
            self.running = False
        elif self.hunt:
            if key in (27, "\x1b"):
                self.hunt = None
                self.locking_hunt = False
                self.lock_attempt = 0
                self.lock_detail = None
            elif key in ("b", "B"):
                self.beep = not self.beep
            elif key in ("r", "R"):
                ap = self.hunt
                ap.samples, ap.minimum, ap.maximum, ap.average = (
                    1,
                    ap.rssi,
                    ap.rssi,
                    float(ap.rssi),
                )
        elif key == " ":
            self.paused = not self.paused
            self.paused_at = time.monotonic() if self.paused else None
        elif key in ("f", "F"):
            self.filter_editing = True
            self.filter_before_edit = self.filter
        elif key in ("d", "D"):
            self.diagnostics = True
        elif key in ("2", "5", "6"):
            band = int(key)
            # Serialize band changes with channel tuning. This makes the band
            # check in the hopper and the subsequent set-frequency command a
            # single operation from the UI's point of view.
            with self.tune_lock:
                if band in self.enabled_bands:
                    self.enabled_bands.remove(band)
                else:
                    self.enabled_bands.add(band)
            self.selected = 0
        elif key in ("r", "R"):
            self.aps.clear()
            self.selected = 0
            self.clear_scan_requested = True
        elif key == curses.KEY_UP:
            self.selected = max(0, self.selected - 1)
        elif key == curses.KEY_DOWN:
            self.selected += 1
        elif key in ("\n", "\r", 10, 13):
            visible = self._visible()
            if visible:
                target = visible[min(self.selected, len(visible) - 1)]
                if not target.frequency:
                    self.tune_error = f"Unable to lock channel: {target.bssid} has no known frequency yet"
                    self.hunt = None
                else:
                    # HUNT is a live view even when it is entered from a frozen
                    # scan, so resume capture updates before locking the target.
                    self.paused = False
                    self.paused_at = None
                    # Publish the request for the hopper, which is the sole
                    # owner of channel changes.  In particular, do not retry a
                    # busy driver from the UI thread: doing so stops event
                    # draining and drawing for several seconds.
                    self.hunt = target
                    # Treat the request as locking until the hopper acquires
                    # tune_lock and verifies which frequency the radio is
                    # actually using.
                    self.locking_hunt = True
                    self.lock_attempt = 0
                    self.lock_detail = None
        return True

    def _lock_frequency(
        self,
        monitor: MonitorInterface,
        frequency: int,
        cancelled: Callable[[], bool] | None = None,
    ) -> bool:
        """Tune for hunt mode, retrying the driver's transient busy response."""
        for attempt in range(LOCK_ATTEMPTS):
            self.lock_attempt = attempt + 1
            self.lock_detail = None
            if cancelled is not None and cancelled():
                return False
            try:
                monitor.set_frequency(frequency)
                return True
            except subprocess.CalledProcessError as error:
                self.lock_detail = command_error(error)
                if not frequency_is_busy(error) or attempt == LOCK_ATTEMPTS - 1:
                    raise
                self.stop_event.wait(LOCK_RETRY_DELAY)
        return False

    def _visible(self) -> list[AccessPoint]:
        def band_is_visible(ap: AccessPoint) -> bool:
            band = network_band(ap.frequency)
            return band is None or band in self.enabled_bands

        return sorted(
            (
                ap
                for ap in self.aps.values()
                if ap.matches(self.filter) and band_is_visible(ap)
            ),
            key=lambda ap: (-smoothed_rssi(ap), ap.bssid),
        )

    def _draw(self) -> None:
        self.screen.erase()
        height, width = self.screen.getmaxyx()
        if height < 4 or width < 20:
            self.screen.addnstr(
                0, 0, "Terminal too small; resize", max(1, width - 1), curses.A_BOLD
            )
            self.screen.refresh()
            return
        if self.diagnostics:
            self._draw_diagnostics()
        elif self.hunt:
            self._draw_hunt(self.hunt)
        else:
            self._draw_scan()
        self.screen.refresh()

    def _draw_scan(self) -> None:
        state = "PAUSED" if self.paused else "SCANNING"
        prefix = f"{state}  {self.adapter.interface}/{self.adapter.phy}   filter: "
        self.screen.addstr(0, 0, prefix, curses.A_BOLD)
        field = f" {self.filter}{'_' if self.filter_editing else ''} "
        field_attr = (
            curses.A_REVERSE | curses.A_BOLD if self.filter_editing else curses.A_BOLD
        )
        self.screen.addnstr(
            0,
            len(prefix),
            field,
            max(0, self.screen.getmaxyx()[1] - len(prefix) - 1),
            field_attr,
        )
        total = len(self.channel_by_frequency)
        current = self.channel_by_frequency.get(self.current_frequency or 0, "?")
        tune = self.tune_statistics.latest
        sweep = self.tune_statistics.last_sweep
        timing = f"   tune {tune * 1000:.0f} ms" if tune is not None else ""
        timing += f"   sweep {sweep:.1f} s" if sweep is not None else ""
        self.screen.addstr(
            1,
            0,
            f"Channels: {total} available / {len(self.usable_frequencies)} usable / {len(self.rejected_frequencies)} rejected   Current: {current} ({self.current_frequency or '?'} MHz){timing}",
        )
        self.screen.addstr(
            2,
            0,
            "RSSI   CH    FREQ   BSSID              SSID                        LAST",
        )
        if self.tune_error:
            self.screen.addnstr(
                1, 0, self.tune_error, self.screen.getmaxyx()[1] - 1, curses.A_BOLD
            )
        visible = self._visible()
        self.selected = min(self.selected, max(0, len(visible) - 1))
        height, width = self.screen.getmaxyx()
        page_size = max(0, height - 4)
        offset = min(
            max(0, self.selected - page_size + 1), max(0, len(visible) - page_size)
        )
        for row, ap in enumerate(visible[offset : offset + page_size]):
            index = offset + row
            now = self.paused_at if self.paused_at is not None else time.monotonic()
            age = now - ap.last_seen
            rssi = round(smoothed_rssi(ap))
            uncertain = "?" if age >= UNCERTAIN_AFTER else " "
            line = f"{rssi:4}  {str(ap.channel or '?'):>4}  {str(ap.frequency or '?'):>5}  {ap.bssid:17}  {ap.ssid:25.25}  {uncertain}{format_age(age)}"
            # Stale observations must be visually distinct from live signal
            # strength, so do not retain a signal-gradient colour for them.
            attr = curses.A_DIM if age >= UNCERTAIN_AFTER else scan_signal_attr(rssi)
            if index == self.selected:
                attr |= curses.A_REVERSE
            self.screen.addnstr(3 + row, 0, line, width - 1, attr)
        action = "resume" if self.paused else "pause"
        self.screen.addnstr(
            height - 1,
            0,
            scan_controls(action, self.enabled_bands, width - 1),
            width - 1,
            curses.A_BOLD,
        )

    def _draw_diagnostics(self) -> None:
        height, width = self.screen.getmaxyx()
        self.screen.addnstr(0, 0, "DIAGNOSTICS", width - 1, curses.A_BOLD)
        stats = self.tune_statistics
        tune = "not measured"
        if stats.samples and stats.ewma is not None and stats.latest is not None:
            tune = (
                f"latest {stats.latest * 1000:.1f} ms   "
                f"EWMA {stats.ewma * 1000:.1f} ms   samples {stats.samples}"
            )
        self.screen.addnstr(1, 0, f"Tune: {tune}", width - 1)
        sweep = (
            f"{stats.last_sweep:.2f} s"
            if stats.last_sweep is not None
            else "not measured"
        )
        self.screen.addnstr(2, 0, f"Last complete sweep: {sweep}", width - 1)
        capture = self.capture_statistics
        if capture is not None:
            capture_line = (
                f"Frames: parsed {capture.frames_parsed}   with RSSI "
                f"{capture.frames_with_rssi}   without RSSI "
                f"{capture.frames_without_rssi}   parse errors {capture.parse_errors}"
            )
            self.screen.addnstr(3, 0, capture_line, width - 1)
        self.screen.addnstr(5, 0, "Rejected frequencies", width - 1, curses.A_BOLD)
        rows = max(0, height - 7)
        for row, (frequency, reason) in enumerate(
            sorted(self.rejected_frequencies.items())[:rows], 6
        ):
            channel = self.channel_by_frequency.get(frequency, "?")
            self.screen.addnstr(
                row, 0, f"{frequency} MHz / ch {channel}: {reason}", width - 1
            )
        self.screen.addnstr(
            height - 1,
            0,
            "[D/Esc] scan   [Q] quit",
            width - 1,
            curses.A_BOLD,
        )

    def _draw_hunt(self, ap: AccessPoint) -> None:
        height, terminal_width = self.screen.getmaxyx()
        if height < 15 or terminal_width < 40:
            message = f"HUNT {ap.ssid} {ap.rssi} dBm — resize to at least 40x15"
            self.screen.addnstr(1, 0, message, terminal_width - 1, curses.A_BOLD)
            return
        if self.locking_hunt:
            message = f"LOCKING CHANNEL {ap.channel or '?'} ({ap.frequency or '?'} MHz)"
            self.screen.addstr(
                6, max(0, (terminal_width - len(message)) // 2), message, curses.A_BOLD
            )
            if self.lock_attempt:
                detail = f"retry {self.lock_attempt}/{LOCK_ATTEMPTS}"
                if self.lock_detail:
                    detail += f": {self.lock_detail}"
                self.screen.addnstr(
                    8,
                    max(0, (terminal_width - len(detail)) // 2),
                    detail,
                    terminal_width - 1,
                )
            self._draw_hunt_controls(terminal_width)
            return
        smooth = ap.average if ap.average is not None else ap.rssi
        age = time.monotonic() - ap.last_seen
        if age > hunt_lost_after(ap.frequency):
            width = max(10, terminal_width - 4)
            self.screen.addstr(
                4, max(0, (terminal_width - 11) // 2), "SIGNAL LOST", curses.A_BOLD
            )
            self.screen.addstr(
                6, max(0, (terminal_width - 6) // 2), "-- dBm", curses.A_BOLD
            )
            self.screen.addstr(8, 2, "░" * width)
            self.screen.addstr(12, 2, f"last {age:5.2f}s")
            self._draw_hunt_controls(terminal_width)
            return
        label, color = proximity(smooth)
        width = max(10, terminal_width - 4)
        filled = round(width * max(0, min(1, (smooth + 90) / 65)))
        lines = [
            ap.ssid,
            ap.bssid,
            f"CH {ap.channel or '?'}  {ap.frequency or '?'} MHz",
            "",
            f"{ap.rssi} dBm",
            "",
        ]
        for row, text in enumerate(lines, 1):
            self.screen.addstr(
                row,
                max(0, (self.screen.getmaxyx()[1] - len(text)) // 2),
                text,
                curses.A_BOLD,
            )
        self.screen.addstr(7, 2, "█" * filled, curses.color_pair(color) | curses.A_BOLD)
        self.screen.addstr(7, 2 + filled, "░" * (width - filled))
        self.screen.addstr(9, 2, label, curses.color_pair(color) | curses.A_BOLD)
        minimum = ap.rssi if ap.minimum is None else ap.minimum
        maximum = ap.rssi if ap.maximum is None else ap.maximum
        self.screen.addstr(
            11,
            2,
            f"current {ap.rssi:4}   avg {smooth:5.1f}   min {minimum:4}   max {maximum:4}",
        )
        self.screen.addstr(12, 2, f"last {age:5.2f}s   samples {ap.samples}")
        self._draw_hunt_controls(terminal_width)
        if self.beep and time.monotonic() - self.last_beep >= beep_interval(smooth):
            self.sound.beep()
            self.last_beep = time.monotonic()

    def _draw_hunt_controls(self, terminal_width: int) -> None:
        controls = f"[B] beep {'ON' if self.beep else 'off'} ({self.sound.name})   [R] reset   [Esc] scan   [Q] quit"
        self.screen.addnstr(14, 2, controls, max(0, terminal_width - 3))


def command_error(error: Exception) -> str:
    if isinstance(error, subprocess.CalledProcessError):
        stderr = (error.stderr or "").strip()
        return (
            stderr.rsplit("\n", 1)[-1]
            if stderr
            else f"command exited {error.returncode}"
        )
    return str(error)


def frequency_is_busy(error: subprocess.CalledProcessError) -> bool:
    """Recognize the transient EBUSY responses produced by iw/nl80211."""
    detail = f"{error.stdout or ''}\n{error.stderr or ''}".casefold()
    return "device or resource busy" in detail or "(-16)" in detail


def scan_expiry(frequency_count: int, last_sweep: float | None = None) -> float:
    # Each hop includes both the dwell and an external `iw` tuning command.
    # Reserve a per-channel tuning/scheduling budget as well as one complete
    # extra hop so observations remain visible until their channel is revisited.
    measured = last_sweep * 1.2 if last_sweep is not None else 0.0
    estimated = (HOP_DWELL + HOP_TUNE_BUDGET) * (frequency_count + 1)
    return max(EXPIRE_AFTER, measured, estimated)


def smoothed_rssi(ap: AccessPoint) -> float:
    return ap.average if ap.average is not None else float(ap.rssi)


def network_band(frequency: int | None) -> int | None:
    """Return the conventional Wi-Fi band for a center frequency in MHz."""
    if frequency is None:
        return None
    if 2400 <= frequency < 2500:
        return 2
    if 4900 <= frequency < 5925:
        return 5
    if 5925 <= frequency <= 7125:
        return 6
    return None


def scan_controls(action: str, enabled_bands: set[int], width: int) -> str:
    """Build a footer that keeps critical controls visible on narrow screens."""
    variants = (
        f"[F] filter [R] clear [Space] {action} [Enter] hunt [Q] quit",
        f"[R] clear [Space] {action} [Enter] hunt [Q] quit",
        f"[R] clear [Enter] hunt [Q] quit",
        "[R] clear [Q] quit",
        "[Q] quit",
    )
    controls = next((item for item in variants if len(item) <= width), variants[-1])
    bands = " ".join(
        f"{band}:{'on' if band in enabled_bands else 'off'}" for band in BANDS
    )
    for suffix in (
        f"  {bands}  dim=unseen 1m+  [D] diag",
        f"  {bands}  dim=unseen 1m+",
        f"  {bands}",
    ):
        if len(controls) + len(suffix) <= width:
            return controls + suffix
    return controls


def signal_level(rssi: float, levels: int) -> int:
    strength = max(0.0, min(1.0, (rssi + 90.0) / 65.0))
    return round((levels - 1) * strength)


def scan_signal_attr(rssi: float) -> int:
    if scan_gradient_pairs:
        return curses.color_pair(
            scan_gradient_pairs[signal_level(rssi, len(scan_gradient_pairs))]
        )
    attr = 0
    if color_pairs_configured:
        _label, color = proximity(rssi)
        attr = curses.color_pair(color)
    if rssi <= -80:
        attr |= curses.A_DIM
    elif rssi >= -45:
        attr |= curses.A_BOLD
    return attr


def hunt_lost_after(frequency: int | None) -> float:
    return (
        HIGH_BAND_LOST_AFTER
        if frequency is not None and frequency >= 5000
        else LOST_AFTER
    )


def format_age(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:5.1f}s"
    total = int(seconds)
    if total < 3600:
        return f"{total // 60:3d}m{total % 60:02d}"
    return f"{total // 3600:3d}h{total % 3600 // 60:02d}"


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
    global color_pairs_configured, scan_gradient_pairs
    curses.start_color()
    curses.use_default_colors()
    for pair, color in enumerate(
        (
            curses.COLOR_RED,
            curses.COLOR_YELLOW,
            curses.COLOR_GREEN,
            curses.COLOR_CYAN,
            curses.COLOR_MAGENTA,
        ),
        1,
    ):
        curses.init_pair(pair, color, -1)
    color_pairs_configured = True
    scan_gradient_pairs = ()
    if curses.COLORS >= 256 and curses.COLOR_PAIRS >= SCAN_GRADIENT_PAIR_START + len(
        SCAN_GRADIENT_COLORS
    ):
        pairs = []
        for offset, color in enumerate(SCAN_GRADIENT_COLORS):
            pair = SCAN_GRADIENT_PAIR_START + offset
            curses.init_pair(pair, color, -1)
            pairs.append(pair)
        scan_gradient_pairs = tuple(pairs)
