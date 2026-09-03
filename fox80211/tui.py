from __future__ import annotations

import curses
import queue
import subprocess
import threading
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, replace

from .capture import CSA_FIELDS, TsharkCapture
from .dfs import ChannelSwitch, DfsEvent, DfsEventMonitor, DfsKind, EventHistory
from .model import AccessPoint, Adapter, Channel, MISSING_SSID
from .sound import SoundBackend, TerminalBell
from .system import MonitorInterface, available_channels

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


@dataclass(frozen=True)
class ScanLayout:
    width: int
    signal: bool
    frequency: bool
    bssid: bool
    last: bool
    ssid_width: int


@dataclass(frozen=True)
class HuntNotice:
    expires: float
    bssid: str
    title: str
    body: tuple[str, ...]


def scan_layout(width: int) -> ScanLayout:
    """Central responsive policy; DFS/event is never sacrificed for extras."""
    usable = max(1, width - 1)
    signal = usable >= 115
    frequency = usable >= 105
    bssid = usable >= 62
    last = usable >= 78
    # Field widths plus one separator between every visible column.  Keeping
    # this calculation in sync with scan_header/scan_row lets SSID consume all
    # remaining space instead of leaving an unexplained gap at the right.
    visible_optional = sum((signal, frequency, bssid, last))
    fixed = 4 + 3 + 8 + 3 + visible_optional  # fields and all separators
    fixed += 18 if signal else 0
    fixed += 5 if frequency else 0
    fixed += 17 if bssid else 0
    fixed += 7 if last else 0
    return ScanLayout(usable, signal, frequency, bssid, last, max(8, usable - fixed))


def scan_header(layout: ScanLayout) -> str:
    parts = [f"{'RSSI':>4}", f"{'CH':>3}", f"{'STATUS':<8}"]
    if layout.signal:
        parts.append(f"{'SIGNAL':<18}")
    if layout.frequency:
        parts.append(f"{'FREQ':>5}")
    if layout.bssid:
        parts.append(f"{'BSSID':<17}")
    parts.append(f"{'SSID':<{layout.ssid_width}}")
    if layout.last:
        parts.append(f"{'LAST':<7}")
    return " ".join(parts)[: layout.width].ljust(layout.width)


def scan_row(
    ap: AccessPoint,
    age: float,
    layout: ScanLayout,
    dfs: bool = False,
    dfs_state: str | None = None,
) -> str:
    event = ap.event_label
    if ap.event_target is not None and event in ("MOVE", "CSA"):
        event += f"→{ap.event_target}"
    if event == "-" and dfs:
        event = (
            "NOP"
            if dfs_state == "UNAVAILABLE"
            else ("CAC" if dfs_state == "CAC" else "DFS")
        )
    parts = [
        f"{round(smoothed_rssi(ap)):4}",
        f"{ap.channel or '?':>3}",
        f"{event:<8.8}",
    ]
    if layout.signal:
        parts.append(f"{proximity(smoothed_rssi(ap))[0]:<18.18}")
    if layout.frequency:
        parts.append(f"{ap.frequency or '?':>5}")
    if layout.bssid:
        parts.append(f"{ap.bssid:<17.17}")
    parts.append(f"{ap.ssid:<{layout.ssid_width}.{layout.ssid_width}}")
    if layout.last:
        parts.append(("?" if age >= UNCERTAIN_AFTER else " ") + format_age(age))
    return " ".join(parts)[: layout.width]


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
        self.capture_totals = [0, 0, 0, 0]
        self.diagnostics = False
        self.help_visible = False
        self.diagnostics_selected = 0
        self.channels: dict[int, Channel] = {}
        self.event_history = EventHistory()
        self.dfs_monitor: DfsEventMonitor | None = None
        self.hunt_notice: HuntNotice | None = None
        self.deferred_dfs_events: deque[DfsEvent | ChannelSwitch] = deque(maxlen=256)
        self.csa_available = False

    def run(self) -> None:
        channels = available_channels(self.adapter.phy)
        self.channels = {item.frequency: item for item in channels}
        frequencies = [
            (item.frequency, item.number) for item in channels if not item.disabled
        ]
        self.channel_by_frequency = dict(frequencies)
        # Keep observations for longer than a complete sweep.  The extra dwell
        # leaves room for tune and scheduling overhead between revisits.
        self.expire_after = scan_expiry(len(frequencies))
        if not frequencies:
            raise RuntimeError("the PHY reports no enabled channels")
        with MonitorInterface(self.adapter) as monitor:
            capture = TsharkCapture(monitor.name)
            capture.start()
            self.csa_available = bool(set(capture.fields) & set(CSA_FIELDS))
            dfs = DfsEventMonitor(self.adapter.phy)
            try:
                dfs.start()
                self.dfs_monitor = dfs
            except (OSError, subprocess.SubprocessError):
                dfs.stderr.close()
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
                    self._dfs_events(capture, apply=not self.paused)
                    desired_target = self.hunt.bssid if self.hunt else None
                    if capture.target_bssid != (
                        desired_target.casefold() if desired_target else None
                    ):
                        replacement = self._replace_capture(
                            capture, monitor.name, desired_target
                        )
                        self._accumulate_capture(capture)
                        capture = replacement
                        self.capture_statistics = capture
                    self._draw()
                    time.sleep(0.05)
            finally:
                self.running = False
                self.stop_event.set()
                hopper.join(timeout=2)
                capture.stop()
                if self.dfs_monitor:
                    self.dfs_monitor.stop()

    def _dfs_events(self, capture: TsharkCapture, apply: bool = True) -> None:
        pending = list(self.deferred_dfs_events) if apply else []
        if apply:
            self.deferred_dfs_events.clear()
        if self.dfs_monitor:
            while True:
                try:
                    event = self.dfs_monitor.events.get_nowait()
                except queue.Empty:
                    break
                pending.append(event)
        switches = getattr(capture, "channel_switches", None)
        if switches is not None:
            while True:
                try:
                    pending.append(switches.get_nowait())
                except queue.Empty:
                    break
        if not apply:
            self.deferred_dfs_events.extend(pending)
            return
        for raw_event in pending:
            if isinstance(raw_event, DfsEvent):
                self._apply_local_dfs_event(raw_event)
                continue
            switch = raw_event
            ap = self.aps.get(switch.bssid)
            old_frequency = ap.frequency if ap else None
            original = self.channels.get(old_frequency or 0)
            switch = ChannelSwitch(
                switch.timestamp,
                switch.bssid,
                switch.old_channel or (ap.channel if ap else None),
                switch.target_channel,
                switch.target_frequency,
                bool(original and original.radar),
                switch.switch_count,
                switch.operating_class,
            )
            self.event_history.add(switch)
            if ap:
                confirmed = self.event_history.radar_for(
                    old_frequency, switch.timestamp
                )
                ap.event_label = (
                    "RADAR+MOVE"
                    if confirmed
                    else ("MOVE" if switch.from_dfs else "CSA")
                )
                ap.event_target, ap.event_seen = switch.target_channel, switch.timestamp
                source_band = network_band(old_frequency)
                target = next(
                    (
                        channel
                        for channel in self.channels.values()
                        if channel.number == switch.target_channel
                        and network_band(channel.frequency) == source_band
                    ),
                    None,
                )
                # Do not leave the announcing AP before its countdown reaches
                # zero. A later observation on the new channel also updates the
                # target naturally if the zero-count frame is missed.
                if target and switch.switch_count == 0:
                    # The hopper observes this model update under its tune lock
                    # and follows the selected BSSID to the announced channel.
                    ap.channel, ap.frequency = target.number, target.frequency
                if self.hunt is ap:
                    self.hunt_notice = hunt_notification(
                        switch, switch.old_channel, bssid=ap.bssid
                    )

    def _apply_local_dfs_event(self, event: DfsEvent) -> None:
        self.event_history.add(event)
        matches = [
            channel
            for channel in self.channels.values()
            if (event.frequency is not None and channel.frequency == event.frequency)
            or (
                event.frequency is None
                and event.channel is not None
                and channel.number == event.channel
            )
        ]
        # Channel-only events can be ambiguous across bands; do not mutate an
        # unrelated cached regulatory state in that case.
        if event.frequency is not None or len(matches) == 1:
            states = {
                DfsKind.RADAR: "UNAVAILABLE",
                DfsKind.CAC_STARTED: "CAC",
                DfsKind.CAC_FINISHED: "AVAILABLE",
                DfsKind.CAC_ABORTED: None,
                DfsKind.NOP_FINISHED: "USABLE",
                DfsKind.PRE_CAC_EXPIRED: "USABLE",
            }
            for channel in matches:
                self.channels[channel.frequency] = replace(
                    channel, dfs_state=states[event.kind]
                )
        channel_number = event.channel or self.channel_by_frequency.get(
            event.frequency or 0
        )
        for ap in self.aps.values():
            relevant = (
                event.frequency is not None and ap.frequency == event.frequency
            ) or (
                event.frequency is None
                and event.channel is not None
                and ap.channel == event.channel
            )
            if relevant:
                ap.event_label = event.kind.value
                ap.event_seen = event.timestamp
        if self.hunt:
            relevant = (
                event.frequency is not None and self.hunt.frequency == event.frequency
            ) or (
                event.frequency is None
                and event.channel is not None
                and self.hunt.channel == event.channel
            )
            if relevant:
                self.hunt_notice = hunt_notification(
                    event, channel_number, bssid=self.hunt.bssid
                )

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

    def _accumulate_capture(self, capture: TsharkCapture) -> None:
        for index, value in enumerate(capture_counters(capture)):
            self.capture_totals[index] += value

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
                        with self.tune_lock:
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
                            cancelled=lambda target=target: (
                                self.stop_event.is_set() or self.hunt is not target
                            ),
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
                if ssid != MISSING_SSID or ap.ssid == MISSING_SSID:
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
            elif key in (curses.KEY_UP, "k"):
                self.diagnostics_selected = max(0, self.diagnostics_selected - 1)
            elif key in (curses.KEY_DOWN, "j"):
                self.diagnostics_selected += 1
            return True
        if self.help_visible:
            if key in (27, "\x1b", "h", "H", "?", "q", "Q"):
                self.help_visible = False
            return True
        if key in ("q", "Q", "\x03", 3):
            self.running = False
        elif self.hunt:
            if key in (27, "\x1b"):
                self.hunt = None
                self.hunt_notice = None
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
            self.diagnostics_selected = 0
        elif key in ("h", "H", "?"):
            self.help_visible = True
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
                    self.hunt_notice = None
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
        if self.help_visible:
            self._draw_help()
        elif self.diagnostics:
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
        width = self.screen.getmaxyx()[1]
        self.screen.addnstr(
            1,
            0,
            scan_status(
                len(self.channel_by_frequency),
                len(self.usable_frequencies),
                len(self.rejected_frequencies),
                self.channel_by_frequency.get(self.current_frequency or 0, "?"),
                self.current_frequency,
                self.tune_statistics.latest,
                self.tune_statistics.last_sweep,
                width - 1,
            ),
            width - 1,
        )
        layout = scan_layout(width)
        self.screen.addnstr(2, 0, scan_header(layout), width - 1, curses.A_BOLD)
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
            metadata = self.channels.get(ap.frequency or 0)
            line = scan_row(
                ap,
                age,
                layout,
                bool(metadata and metadata.radar),
                metadata.dfs_state if metadata else None,
            )
            # Stale observations must be visually distinct from live signal
            # strength, so do not retain a signal-gradient colour for them.
            attr = curses.A_DIM if age >= UNCERTAIN_AFTER else scan_signal_attr(rssi)
            if age < UNCERTAIN_AFTER:
                state_label = (
                    "NOP"
                    if metadata and metadata.dfs_state == "UNAVAILABLE"
                    else "CAC"
                    if metadata and metadata.dfs_state == "CAC"
                    else ap.event_label
                )
                attr = event_attr(state_label, bool(metadata and metadata.radar), attr)
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

    def _draw_help(self) -> None:
        """Draw a compact glossary and key reference for the scan table."""
        height, width = self.screen.getmaxyx()
        lines = (
            ("HELP — SCAN TABLE", curses.A_BOLD),
            ("RSSI: signal strength in dBm; closer to 0 is stronger.", 0),
            ("STATUS: DFS = radar-sensitive channel (not a radar alert).", 0),
            (
                "RADAR = locally confirmed; MOVE/CSA = AP announced a channel switch.",
                0,
            ),
            (
                "CAC = channel availability check; NOP = channel temporarily unavailable.",
                0,
            ),
            ("", 0),
            ("[2] toggle 2.4 GHz networks   [5] toggle 5 GHz networks", 0),
            ("[6] toggle 6 GHz networks     on/off in the footer shows visibility.", 0),
            ("[F] filter  [R] clear  [Space] pause/resume  [Enter] hunt", 0),
            ("[D] diagnostics  [Up/Down] select", 0),
        )
        for row, (line, attr) in enumerate(lines[: max(0, height - 1)]):
            self.screen.addnstr(row, 0, line, width - 1, attr)
        self.screen.addnstr(
            height - 1, 0, "[H/?/Esc/Q] return to scan", width - 1, curses.A_BOLD
        )

    def _draw_diagnostics(self) -> None:
        height, width = self.screen.getmaxyx()
        self.screen.addnstr(0, 0, "DIAGNOSTICS", width - 1, curses.A_BOLD)
        if height < 7:
            if height > 2:
                self.screen.addnstr(
                    1, 0, "Resize to at least 7 rows", width - 1, curses.A_BOLD
                )
            self.screen.addnstr(
                height - 1, 0, "[D/Esc] scan   [Q] quit", width - 1, curses.A_BOLD
            )
            return
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
            counters = tuple(
                total + current
                for total, current in zip(
                    self.capture_totals, capture_counters(capture), strict=True
                )
            )
            capture_line = (
                f"Frames: parsed {counters[0]}   with RSSI {counters[1]}   "
                f"without RSSI {counters[2]}   parse errors {counters[3]}"
            )
            self.screen.addnstr(3, 0, capture_line, width - 1)
        states = (
            "available"
            if self.channels and any(c.dfs_state for c in self.channels.values())
            else "unavailable"
        )
        radar = (
            "available"
            if self.dfs_monitor and self.dfs_monitor.available
            else "unavailable"
        )
        csa = "available" if self.csa_available else "unavailable"
        self.screen.addnstr(
            4,
            0,
            f"DFS: states {states}; local radar events {radar}; CSA {csa}",
            width - 1,
        )
        self.screen.addnstr(
            5,
            0,
            "DFS=radar-sensitive  RADAR=local confirmation  MOVE=cause unknown  CAC=check  NOP=unavailable",
            width - 1,
        )
        history = list(self.event_history.items)[-2:] if height >= 12 else []
        if height >= 12:
            self.screen.addnstr(
                6, 0, "Recent DFS/channel events", width - 1, curses.A_BOLD
            )
        for index, event in enumerate(history, 7):
            stamp = time.strftime("%H:%M:%S", time.localtime(event.timestamp))
            if isinstance(event, ChannelSwitch):
                detail = f"{stamp} {event.bssid} {event.label} {event.old_channel or '?'}→{event.target_channel or '?'}"
            else:
                detail = f"{stamp} CH{event.channel or self.channel_by_frequency.get(event.frequency or 0, '?')} {event.kind.value}"
            self.screen.addnstr(index, 0, detail, width - 1)
        rejected_row = (7 + len(history)) if height >= 12 else 6
        self.screen.addnstr(
            rejected_row, 0, "Rejected frequencies", width - 1, curses.A_BOLD
        )
        rows = max(0, height - rejected_row - 2)
        with self.tune_lock:
            rejected = sorted(self.rejected_frequencies.items())
        self.diagnostics_selected = min(
            self.diagnostics_selected, max(0, len(rejected) - 1)
        )
        offset = min(
            max(0, self.diagnostics_selected - rows + 1),
            max(0, len(rejected) - rows),
        )
        for row, (frequency, reason) in enumerate(
            rejected[offset : offset + rows], rejected_row + 1
        ):
            channel = self.channel_by_frequency.get(frequency, "?")
            attr = (
                curses.A_REVERSE
                if offset + row - rejected_row - 1 == self.diagnostics_selected
                else 0
            )
            self.screen.addnstr(
                row, 0, f"{frequency} MHz / ch {channel}: {reason}", width - 1, attr
            )
        self.screen.addnstr(
            height - 1,
            0,
            "[Up/Down] rejected   [D/Esc] scan   [Q] quit",
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
        self.screen.addnstr(
            13,
            2,
            "RSSI proximity is approximate; walls and antenna orientation affect it.",
            max(0, terminal_width - 3),
        )
        if (
            self.hunt_notice
            and self.hunt_notice.bssid == ap.bssid
            and time.monotonic() < self.hunt_notice.expires
        ):
            title, body = self.hunt_notice.title, self.hunt_notice.body
            start = 9 if height >= 20 else 1
            self.screen.addnstr(
                start, 2, title, max(0, terminal_width - 3), curses.A_BOLD
            )
            for offset, text in enumerate(body, 1):
                if start + offset < height - 1:
                    self.screen.addnstr(
                        start + offset, 2, text, max(0, terminal_width - 3)
                    )
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


def capture_counters(capture: TsharkCapture) -> tuple[int, int, int, int]:
    return (
        capture.frames_parsed,
        capture.frames_with_rssi,
        capture.frames_without_rssi,
        capture.parse_errors,
    )


def scan_status(
    total: int,
    usable: int,
    rejected: int,
    channel: int | str,
    frequency: int | None,
    tune: float | None,
    sweep: float | None,
    width: int,
) -> str:
    """Return the most informative scan status which fits one terminal row."""
    timing = f" tune {tune * 1000:.0f}ms" if tune is not None else ""
    timing += f" sweep {sweep:.1f}s" if sweep is not None else ""
    frequency_text = frequency or "?"
    variants = (
        f"Channels: {total} available / {usable} usable / {rejected} rejected   Current: {channel} ({frequency_text} MHz){timing}",
        f"Ch {total} avail/{usable} ok/{rejected} reject  Current {channel} ({frequency_text}MHz){timing}",
        f"Ch {usable}/{total} reject {rejected}  {channel} ({frequency_text}MHz){timing}",
        f"Ch {channel} {frequency_text}MHz{timing}",
    )
    return next(
        (variant for variant in variants if len(variant) <= width),
        variants[-1][: max(0, width)],
    )


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
        "[R] clear [Enter] hunt [Q] quit",
        "[R] clear [Q] quit",
        "[Q] quit",
    )
    controls = next((item for item in variants if len(item) <= width), variants[-1])
    bands = " ".join(
        f"{band}:{'on' if band in enabled_bands else 'off'}" for band in BANDS
    )
    for suffix in (
        f"  Bands {bands}  dim=unseen 1m+  [H/?] help  [D] diag",
        f"  {bands}  dim=unseen 1m+  [H]help",
        f"  {bands}  dim=unseen 1m+",
        f"  Bands {bands}  [H/?] help",
        f"  Bands {bands}",
        "  [H/?] help",
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


def event_attr(label: str, dfs: bool, fallback: int = 0) -> int:
    """Semantic colour with readable text and a monochrome attribute fallback."""
    if label.startswith("RADAR"):
        return (curses.color_pair(1) if color_pairs_configured else 0) | curses.A_BOLD
    if label.startswith("NOP"):
        return (curses.color_pair(5) if color_pairs_configured else 0) | curses.A_BOLD
    if label.startswith("CAC") or label in ("MOVE", "CSA"):
        return (curses.color_pair(2) if color_pairs_configured else 0) | curses.A_BOLD
    if dfs:
        # Keep the row's RSSI gradient: the textual DFS label supplies the
        # regulatory distinction without hiding the primary hunting cue.
        return fallback
    return fallback


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
    if rssi < -82:
        return "VERY FAR / HEAVILY OBSTRUCTED", 1
    if rssi < -72:
        return "FAR OR OBSTRUCTED", 1
    if rssi < -62:
        return "SOME DISTANCE", 2
    if rssi < -52:
        return "CLOSE", 3
    if rssi < -42:
        return "NEARBY", 4
    return "VERY CLOSE", 5


def hunt_notification(
    event: DfsEvent | ChannelSwitch,
    channel: int | None,
    now: float | None = None,
    bssid: str = "",
) -> HuntNotice:
    expires = (time.monotonic() if now is None else now) + 12.0
    ch = channel or "?"
    if isinstance(event, ChannelSwitch):
        return HuntNotice(
            expires,
            bssid or event.bssid,
            "CHANNEL SWITCH ANNOUNCED",
            (
                f"The target AP announced a move from channel {ch} to channel {event.target_channel or '?'}.",
                "A DFS move can have several causes. Radar is not confirmed by a CSA.",
            ),
        )
    if event.kind is DfsKind.RADAR:
        return HuntNotice(
            expires,
            bssid,
            "RADAR DETECTED",
            (
                f"The local Wi-Fi adapter reported radar on channel {ch}.",
                "DFS rules require affected transmitters to leave; the target may move.",
            ),
        )
    if event.kind is DfsKind.CAC_STARTED:
        return HuntNotice(
            expires,
            bssid,
            "DFS CAC",
            (f"Channel {ch} is undergoing a Channel Availability Check.",),
        )
    return HuntNotice(
        expires,
        bssid,
        event.kind.value,
        (f"Local DFS event reported for channel {ch}.",),
    )


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
