import curses
import io
import queue
import signal
import subprocess
import threading
import time
import unittest
from unittest.mock import Mock, call, patch

from fox80211.capture import (
    EVENT_QUEUE_SIZE,
    TsharkCapture,
    _ssid,
    _tshark_fields,
)
from fox80211.cli import _install_signal_handlers
from fox80211.model import AccessPoint, Adapter
from fox80211.system import (
    MonitorInterface,
    _interface_associated,
    available_frequencies,
    cleanup_orphan_monitors,
    discover_adapters,
)
from fox80211.tui import (
    EVENTS_PER_TICK,
    EXPIRE_AFTER,
    HOP_DWELL,
    HOP_TUNE_BUDGET,
    KEYS_PER_TICK,
    LOCK_ATTEMPTS,
    Application,
    TuneStatistics,
    network_band,
    scan_controls,
    scan_expiry,
    scan_status,
    signal_level,
)


class FakeScreen:
    def __init__(self, height=20, width=100):
        self.height, self.width = height, width
        self.writes = []
        self.key = -1

    def getmaxyx(self):
        return self.height, self.width

    def erase(self):
        pass

    def refresh(self):
        pass

    def getch(self):
        return self.key

    def get_wch(self):
        if self.key == -1:
            raise curses.error("no input")
        return self.key

    def addstr(self, row, column, text, attributes=0):
        if row >= self.height:
            raise curses.error("outside screen")
        self.writes.append((row, text, attributes))

    def addnstr(self, row, column, text, length, attributes=0):
        self.addstr(row, column, text[:length], attributes)


class ReviewFixTests(unittest.TestCase):
    def make_app(self, screen=None):
        return Application(screen or FakeScreen(), Adapter("wlan1", "phy1"))

    def test_tshark_hex_ssid_is_decoded_for_display(self):
        self.assertEqual(
            _ssid("4176656e676120436f72706f", "4176656e676120436f72706f"),
            "Avenga Corpo",
        )
        self.assertEqual(_ssid("D0A2D0B5D181D182", "d0:a2:d0:b5:d1:81:d1:82"), "Тест")

    def test_hexadecimal_ssid_is_decoded_when_display_field_is_bytes(self):
        self.assertEqual(_ssid("4142", value_is_bytes=True), "AB")
        self.assertEqual(_ssid("31323334", value_is_bytes=True), "1234")
        self.assertEqual(
            _ssid("4578616d706c6553534944", value_is_bytes=True), "ExampleSSID"
        )

    def test_ambiguous_hexadecimal_text_ssids_are_preserved(self):
        self.assertEqual(_ssid("Cafe"), "Cafe")
        self.assertEqual(_ssid("1234"), "1234")
        self.assertEqual(_ssid("0000"), "0000")

    def test_missing_and_plain_text_ssids_are_preserved(self):
        self.assertEqual(_ssid(""), "<MISSING>")
        self.assertEqual(
            _ssid("Office Wi-Fi", "4f66666963652057692d4669"), "Office Wi-Fi"
        )

    def test_raw_bytes_preserve_plain_hexadecimal_looking_ssids(self):
        self.assertEqual(_ssid("Cafe", "43616665"), "Cafe")
        self.assertEqual(_ssid("1234", "31323334"), "1234")
        self.assertEqual(_ssid("deadbeef", "6465616462656566"), "deadbeef")
        self.assertEqual(_ssid("31323334"), "31323334")

    def test_text_rendering_and_malformed_hex_are_tolerated(self):
        self.assertEqual(_ssid("Office Wi-Fi"), "Office Wi-Fi")
        self.assertEqual(_ssid("abc"), "abc")
        self.assertEqual(_ssid("0x43616665", value_is_bytes=True), "Cafe")
        self.assertEqual(_ssid("0X43616665", value_is_bytes=True), "Cafe")

    def test_raw_ssid_is_authoritative_when_display_field_is_hex_or_wrong(self):
        self.assertEqual(_ssid("43616665", "3433363136363635"), "43616665")
        self.assertEqual(
            _ssid("unhelpful", "53796e74686574696353534944"), "SyntheticSSID"
        )

    def test_null_filled_ssids_are_missing(self):
        self.assertEqual(_ssid("0000", "0000"), "<MISSING>")

    def test_hidden_beacon_does_not_replace_learned_ssid(self):
        app = self.make_app()
        app.aps["AA"] = AccessPoint("AA", "Office", -50, 1, 2412)
        capture = Mock(events=queue.Queue())
        capture.events.put(("AA", "<MISSING>", -49, 1, 2412))
        app._events(capture)
        self.assertEqual(app.aps["AA"].ssid, "Office")

    def test_event_drain_has_a_per_tick_budget(self):
        app = self.make_app()
        capture = Mock(events=queue.Queue())
        for index in range(EVENTS_PER_TICK + 5):
            capture.events.put(("AA", "Office", -50 + index % 2, 1, 2412))

        app._events(capture)

        self.assertEqual(capture.events.qsize(), 5)

    def test_scan_viewport_keeps_selection_visible(self):
        screen = FakeScreen(height=8)
        app = self.make_app(screen)
        for index in range(10):
            bssid = f"00:00:00:00:00:{index:02X}"
            app.aps[bssid] = AccessPoint(bssid, str(index), -30 - index, 1, 2412)
        app.selected = 8
        app._draw_scan()
        highlighted = [
            text for _, text, attr in screen.writes if attr & curses.A_REVERSE
        ]
        self.assertEqual(len(highlighted), 1)
        self.assertIn("00:00:00:00:00:08", highlighted[0])

    def test_scan_displays_and_sorts_by_smoothed_average(self):
        screen = FakeScreen()
        app = self.make_app(screen)
        now = time.monotonic()
        steady = AccessPoint(
            "00:00:00:00:00:01", "steady", -50, 1, 2412, last_seen=now, average=-50
        )
        noisy = AccessPoint(
            "00:00:00:00:00:02", "noisy", -80, 1, 2412, last_seen=now, average=-45
        )
        app.aps = {steady.bssid: steady, noisy.bssid: noisy}

        self.assertEqual([ap.ssid for ap in app._visible()], ["noisy", "steady"])
        app._draw_scan()
        rows = [
            text
            for row, text, _ in screen.writes
            if row >= 3 and "00:00:00:00:00:" in text
        ]
        self.assertTrue(rows[0].startswith(" -45"))

    def test_scan_reserves_last_row_for_controls(self):
        screen = FakeScreen(height=8)
        app = self.make_app(screen)
        for index in range(10):
            bssid = f"00:00:00:00:00:{index:02X}"
            app.aps[bssid] = AccessPoint(bssid, str(index), -30 - index, 1, 2412)
        app._draw_scan()
        access_point_rows = [
            row
            for row, text, _ in screen.writes
            if row >= 3 and "00:00:00:00:00:" in text
        ]
        self.assertEqual(access_point_rows, list(range(3, screen.height - 1)))
        self.assertTrue(
            any(
                row == screen.height - 1
                and "[Space] pause" in text
                and "[Q] quit" in text
                for row, text, _ in screen.writes
            )
        )

    def test_scan_prioritizes_essential_controls_at_narrow_widths(self):
        controls = scan_controls("pause", {2, 5, 6}, 59)
        self.assertIn("[Enter] hunt", controls)
        self.assertIn("[Q] quit", controls)
        self.assertLessEqual(len(controls), 59)

    def test_scan_shows_compact_band_status_at_eighty_columns(self):
        controls = scan_controls("pause", {2, 6}, 79)
        self.assertIn("2:on 5:off 6:on", controls)
        self.assertIn("[Q] quit", controls)
        self.assertLessEqual(len(controls), 79)

    def test_space_pauses_scan_and_updates_controls(self):
        screen = FakeScreen()
        app = self.make_app(screen)
        screen.key = " "
        app._keys(Mock())
        app._draw_scan()
        rendered = " ".join(text for _, text, _ in screen.writes)
        self.assertTrue(app.paused)
        self.assertIn("PAUSED", rendered)
        self.assertIn("[Space] resume", rendered)

    def test_input_drains_a_bounded_burst_of_keys(self):
        screen = FakeScreen()
        screen.get_wch = Mock(side_effect=[curses.KEY_DOWN] * (KEYS_PER_TICK + 1))
        app = self.make_app(screen)

        app._input(Mock())

        self.assertEqual(app.selected, KEYS_PER_TICK)
        self.assertEqual(screen.get_wch.call_count, KEYS_PER_TICK)

    def test_ctrl_c_character_stops_application(self):
        screen = FakeScreen()
        screen.key = "\x03"
        app = self.make_app(screen)

        self.assertTrue(app._keys(Mock()))

        self.assertFalse(app.running)

    def test_filter_is_edited_only_after_f_and_enter_commits_it(self):
        screen = FakeScreen()
        app = self.make_app(screen)
        monitor = Mock()
        for character in "FMy WiFi Q\n":
            screen.key = character
            app._keys(monitor)
        self.assertEqual(app.filter, "My WiFi Q")
        self.assertFalse(app.filter_editing)
        self.assertTrue(app.running)
        monitor.set_frequency.assert_not_called()

    def test_filter_field_is_highlighted_while_editing(self):
        screen = FakeScreen()
        app = self.make_app(screen)
        screen.key = "f"
        app._keys(Mock())
        app._draw_scan()
        fields = [
            text
            for row, text, attr in screen.writes
            if row == 0 and attr & curses.A_REVERSE
        ]
        self.assertEqual(fields, [" _ "])

    def test_pause_discards_events_and_freezes_visible_order(self):
        screen = FakeScreen()
        app = self.make_app(screen)
        now = time.monotonic()
        first = AccessPoint("01", "first", -40, 1, 2412, last_seen=now)
        second = AccessPoint("02", "second", -50, 1, 2412, last_seen=now)
        app.aps = {first.bssid: first, second.bssid: second}
        screen.key = " "
        with patch("fox80211.tui.time.monotonic", return_value=now):
            app._keys(Mock())
        capture = Mock(events=queue.Queue())
        capture.events.put((second.bssid, second.ssid, -10, 1, 2412))
        app._events(capture, apply=not app.paused)
        with patch("fox80211.tui.time.monotonic", return_value=now + 20):
            self.assertEqual([ap.bssid for ap in app._visible()], ["01", "02"])
        self.assertEqual(second.rssi, -50)
        self.assertTrue(capture.events.empty())

    def test_starting_hunt_from_paused_scan_resumes_capture_updates(self):
        screen = FakeScreen()
        app = self.make_app(screen)
        target = AccessPoint("AA", "Office", -40, 124, 5620)
        app.aps[target.bssid] = target
        app.paused = True
        app.paused_at = time.monotonic()
        screen.key = "\n"

        app._keys(Mock())

        self.assertIs(app.hunt, target)
        self.assertFalse(app.paused)
        self.assertIsNone(app.paused_at)

        capture = Mock(events=queue.Queue())
        capture.events.put(
            (target.bssid, target.ssid, -25, target.channel, target.frequency)
        )
        app._events(capture, apply=not app.paused)
        self.assertEqual(target.rssi, -25)

    @patch("fox80211.sound.curses.beep")
    @patch("fox80211.tui.curses.color_pair", return_value=0)
    def test_stale_hunt_does_not_beep(self, _color_pair, beep):
        app = self.make_app()
        ap = AccessPoint(
            "AA", "Office", -35, 1, 2412, last_seen=time.monotonic() - 3, average=-35
        )
        app.beep = True
        app._draw_hunt(ap)
        beep.assert_not_called()

    def test_unicode_filter_input(self):
        screen = FakeScreen()
        app = self.make_app(screen)
        screen.key = "f"
        app._keys(Mock())
        screen.key = "ї"
        app._keys(Mock())
        self.assertEqual(app.filter, "ї")

    def test_string_backspace_edits_filter(self):
        screen = FakeScreen()
        app = self.make_app(screen)
        for backspace in ("\x7f", "\b"):
            app.filter = "test"
            app.filter_editing = True
            screen.key = backspace
            app._keys(Mock())
            self.assertEqual(app.filter, "tes")

    def test_old_access_points_keep_signal_order_and_expire(self):
        app = self.make_app()
        now = time.monotonic()
        app.aps["live"] = AccessPoint("live", "live", -70, 1, 2412, last_seen=now)
        app.aps["old"] = AccessPoint("old", "old", -20, 1, 2412, last_seen=now - 61)
        self.assertEqual([ap.bssid for ap in app._visible()], ["old", "live"])
        app.aps["remembered"] = AccessPoint(
            "remembered", "remembered", -10, 1, 2412, last_seen=now - 60
        )
        app.aps["dead"] = AccessPoint(
            "dead", "dead", -10, 1, 2412, last_seen=now - EXPIRE_AFTER - 1
        )
        app._events(Mock(events=queue.Queue()))
        self.assertIn("remembered", app.aps)
        self.assertNotIn("dead", app.aps)

    def test_scan_marks_network_not_seen_for_a_minute(self):
        screen = FakeScreen()
        app = self.make_app(screen)
        now = time.monotonic()
        app.aps["00:11:22:33:44:55"] = AccessPoint(
            "00:11:22:33:44:55",
            "Office",
            -50,
            100,
            5500,
            last_seen=now - 61,
        )

        with patch("fox80211.tui.time.monotonic", return_value=now):
            app._draw_scan()

        row, attributes = next(
            (text, attributes)
            for index, text, attributes in screen.writes
            if index == 3
        )
        self.assertIn("?  1m01", row)
        self.assertTrue(attributes & curses.A_DIM)
        controls = next(
            text for index, text, _ in screen.writes if index == screen.height - 1
        )
        self.assertIn("dim=unseen 1m+", controls)

    def test_number_keys_toggle_band_filters(self):
        screen = FakeScreen()
        app = self.make_app(screen)
        for band, frequency in ((2, 2412), (5, 5500), (6, 6115)):
            bssid = str(band)
            app.aps[bssid] = AccessPoint(bssid, f"{band} GHz", -50, 1, frequency)
        app.aps["unknown"] = AccessPoint("unknown", "unknown", -50, 1, None)

        screen.key = "5"
        app._keys(Mock())

        self.assertEqual(
            {ap.bssid for ap in app._visible()}, {"2", "6", "unknown"}
        )
        app._draw_scan()
        controls = next(
            text for row, text, _ in screen.writes if row == screen.height - 1
        )
        self.assertIn("2:on 5:off 6:on", controls)

    def test_disabled_band_is_skipped_by_channel_hopper(self):
        screen = FakeScreen()
        app = self.make_app(screen)
        screen.key = "5"
        app._keys(Mock())
        monitor = Mock()
        app.stop_event.wait = Mock(
            side_effect=lambda _timeout: app.stop_event.set()
        )

        app._hop(monitor, [(5500, 100), (2412, 1)])

        monitor.set_frequency.assert_called_once_with(2412)

    def test_band_toggle_waits_for_in_progress_channel_tune(self):
        screen = FakeScreen()
        app = self.make_app(screen)
        screen.key = "5"
        key_read = threading.Event()
        original_get_wch = screen.get_wch

        def get_wch():
            key_read.set()
            return original_get_wch()

        screen.get_wch = get_wch
        app.tune_lock.acquire()
        toggle = threading.Thread(target=app._keys, args=(Mock(),))
        try:
            toggle.start()
            self.assertTrue(key_read.wait(1))
            self.assertIn(5, app.enabled_bands)
        finally:
            app.tune_lock.release()
            toggle.join(timeout=1)

        self.assertFalse(toggle.is_alive())
        self.assertNotIn(5, app.enabled_bands)

    def test_hopper_waits_without_tuning_when_all_bands_are_disabled(self):
        app = self.make_app()
        app.enabled_bands.clear()
        monitor = Mock()
        app.stop_event.wait = Mock(
            side_effect=lambda _timeout: app.stop_event.set()
        )

        app._hop(monitor, [(2412, 1), (5500, 100), (6115, 33)])

        monitor.set_frequency.assert_not_called()
        app.stop_event.wait.assert_called_once_with(0.1)

    def test_scan_reset_key_clears_discovered_networks(self):
        screen = FakeScreen()
        app = self.make_app(screen)
        app.aps["AA"] = AccessPoint("AA", "Office", -50, 1, 2412)
        app.selected = 3
        screen.key = "r"

        app._keys(Mock())

        self.assertEqual(app.aps, {})
        self.assertEqual(app.selected, 0)

    def test_scan_reset_discards_observations_already_in_capture_queue(self):
        screen = FakeScreen()
        app = self.make_app(screen)
        capture = Mock(events=queue.Queue())
        capture.events.put(("old", "Old AP", -50, 1, 2412))
        screen.key = "r"

        app._keys(Mock())
        app._events(capture)

        self.assertEqual(app.aps, {})
        self.assertTrue(capture.events.empty())
        self.assertFalse(app.clear_scan_requested)

    def test_network_band_uses_frequency_boundaries(self):
        self.assertEqual(network_band(2412), 2)
        self.assertEqual(network_band(5500), 5)
        self.assertEqual(network_band(5955), 6)
        self.assertIsNone(network_band(None))

    def test_signal_gradient_is_clamped_and_monotonic(self):
        levels = [
            signal_level(rssi, 16) for rssi in (-110, -90, -75, -60, -45, -25, -10)
        ]
        self.assertEqual(levels, sorted(levels))
        self.assertEqual(levels[0], 0)
        self.assertEqual(levels[-1], 15)

    def test_short_hunt_layout_does_not_write_outside_screen(self):
        app = self.make_app(FakeScreen(height=8, width=50))
        app._draw_hunt(AccessPoint("AA", "Office", -50, 1, 2412))

    @patch("fox80211.tui.curses.color_pair", return_value=0)
    def test_hunt_controls_are_clipped_to_terminal_width(self, _color_pair):
        screen = FakeScreen(height=15, width=50)
        app = self.make_app(screen)
        app._draw_hunt(AccessPoint("AA", "Office", -50, 1, 2412))
        controls = [text for row, text, _ in screen.writes if row == 14]
        self.assertEqual(len(controls), 1)
        self.assertLessEqual(len(controls[0]), 47)

    @patch("fox80211.tui.curses.color_pair", return_value=0)
    def test_hunt_bar_uses_available_terminal_width(self, _color_pair):
        screen = FakeScreen(height=15, width=160)
        app = self.make_app(screen)
        app._draw_hunt(AccessPoint("AA", "Office", -50, 1, 2412))
        bar_segments = [text for row, text, _ in screen.writes if row == 7]
        self.assertEqual(sum(map(len, bar_segments)), 156)

    def test_expiry_covers_complete_channel_sweep(self):
        self.assertGreaterEqual(scan_expiry(100), (HOP_DWELL + HOP_TUNE_BUDGET) * 100)

    def test_expiry_adapts_to_measured_sweep(self):
        self.assertEqual(scan_expiry(1, EXPIRE_AFTER), EXPIRE_AFTER * 1.2)

    def test_tune_statistics_tracks_latest_and_ewma(self):
        statistics = TuneStatistics()
        statistics.record(0.020)
        statistics.record(0.100)
        self.assertEqual(statistics.latest, 0.100)
        self.assertAlmostEqual(statistics.ewma, 0.040)
        self.assertEqual(statistics.samples, 2)

    def test_diagnostics_shows_timing_capture_and_rejections(self):
        screen = FakeScreen()
        app = self.make_app(screen)
        app.tune_statistics.record(0.028)
        app.tune_statistics.last_sweep = 19.3
        app.channel_by_frequency[5620] = 124
        app.rejected_frequencies[5620] = "Operation not permitted (-1)"
        app.capture_statistics = Mock(
            frames_parsed=100,
            frames_with_rssi=97,
            frames_without_rssi=2,
            parse_errors=1,
        )

        app._draw_diagnostics()

        rendered = " ".join(text for _, text, _ in screen.writes)
        self.assertIn("latest 28.0 ms", rendered)
        self.assertIn("Last complete sweep: 19.30 s", rendered)
        self.assertIn("without RSSI 2", rendered)
        self.assertIn("5620 MHz / ch 124: Operation not permitted (-1)", rendered)

    def test_capture_counts_frames_without_rssi(self):
        capture = TsharkCapture("mon0")
        capture.fields = capture.FIELDS
        capture.process = Mock(
            stdout=io.StringIO(
                '"AA:BB:CC:DD:EE:FF"\t"Office"\t""\t"1"\t"2412"\n'
            )
        )

        capture._read()

        self.assertEqual(capture.frames_parsed, 1)
        self.assertEqual(capture.frames_with_rssi, 0)
        self.assertEqual(capture.frames_without_rssi, 1)
        self.assertTrue(capture.events.empty())
        capture.stderr.close()

    def test_malformed_rssi_is_only_a_parse_error(self):
        capture = TsharkCapture("mon0")
        capture.fields = capture.FIELDS
        capture.process = Mock(
            stdout=io.StringIO(
                '"AA:BB:CC:DD:EE:FF"\t"Office"\t"invalid"\t"1"\t"2412"\n'
            )
        )

        capture._read()

        self.assertEqual(capture.frames_parsed, 0)
        self.assertEqual(capture.parse_errors, 1)
        capture.stderr.close()

    def test_scan_status_keeps_timing_on_an_eighty_column_row(self):
        status = scan_status(50, 47, 3, 124, 5620, 0.028, 19.3, 79)
        self.assertLessEqual(len(status), 79)
        self.assertIn("tune 28ms", status)
        self.assertIn("sweep 19.3s", status)

    def test_short_diagnostics_layout_stays_inside_terminal(self):
        screen = FakeScreen(height=4, width=40)
        app = self.make_app(screen)

        app._draw_diagnostics()

        self.assertTrue(all(row < screen.height for row, _, _ in screen.writes))
        self.assertIn(
            "Resize to at least 7 rows",
            " ".join(text for _, text, _ in screen.writes),
        )

    def test_diagnostics_scrolls_to_all_rejected_frequencies(self):
        screen = FakeScreen(height=9)
        app = self.make_app(screen)
        for index in range(8):
            app.rejected_frequencies[5000 + index * 5] = f"failure {index}"
        app.diagnostics_selected = 7

        app._draw_diagnostics()

        rendered = " ".join(text for _, text, _ in screen.writes)
        self.assertIn("failure 7", rendered)
        self.assertNotIn("failure 0", rendered)

    def test_capture_counters_survive_capture_replacement(self):
        app = self.make_app()
        previous = Mock(
            frames_parsed=10,
            frames_with_rssi=8,
            frames_without_rssi=1,
            parse_errors=1,
        )
        current = Mock(
            frames_parsed=4,
            frames_with_rssi=3,
            frames_without_rssi=1,
            parse_errors=0,
        )
        app._accumulate_capture(previous)
        app.capture_statistics = current

        app._draw_diagnostics()

        rendered = " ".join(text for _, text, _ in app.screen.writes)
        self.assertIn("parsed 14", rendered)
        self.assertIn("with RSSI 11", rendered)
        self.assertIn("without RSSI 2", rendered)
        self.assertIn("parse errors 1", rendered)

    def test_failed_frequency_is_removed_from_usable_set(self):
        app = self.make_app()
        app.usable_frequencies.add(2412)
        app.stop_event.wait = Mock(side_effect=lambda _timeout: app.stop_event.set())
        monitor = Mock()
        monitor.set_frequency.side_effect = RuntimeError("tune failed")
        app._hop(monitor, [(2412, 1)])
        self.assertNotIn(2412, app.usable_frequencies)
        self.assertEqual(app.rejected_frequencies[2412], "tune failed")

    @patch("fox80211.tui.curses.color_pair", return_value=0)
    def test_stale_hunt_displays_signal_lost(self, _color_pair):
        screen = FakeScreen()
        app = self.make_app(screen)
        app._draw_hunt(
            AccessPoint("AA", "Office", -31, 124, 5620, last_seen=time.monotonic() - 6)
        )
        rendered = " ".join(text for _, text, _ in screen.writes)
        self.assertIn("SIGNAL LOST", rendered)
        self.assertIn("-- dBm", rendered)
        self.assertNotIn("VERY CLOSE", rendered)

    @patch("fox80211.tui.curses.color_pair", return_value=0)
    def test_five_ghz_hunt_tolerates_short_frame_gap(self, _color_pair):
        screen = FakeScreen()
        app = self.make_app(screen)
        app._draw_hunt(
            AccessPoint("AA", "Office", -31, 124, 5620, last_seen=time.monotonic() - 3)
        )
        rendered = " ".join(text for _, text, _ in screen.writes)
        self.assertNotIn("SIGNAL LOST", rendered)
        self.assertIn("VERY CLOSE", rendered)

    def test_failed_hunt_tune_returns_to_scan_with_error(self):
        screen = FakeScreen()
        screen.key = "\n"
        app = self.make_app(screen)
        app.aps["AA"] = AccessPoint("AA", "Office", -40, 124, 5620)
        monitor = Mock()
        monitor.set_frequency.side_effect = subprocess.CalledProcessError(
            1, ["iw"], stderr="Operation not permitted\n"
        )
        app._keys(monitor)
        app.stop_event.wait = Mock(side_effect=lambda _timeout: app.stop_event.set())
        app._hop(monitor, [(5620, 124)])
        self.assertIsNone(app.hunt)
        self.assertEqual(
            app.tune_error, "Unable to lock channel 124: Operation not permitted"
        )
        monitor.set_frequency.assert_called_once_with(5620)

    def test_busy_hunt_tune_is_retried(self):
        screen = FakeScreen()
        screen.key = "\n"
        app = self.make_app(screen)
        app.stop_event.wait = Mock(return_value=False)
        app.aps["AA"] = AccessPoint("AA", "Office", -40, 153, 5765)
        monitor = Mock()
        busy = subprocess.CalledProcessError(
            1, ["iw"], stderr="command failed: Device or resource busy (-16)\n"
        )
        monitor.set_frequency.side_effect = [busy, None]

        app._keys(monitor)
        waits = 0

        def wait(_timeout):
            nonlocal waits
            waits += 1
            if waits == 2:
                app.stop_event.set()

        app.stop_event.wait = Mock(side_effect=wait)
        app._hop(monitor, [(5765, 153)])

        self.assertIs(app.hunt, app.aps["AA"])
        self.assertIsNone(app.tune_error)
        self.assertEqual(app.current_frequency, 5765)
        self.assertEqual(monitor.set_frequency.call_count, 2)
        self.assertIn(
            0.1, [call.args[0] for call in app.stop_event.wait.call_args_list]
        )

    def test_hunt_does_not_retune_frequency_already_locked_by_hopper(self):
        screen = FakeScreen()
        screen.key = "\n"
        app = self.make_app(screen)
        app.aps["AA"] = AccessPoint("AA", "Office", -40, 1, 2412)
        app.current_frequency = 2412
        monitor = Mock()

        app._keys(monitor)

        self.assertIs(app.hunt, app.aps["AA"])
        self.assertTrue(app.locking_hunt)
        monitor.set_frequency.assert_not_called()

        app.stop_event.wait = Mock(side_effect=lambda _timeout: app.stop_event.set())
        app._hop(monitor, [(2412, 1)])

        self.assertFalse(app.locking_hunt)
        self.assertIsNone(app.tune_error)
        monitor.set_frequency.assert_not_called()

    def test_hunt_lock_retries_do_not_block_ui_thread(self):
        screen = FakeScreen()
        screen.key = "\n"
        app = self.make_app(screen)
        app.aps["AA"] = AccessPoint("AA", "Office", -40, 153, 5765)
        monitor = Mock()

        app._keys(monitor)

        self.assertIs(app.hunt, app.aps["AA"])
        self.assertTrue(app.locking_hunt)
        monitor.set_frequency.assert_not_called()

    @patch("fox80211.tui.curses.color_pair", return_value=0)
    def test_hunt_shows_locking_state_instead_of_stale_signal(self, _color_pair):
        screen = FakeScreen()
        app = self.make_app(screen)
        app.locking_hunt = True
        app._draw_hunt(
            AccessPoint("AA", "Office", -31, 153, 5765, last_seen=time.monotonic() - 3)
        )
        rendered = " ".join(text for _, text, _ in screen.writes)
        self.assertIn("LOCKING CHANNEL 153", rendered)
        self.assertNotIn("SIGNAL LOST", rendered)

    def test_persistent_busy_hunt_tune_reports_error_after_retries(self):
        screen = FakeScreen()
        screen.key = "\n"
        app = self.make_app(screen)
        app.stop_event.wait = Mock(return_value=False)
        app.aps["AA"] = AccessPoint("AA", "Office", -40, 153, 5765)
        monitor = Mock()
        monitor.set_frequency.side_effect = subprocess.CalledProcessError(
            1, ["iw"], stderr="command failed: Device or resource busy (-16)\n"
        )

        app._keys(monitor)
        waits = 0

        def wait(_timeout):
            nonlocal waits
            waits += 1
            if waits == LOCK_ATTEMPTS:
                app.stop_event.set()

        app.stop_event.wait = Mock(side_effect=wait)
        app._hop(monitor, [(5765, 153)])

        self.assertIsNone(app.hunt)
        self.assertIn("Device or resource busy", app.tune_error)
        self.assertEqual(monitor.set_frequency.call_count, LOCK_ATTEMPTS)

    def test_cancelled_hunt_aborts_busy_retries(self):
        app = self.make_app()
        target = AccessPoint("AA", "Office", -40, 153, 5765)
        app.hunt = target
        app.locking_hunt = True
        monitor = Mock()
        monitor.set_frequency.side_effect = subprocess.CalledProcessError(
            1, ["iw"], stderr="command failed: Device or resource busy (-16)\n"
        )
        app.stop_event.wait = Mock(
            side_effect=lambda _timeout: setattr(app, "hunt", None)
        )

        locked = app._lock_frequency(
            monitor, target.frequency, cancelled=lambda: app.hunt is not target
        )

        self.assertFalse(locked)
        self.assertIsNone(app.hunt)
        self.assertEqual(monitor.set_frequency.call_count, 1)

    def test_hunt_records_frequency_requested_before_target_update(self):
        app = self.make_app()
        target = AccessPoint("AA", "Office", -40, 1, 2412)
        app.hunt = target
        app.locking_hunt = True
        monitor = Mock()

        def tune(_frequency):
            target.update(-39, 6, 2437)

        monitor.set_frequency.side_effect = tune
        app.stop_event.wait = Mock(side_effect=lambda _timeout: app.stop_event.set())

        app._hop(monitor, [(2412, 1)])

        monitor.set_frequency.assert_called_once_with(2412)
        self.assertEqual(app.current_frequency, 2412)
        self.assertEqual(target.frequency, 2437)
        self.assertTrue(app.locking_hunt)

    def test_hunt_stays_locking_until_in_progress_scan_tune_finishes(self):
        screen = FakeScreen()
        screen.key = "\n"
        app = self.make_app(screen)
        target = AccessPoint("AA", "Office", -40, 1, 2412)
        app.aps[target.bssid] = target
        app.current_frequency = target.frequency

        app._keys(Mock())

        self.assertTrue(app.locking_hunt)

    def test_hunt_without_known_frequency_returns_to_scan_with_error(self):
        screen = FakeScreen()
        screen.key = "\n"
        app = self.make_app(screen)
        app.aps["AA"] = AccessPoint("AA", "Office", -40, 124, None)
        monitor = Mock()
        app._keys(monitor)
        self.assertIsNone(app.hunt)
        self.assertEqual(
            app.tune_error, "Unable to lock channel: AA has no known frequency yet"
        )
        monitor.set_frequency.assert_not_called()

    def test_capture_failure_is_reported(self):
        capture = TsharkCapture("mon0")
        capture.process = Mock(poll=Mock(return_value=2))
        capture.stderr.write("tshark: bad interface\n")
        with self.assertRaisesRegex(RuntimeError, "bad interface"):
            capture.raise_if_failed()
        capture.stderr.close()

    def test_capture_failure_preserves_multiline_diagnostic(self):
        capture = TsharkCapture("mon0")
        capture.process = Mock(poll=Mock(return_value=2))
        capture.stderr.write("tshark: mon0: Permission denied\n0 packets captured\n")
        with self.assertRaisesRegex(
            RuntimeError, "(?s)Permission denied.*0 packets captured"
        ):
            capture.raise_if_failed()
        capture.stderr.close()

    @patch("fox80211.capture.subprocess.run")
    def test_tshark_field_discovery_parses_field_abbreviations(self, run):
        _tshark_fields.cache_clear()
        run.return_value = Mock(
            returncode=0,
            stdout="F\tSSID\twlan.ssid\tFT_STRING\twlan\nF\tRaw SSID\twlan.ssid_raw\tFT_BYTES\twlan\n",
        )
        self.assertEqual(
            _tshark_fields(), {"wlan.ssid": "FT_STRING", "wlan.ssid_raw": "FT_BYTES"}
        )

    @patch("fox80211.capture.subprocess.run")
    def test_tshark_field_discovery_is_cached(self, run):
        _tshark_fields.cache_clear()
        run.return_value = Mock(
            returncode=0, stdout="F\tSSID\twlan.ssid\tFT_STRING\twlan\n"
        )
        self.assertEqual(_tshark_fields(), _tshark_fields())
        run.assert_called_once()

    @patch("fox80211.capture.subprocess.Popen")
    @patch("fox80211.capture._tshark_fields", return_value={"wlan.ssid": "FT_STRING"})
    def test_capture_omits_raw_ssid_when_tshark_does_not_support_it(
        self, _fields, popen
    ):
        process = popen.return_value
        process.stdout = iter(())
        capture = TsharkCapture("mon0")
        capture.start()
        capture.reader.join(timeout=1)
        command = popen.call_args.args[0]
        self.assertNotIn("wlan.ssid_raw", command)
        capture.stderr.close()

    @patch("fox80211.capture.subprocess.Popen")
    @patch(
        "fox80211.capture._tshark_fields", return_value={"wlan.ssid_raw": "FT_BYTES"}
    )
    def test_capture_uses_raw_ssid_when_tshark_supports_it(self, _fields, popen):
        process = popen.return_value
        process.stdout = iter(())
        capture = TsharkCapture("mon0")
        capture.start()
        capture.reader.join(timeout=1)
        command = popen.call_args.args[0]
        self.assertIn("wlan.ssid_raw", command)
        capture.stderr.close()

    @patch("fox80211.capture.subprocess.Popen")
    @patch("fox80211.capture._tshark_fields", return_value={"wlan.ssid": "FT_STRING"})
    def test_hunt_capture_includes_all_target_bssid_frames(self, _fields, popen):
        process = popen.return_value
        process.stdout = iter(())
        capture = TsharkCapture("mon0", "00:11:22:33:44:55")
        capture.start()
        capture.reader.join(timeout=1)
        command = popen.call_args.args[0]
        display_filter = command[command.index("-Y") + 1]
        self.assertIn("wlan.fc.type_subtype == 8", display_filter)
        self.assertIn("wlan.ta == 00:11:22:33:44:55", display_filter)
        self.assertNotIn("wlan.bssid == 00:11:22:33:44:55", display_filter)
        capture.stderr.close()

    def test_hunt_capture_rejects_unsafe_bssid_filter(self):
        with self.assertRaisesRegex(ValueError, "invalid BSSID"):
            TsharkCapture("mon0", "00:11:22:33:44:55 || frame")

    @patch("fox80211.capture.time.monotonic", side_effect=[10.0, 10.01, 10.06])
    def test_hunt_capture_rate_limits_target_updates(self, _monotonic):
        capture = TsharkCapture("mon0", "00:11:22:33:44:55")
        event = ("00:11:22:33:44:55", "Office", -50, 100, 5500)

        capture._emit(event)
        capture._emit(event)
        capture._emit(event)

        self.assertEqual(capture.events.qsize(), 2)
        capture.stderr.close()

    def test_capture_queue_drops_oldest_event_when_full(self):
        capture = TsharkCapture("mon0")
        for index in range(EVENT_QUEUE_SIZE + 1):
            capture._emit((str(index), "Office", index, 1, 2412))

        self.assertEqual(capture.events.qsize(), EVENT_QUEUE_SIZE)
        self.assertEqual(capture.events.get_nowait()[2], 1)
        capture.stderr.close()

    @patch("fox80211.tui.TsharkCapture")
    def test_capture_filter_switch_starts_replacement_before_stopping_scan(
        self, capture_class
    ):
        order = []
        current = Mock()
        current.stop.side_effect = lambda: order.append("old stop")
        replacement = capture_class.return_value
        replacement.start.side_effect = lambda: order.append("new start")

        result = Application._replace_capture(current, "mon0", "00:11:22:33:44:55")

        self.assertIs(result, replacement)
        self.assertEqual(order, ["new start", "old stop"])
        capture_class.assert_called_once_with("mon0", "00:11:22:33:44:55")

    @patch("fox80211.tui.TsharkCapture")
    def test_failed_capture_filter_switch_keeps_current_capture(self, capture_class):
        current = Mock()
        replacement = capture_class.return_value
        replacement.start.side_effect = OSError("tshark failed")

        with self.assertRaisesRegex(OSError, "tshark failed"):
            Application._replace_capture(current, "mon0", "00:11:22:33:44:55")

        current.stop.assert_not_called()
        replacement.stop.assert_called_once_with()

    @patch("fox80211.system.run")
    def test_association_is_unknown_when_iw_fails(self, run):
        run.side_effect = subprocess.CalledProcessError(1, ["iw"])
        self.assertIsNone(_interface_associated("wlan0"))

    @patch("fox80211.system.run")
    def test_non_managed_interface_never_uses_station_link_as_safety_signal(self, run):
        self.assertIsNone(_interface_associated("wlan0", "AP"))
        run.assert_not_called()

    @patch("fox80211.system.subprocess.run")
    def test_commands_use_stable_c_locale(self, subprocess_run):
        subprocess_run.return_value.stdout = ""
        from fox80211.system import run

        run("nmcli", "device")
        self.assertEqual(subprocess_run.call_args.kwargs["env"]["LC_ALL"], "C")

    @patch("fox80211.cli.signal.signal")
    def test_terminal_close_and_termination_use_cleanup_path(self, signal_handler):
        _install_signal_handlers()

        self.assertEqual(
            [item.args[0] for item in signal_handler.call_args_list],
            [signal.SIGHUP, signal.SIGTERM],
        )
        for item in signal_handler.call_args_list:
            with self.assertRaises(KeyboardInterrupt):
                item.args[1](item.args[0], None)

    @patch("fox80211.system.Path.exists")
    @patch("fox80211.system.run")
    def test_only_dead_app_monitor_interfaces_are_removed(self, run, exists):
        run.return_value = """\
phy#1
\tInterface whmon123
\t\ttype monitor
\tInterface whmon456
\t\ttype monitor
\tInterface monitor0
\t\ttype monitor
\tInterface whmon789
\t\ttype managed
"""
        exists.side_effect = [False, True]

        self.assertEqual(cleanup_orphan_monitors(), ["whmon123"])
        self.assertIn(
            call("iw", "dev", "whmon123", "del", check=False), run.call_args_list
        )
        self.assertNotIn(
            call("iw", "dev", "whmon456", "del", check=False), run.call_args_list
        )

    @patch("fox80211.system._monitor_phys", return_value={"phy1"})
    @patch("fox80211.system._interface_associated", return_value=False)
    @patch("fox80211.system.run")
    def test_app_monitor_vif_is_not_presented_as_adapter(
        self, run, _associated, _monitor_phys
    ):
        run.return_value = """\
phy#1
\tInterface whmon123
\t\ttype monitor
\tInterface wlan1
\t\ttype managed
"""

        adapters = discover_adapters()

        self.assertEqual([adapter.interface for adapter in adapters], ["wlan1"])

    @patch("fox80211.system.os.getpid", return_value=123456)
    def test_monitor_name_contains_complete_owner_pid(self, _getpid):
        monitor = MonitorInterface(Adapter("wlan1", "phy1"))

        self.assertEqual(monitor.name, "whmon123456")

    @patch("fox80211.system.run")
    def test_available_frequencies_accepts_decimal_iw_output(self, run):
        run.return_value = """\
Band 1:
\tFrequencies:
\t\t* 2412.0 MHz [1] (20.0 dBm)
\t\t* 2437.0 MHz [6] (disabled)
\t\t* 2462 MHz [11] (20.0 dBm)
"""

        self.assertEqual(available_frequencies("phy1"), [(2412, 1), (2462, 11)])
        run.assert_called_once_with("iw", "phy", "phy1", "info")

    @patch("fox80211.system.run", return_value="yes\n")
    def test_networkmanager_status_uses_current_field_name(self, run):
        monitor = MonitorInterface(Adapter("wlan1", "phy1"))

        self.assertTrue(monitor._nm_managed("wlan1"))
        run.assert_called_once_with(
            "nmcli", "-g", "GENERAL.NM-MANAGED", "device", "show", "wlan1"
        )

    @patch("fox80211.system.run")
    def test_networkmanager_status_falls_back_to_legacy_field_name(self, run):
        modern = subprocess.CalledProcessError(2, ["nmcli", "-g", "GENERAL.NM-MANAGED"])
        run.side_effect = [modern, "no\n"]
        monitor = MonitorInterface(Adapter("wlan1", "phy1"))

        self.assertFalse(monitor._nm_managed("wlan1"))
        self.assertEqual(
            run.call_args_list,
            [
                call(
                    "nmcli",
                    "-g",
                    "GENERAL.NM-MANAGED",
                    "device",
                    "show",
                    "wlan1",
                ),
                call(
                    "nmcli",
                    "-g",
                    "GENERAL.MANAGED",
                    "device",
                    "show",
                    "wlan1",
                ),
            ],
        )

    @patch("fox80211.system._link_is_up", return_value=True)
    @patch("fox80211.system.run")
    def test_partial_monitor_setup_is_restored(self, run, _link_is_up):
        calls = []

        def command(*args, check=True):
            calls.append(args)
            if args[:4] == ("iw", "phy", "phy1", "interface"):
                raise subprocess.CalledProcessError(1, args)
            if args[:4] == ("nmcli", "-g", "GENERAL.NM-MANAGED", "device"):
                return "yes\n"
            if args[:6] == ("iw", "dev", "wlan1", "set", "type", "monitor"):
                raise subprocess.CalledProcessError(1, args)
            return ""

        run.side_effect = command
        monitor = MonitorInterface(
            Adapter("wlan1", "phy1", mode="managed", connection_known=True)
        )
        with self.assertRaises(subprocess.CalledProcessError):
            monitor.__enter__()
        self.assertIn(("iw", "dev", "wlan1", "set", "type", "managed"), calls)
        self.assertIn(("ip", "link", "set", "wlan1", "up"), calls)
        self.assertIn(("nmcli", "device", "set", "wlan1", "managed", "yes"), calls)

    @patch("fox80211.system._link_is_up", return_value=False)
    @patch("fox80211.system.run")
    def test_down_unmanaged_interface_stays_down_and_unmanaged(self, run, _link_is_up):
        calls = []

        def command(*args, check=True):
            calls.append(args)
            if args[:4] == ("iw", "phy", "phy1", "interface"):
                raise subprocess.CalledProcessError(1, args)
            if args[:4] == ("nmcli", "-g", "GENERAL.NM-MANAGED", "device"):
                return "no\n"
            return ""

        run.side_effect = command
        monitor = MonitorInterface(
            Adapter("wlan1", "phy1", mode="managed", connection_known=True)
        )
        with monitor:
            pass
        restore_type = calls.index(("iw", "dev", "wlan1", "set", "type", "managed"))
        self.assertNotIn(("ip", "link", "set", "wlan1", "up"), calls[restore_type:])
        self.assertFalse(any(call[:3] == ("nmcli", "device", "set") for call in calls))

    @patch("fox80211.system._link_is_up", return_value=True)
    @patch("fox80211.system.run")
    def test_separate_vif_isolates_and_restores_original_interface(
        self, run, _link_is_up
    ):
        calls = []

        def command(*args, check=True):
            calls.append(args)
            if args[:4] == ("nmcli", "-g", "GENERAL.NM-MANAGED", "device"):
                return "yes\n"
            return ""

        run.side_effect = command
        with MonitorInterface(Adapter("wlan1", "phy1")) as monitor:
            name = monitor.name
        self.assertLess(
            calls.index(("nmcli", "device", "set", "wlan1", "managed", "no")),
            calls.index(
                ("iw", "phy", "phy1", "interface", "add", name, "type", "monitor")
            ),
        )
        self.assertIn(("ip", "link", "set", "wlan1", "down"), calls)
        self.assertIn(("ip", "link", "set", "wlan1", "up"), calls)
        self.assertIn(("nmcli", "device", "set", "wlan1", "managed", "yes"), calls)


if __name__ == "__main__":
    unittest.main()
