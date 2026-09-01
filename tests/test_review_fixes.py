import curses
import queue
import subprocess
import time
import unittest
from unittest.mock import Mock, patch

from fox80211.capture import TsharkCapture, _ssid, _tshark_fields
from fox80211.model import AccessPoint, Adapter
from fox80211.system import MonitorInterface, _interface_associated, available_frequencies
from fox80211.tui import HOP_DWELL, HOP_TUNE_BUDGET, Application, scan_expiry


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
        self.assertEqual(_ssid("4176656e676120436f72706f", "4176656e676120436f72706f"), "Avenga Corpo")
        self.assertEqual(_ssid("D0A2D0B5D181D182", "d0:a2:d0:b5:d1:81:d1:82"), "Тест")

    def test_hexadecimal_ssid_is_decoded_when_display_field_is_bytes(self):
        self.assertEqual(_ssid("4142", value_is_bytes=True), "AB")
        self.assertEqual(_ssid("31323334", value_is_bytes=True), "1234")
        self.assertEqual(_ssid("4578616d706c6553534944", value_is_bytes=True), "ExampleSSID")

    def test_ambiguous_hexadecimal_text_ssids_are_preserved(self):
        self.assertEqual(_ssid("Cafe"), "Cafe")
        self.assertEqual(_ssid("1234"), "1234")
        self.assertEqual(_ssid("0000"), "0000")

    def test_hidden_and_plain_text_ssids_are_preserved(self):
        self.assertEqual(_ssid(""), "<hidden>")
        self.assertEqual(_ssid("Office Wi-Fi", "4f66666963652057692d4669"), "Office Wi-Fi")

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
        self.assertEqual(_ssid("unhelpful", "53796e74686574696353534944"), "SyntheticSSID")

    def test_null_filled_ssids_are_hidden(self):
        self.assertEqual(_ssid("0000", "0000"), "<hidden>")

    def test_hidden_beacon_does_not_replace_learned_ssid(self):
        app = self.make_app()
        app.aps["AA"] = AccessPoint("AA", "Office", -50, 1, 2412)
        capture = Mock(events=queue.Queue())
        capture.events.put(("AA", "<hidden>", -49, 1, 2412))
        app._events(capture)
        self.assertEqual(app.aps["AA"].ssid, "Office")

    def test_scan_viewport_keeps_selection_visible(self):
        screen = FakeScreen(height=8)
        app = self.make_app(screen)
        for index in range(10):
            bssid = f"00:00:00:00:00:{index:02X}"
            app.aps[bssid] = AccessPoint(bssid, str(index), -30 - index, 1, 2412)
        app.selected = 8
        app._draw_scan()
        highlighted = [text for _, text, attr in screen.writes if attr == curses.A_REVERSE]
        self.assertEqual(len(highlighted), 1)
        self.assertIn("00:00:00:00:00:08", highlighted[0])

    def test_scan_displays_ten_second_average_instead_of_latest_signal(self):
        screen = FakeScreen()
        app = self.make_app(screen)
        ap = AccessPoint("00:00:00:00:00:01", "Office", -70, 1, 2412)
        ap.signal_history.extend(((ap.last_seen, -50), (ap.last_seen, -30)))
        ap.rssi = -30
        app.aps[ap.bssid] = ap

        app._draw_scan()

        row = next(text for _, text, _ in screen.writes if ap.bssid in text)
        self.assertTrue(row.startswith(" -50"))

    def test_scan_reserves_last_row_for_controls(self):
        screen = FakeScreen(height=8)
        app = self.make_app(screen)
        for index in range(10):
            bssid = f"00:00:00:00:00:{index:02X}"
            app.aps[bssid] = AccessPoint(bssid, str(index), -30 - index, 1, 2412)
        app._draw_scan()
        access_point_rows = [row for row, text, _ in screen.writes if row >= 3 and "00:00:00:00:00:" in text]
        self.assertEqual(access_point_rows, list(range(3, screen.height - 1)))
        self.assertTrue(any(row == screen.height - 1 and "[Space] pause" in text and "[Q] quit" in text for row, text, _ in screen.writes))

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

    def test_j_and_k_are_available_to_filter(self):
        screen = FakeScreen()
        app = self.make_app(screen)
        monitor = Mock()
        for character in "jk":
            screen.key = character
            app._keys(monitor)
        self.assertEqual(app.filter, "jk")

    @patch("fox80211.sound.curses.beep")
    @patch("fox80211.tui.curses.color_pair", return_value=0)
    def test_stale_hunt_does_not_beep(self, _color_pair, beep):
        app = self.make_app()
        ap = AccessPoint("AA", "Office", -35, 1, 2412, last_seen=time.monotonic() - 3, average=-35)
        app.beep = True
        app._draw_hunt(ap)
        beep.assert_not_called()

    def test_unicode_filter_input(self):
        screen = FakeScreen()
        app = self.make_app(screen)
        screen.key = "ї"
        app._keys(Mock())
        self.assertEqual(app.filter, "ї")

    def test_string_backspace_edits_filter(self):
        screen = FakeScreen()
        app = self.make_app(screen)
        for backspace in ("\x7f", "\b"):
            app.filter = "test"
            screen.key = backspace
            app._keys(Mock())
            self.assertEqual(app.filter, "tes")

    def test_stale_access_points_sort_last_and_expire(self):
        app = self.make_app()
        now = time.monotonic()
        app.aps["live"] = AccessPoint("live", "live", -70, 1, 2412, last_seen=now)
        app.aps["stale"] = AccessPoint("stale", "stale", -20, 1, 2412, last_seen=now - 15)
        self.assertEqual([ap.bssid for ap in app._visible()], ["live", "stale"])
        app.aps["dead"] = AccessPoint("dead", "dead", -10, 1, 2412, last_seen=now - 31)
        app._events(Mock(events=queue.Queue()))
        self.assertNotIn("dead", app.aps)

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

    def test_expiry_covers_complete_channel_sweep(self):
        self.assertGreaterEqual(scan_expiry(100), (HOP_DWELL + HOP_TUNE_BUDGET) * 100)

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
        app._draw_hunt(AccessPoint("AA", "Office", -31, 124, 5620, last_seen=time.monotonic() - 3))
        rendered = " ".join(text for _, text, _ in screen.writes)
        self.assertIn("SIGNAL LOST", rendered)
        self.assertIn("-- dBm", rendered)
        self.assertNotIn("VERY CLOSE", rendered)

    def test_failed_hunt_tune_returns_to_scan_with_error(self):
        screen = FakeScreen()
        screen.key = "\n"
        app = self.make_app(screen)
        app.aps["AA"] = AccessPoint("AA", "Office", -40, 124, 5620)
        monitor = Mock()
        monitor.set_frequency.side_effect = subprocess.CalledProcessError(1, ["iw"], stderr="Operation not permitted\n")
        app._keys(monitor)
        self.assertIsNone(app.hunt)
        self.assertEqual(app.tune_error, "Unable to lock channel 124: Operation not permitted")
        monitor.set_frequency.assert_called_once_with(5620)

    def test_busy_hunt_tune_is_retried(self):
        screen = FakeScreen()
        screen.key = "\n"
        app = self.make_app(screen)
        app.stop_event.wait = Mock(return_value=False)
        app.aps["AA"] = AccessPoint("AA", "Office", -40, 153, 5765)
        monitor = Mock()
        busy = subprocess.CalledProcessError(1, ["iw"], stderr="command failed: Device or resource busy (-16)\n")
        monitor.set_frequency.side_effect = [busy, None]

        app._keys(monitor)

        self.assertIs(app.hunt, app.aps["AA"])
        self.assertIsNone(app.tune_error)
        self.assertEqual(app.current_frequency, 5765)
        self.assertEqual(monitor.set_frequency.call_count, 2)
        app.stop_event.wait.assert_called_once_with(0.1)

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

        self.assertIsNone(app.hunt)
        self.assertIn("Device or resource busy", app.tune_error)
        self.assertEqual(monitor.set_frequency.call_count, 3)

    def test_hunt_without_known_frequency_returns_to_scan_with_error(self):
        screen = FakeScreen()
        screen.key = "\n"
        app = self.make_app(screen)
        app.aps["AA"] = AccessPoint("AA", "Office", -40, 124, None)
        monitor = Mock()
        app._keys(monitor)
        self.assertIsNone(app.hunt)
        self.assertEqual(app.tune_error, "Unable to lock channel: AA has no known frequency yet")
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
        with self.assertRaisesRegex(RuntimeError, "(?s)Permission denied.*0 packets captured"):
            capture.raise_if_failed()
        capture.stderr.close()

    @patch("fox80211.capture.subprocess.run")
    def test_tshark_field_discovery_parses_field_abbreviations(self, run):
        _tshark_fields.cache_clear()
        run.return_value = Mock(
            returncode=0,
            stdout="F\tSSID\twlan.ssid\tFT_STRING\twlan\nF\tRaw SSID\twlan.ssid_raw\tFT_BYTES\twlan\n",
        )
        self.assertEqual(_tshark_fields(), {"wlan.ssid": "FT_STRING", "wlan.ssid_raw": "FT_BYTES"})

    @patch("fox80211.capture.subprocess.run")
    def test_tshark_field_discovery_is_cached(self, run):
        _tshark_fields.cache_clear()
        run.return_value = Mock(returncode=0, stdout="F\tSSID\twlan.ssid\tFT_STRING\twlan\n")
        self.assertEqual(_tshark_fields(), _tshark_fields())
        run.assert_called_once()

    @patch("fox80211.capture.subprocess.Popen")
    @patch("fox80211.capture._tshark_fields", return_value={"wlan.ssid": "FT_STRING"})
    def test_capture_omits_raw_ssid_when_tshark_does_not_support_it(self, _fields, popen):
        process = popen.return_value
        process.stdout = iter(())
        capture = TsharkCapture("mon0")
        capture.start()
        capture.reader.join(timeout=1)
        command = popen.call_args.args[0]
        self.assertNotIn("wlan.ssid_raw", command)
        capture.stderr.close()

    @patch("fox80211.capture.subprocess.Popen")
    @patch("fox80211.capture._tshark_fields", return_value={"wlan.ssid_raw": "FT_BYTES"})
    def test_capture_uses_raw_ssid_when_tshark_supports_it(self, _fields, popen):
        process = popen.return_value
        process.stdout = iter(())
        capture = TsharkCapture("mon0")
        capture.start()
        capture.reader.join(timeout=1)
        command = popen.call_args.args[0]
        self.assertIn("wlan.ssid_raw", command)
        capture.stderr.close()

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

    @patch("fox80211.system._link_is_up", return_value=True)
    @patch("fox80211.system.run")
    def test_partial_monitor_setup_is_restored(self, run, _link_is_up):
        calls = []

        def command(*args, check=True):
            calls.append(args)
            if args[:4] == ("iw", "phy", "phy1", "interface"):
                raise subprocess.CalledProcessError(1, args)
            if args[:4] == ("nmcli", "-g", "GENERAL.MANAGED", "device"):
                return "yes\n"
            if args[:6] == ("iw", "dev", "wlan1", "set", "type", "monitor"):
                raise subprocess.CalledProcessError(1, args)
            return ""

        run.side_effect = command
        monitor = MonitorInterface(Adapter("wlan1", "phy1", mode="managed", connection_known=True))
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
            if args[:4] == ("nmcli", "-g", "GENERAL.MANAGED", "device"):
                return "no\n"
            return ""

        run.side_effect = command
        monitor = MonitorInterface(Adapter("wlan1", "phy1", mode="managed", connection_known=True))
        with monitor:
            pass
        restore_type = calls.index(("iw", "dev", "wlan1", "set", "type", "managed"))
        self.assertNotIn(("ip", "link", "set", "wlan1", "up"), calls[restore_type:])
        self.assertFalse(any(call[:3] == ("nmcli", "device", "set") for call in calls))

    @patch("fox80211.system._link_is_up", return_value=True)
    @patch("fox80211.system.run")
    def test_separate_vif_isolates_and_restores_original_interface(self, run, _link_is_up):
        calls = []

        def command(*args, check=True):
            calls.append(args)
            if args[:4] == ("nmcli", "-g", "GENERAL.MANAGED", "device"):
                return "yes\n"
            return ""

        run.side_effect = command
        with MonitorInterface(Adapter("wlan1", "phy1")) as monitor:
            name = monitor.name
        self.assertLess(calls.index(("nmcli", "device", "set", "wlan1", "managed", "no")), calls.index(("iw", "phy", "phy1", "interface", "add", name, "type", "monitor")))
        self.assertIn(("ip", "link", "set", "wlan1", "down"), calls)
        self.assertIn(("ip", "link", "set", "wlan1", "up"), calls)
        self.assertIn(("nmcli", "device", "set", "wlan1", "managed", "yes"), calls)


if __name__ == "__main__":
    unittest.main()
