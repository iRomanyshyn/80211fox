import curses
import queue
import subprocess
import time
import unittest
from unittest.mock import Mock, patch

from fox80211.capture import TsharkCapture
from fox80211.model import AccessPoint, Adapter
from fox80211.system import MonitorInterface, _interface_associated
from fox80211.tui import Application


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
