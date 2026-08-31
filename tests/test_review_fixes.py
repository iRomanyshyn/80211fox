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
            screen.key = ord(character)
            app._keys(monitor)
        self.assertEqual(app.filter, "jk")

    @patch("fox80211.tui.curses.beep")
    @patch("fox80211.tui.curses.color_pair", return_value=0)
    def test_stale_hunt_does_not_beep(self, _color_pair, beep):
        app = self.make_app()
        ap = AccessPoint("AA", "Office", -35, 1, 2412, last_seen=time.monotonic() - 3, average=-35)
        app.beep = True
        app._draw_hunt(ap)
        beep.assert_not_called()

    def test_short_hunt_layout_does_not_write_outside_screen(self):
        app = self.make_app(FakeScreen(height=8, width=50))
        app._draw_hunt(AccessPoint("AA", "Office", -50, 1, 2412))

    def test_capture_failure_is_reported(self):
        capture = TsharkCapture("mon0")
        capture.process = Mock(poll=Mock(return_value=2))
        capture.stderr.write("tshark: bad interface\n")
        with self.assertRaisesRegex(RuntimeError, "bad interface"):
            capture.raise_if_failed()
        capture.stderr.close()

    @patch("fox80211.system.run")
    def test_association_is_unknown_when_iw_fails(self, run):
        run.side_effect = subprocess.CalledProcessError(1, ["iw"])
        self.assertIsNone(_interface_associated("wlan0"))

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


if __name__ == "__main__":
    unittest.main()
