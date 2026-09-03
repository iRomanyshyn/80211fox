import time
import unittest

from fox80211.capture import _ssid, extract_channel_switch
from fox80211.dfs import DfsEvent, DfsKind, EventHistory, ChannelSwitch, parse_iw_event
from fox80211.model import AccessPoint
from fox80211.system import parse_channels
from fox80211.tui import hunt_notification, proximity, scan_layout, scan_row


class DfsTests(unittest.TestCase):
    def test_missing_ssid_marker(self):
        self.assertEqual(_ssid(""), "<MISSING>")

    def test_channel_metadata(self):
        text = """
        * 5620 MHz [124] (22.0 dBm) (radar detection) (no IR), DFS state: unavailable (for 100 sec), CAC time: 60000 ms
        * 5745.0 MHz [149] (disabled)
        """
        channels = parse_channels(text)
        self.assertTrue(channels[0].radar)
        self.assertTrue(channels[0].no_ir)
        self.assertEqual(channels[0].dfs_state, "UNAVAILABLE")
        self.assertEqual(channels[0].cac_ms, 60000)
        self.assertTrue(channels[1].disabled)

    def test_radar_cac_nop_and_malformed_events(self):
        self.assertEqual(parse_iw_event("phy1 radar detected freq=5620", 1).kind, DfsKind.RADAR)
        self.assertEqual(parse_iw_event("phy1 CAC started, frequency: 5600", 1).kind, DfsKind.CAC_STARTED)
        self.assertEqual(parse_iw_event("phy1 NOP finished freq 5620", 1).kind, DfsKind.NOP_FINISHED)
        self.assertIsNone(parse_iw_event("unrelated malformed output"))

    def test_csa_is_not_radar_and_dfs_move(self):
        event = extract_channel_switch({"wlan_mgt.tag.csa.new_channel": "36"}, "aa:bb", 124, 2)
        self.assertEqual(event.target_channel, 36)
        self.assertEqual(event.label, "CSA")
        move = ChannelSwitch(2, "AA", 124, 36, from_dfs=True)
        self.assertEqual(move.label, "DFS MOVE")
        self.assertNotIn("RADAR DETECTED", hunt_notification(move, 124, 0)[1])

    def test_correlation_and_bounded_history(self):
        history = EventHistory(2)
        history.add(DfsEvent(DfsKind.RADAR, 1, 5620, 124))
        self.assertTrue(history.radar_for(5620, 5))
        history.add(DfsEvent(DfsKind.CAC_STARTED, 2))
        history.add(DfsEvent(DfsKind.NOP_FINISHED, 3))
        self.assertEqual(len(history.items), 2)
        self.assertFalse(history.radar_for(5620, 5))

    def test_signal_thresholds(self):
        self.assertEqual(proximity(-90)[0], "VERY FAR / HEAVILY OBSTRUCTED")
        self.assertEqual(proximity(-75)[0], "FAR OR OBSTRUCTED")
        self.assertEqual(proximity(-40)[0], "VERY CLOSE")

    def test_responsive_layout_lines_fit_and_event_survives(self):
        ap = AccessPoint("AA:BB:CC:DD:EE:FF", "A very long network name", -50, 124, 5620)
        ap.event_label, ap.event_target = "MOVE", 36
        for width in (35, 55, 80, 120, 180):
            layout = scan_layout(width)
            row = scan_row(ap, 0.2, layout, True)
            self.assertLessEqual(len(row), width - 1)
            self.assertIn("MOVE", row)
        self.assertFalse(scan_layout(80).frequency)
        self.assertTrue(scan_layout(120).signal)

    def test_hunt_notification_expires(self):
        notice = hunt_notification(DfsEvent(DfsKind.RADAR, 1, 5620, 124), 124, now=10)
        self.assertEqual(notice[0], 22)
        self.assertEqual(notice[1], "RADAR DETECTED")


if __name__ == "__main__":
    unittest.main()
