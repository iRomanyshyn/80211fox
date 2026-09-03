import queue
import unittest
from unittest.mock import Mock

from fox80211.capture import CSA_FIELDS, _ssid, extract_channel_switch
from fox80211.dfs import (
    ChannelSwitch,
    DfsEvent,
    DfsEventMonitor,
    DfsKind,
    EventHistory,
    parse_iw_event,
)
from fox80211.model import AccessPoint, Adapter, Channel
from fox80211.system import parse_channels
from fox80211.tui import (
    Application,
    event_attr,
    hunt_notification,
    proximity,
    scan_layout,
    scan_row,
)


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
        self.assertEqual(
            parse_iw_event("phy1 radar detected freq=5620", 1).kind, DfsKind.RADAR
        )
        self.assertEqual(
            parse_iw_event("phy1 CAC started, frequency: 5600", 1).kind,
            DfsKind.CAC_STARTED,
        )
        self.assertEqual(
            parse_iw_event("phy1 NOP finished freq 5620", 1).kind, DfsKind.NOP_FINISHED
        )
        self.assertIsNone(parse_iw_event("unrelated malformed output"))

    def test_csa_is_not_radar_and_dfs_move(self):
        event = extract_channel_switch(
            {"wlan_mgt.tag.csa.new_channel": "36"}, "aa:bb", 124, 2
        )
        self.assertEqual(event.target_channel, 36)
        self.assertEqual(event.label, "CSA")
        move = ChannelSwitch(2, "AA", 124, 36, from_dfs=True)
        self.assertEqual(move.label, "DFS MOVE")
        self.assertNotIn("RADAR DETECTED", hunt_notification(move, 124, 0).title)

    def test_csa_count_and_operating_class_are_extracted(self):
        event = extract_channel_switch(
            {
                "wlan_mgt.tag.ext_csa.new_channel": "5",
                "wlan_mgt.tag.ext_csa.channel_switch_count": "3",
                "wlan_mgt.tag.ext_csa.new_reg_class": "131",
            },
            "AA:BB:CC:DD:EE:FF",
            1,
            2,
        )
        self.assertEqual(event.switch_count, 3)
        self.assertEqual(event.operating_class, 131)
        self.assertIn("wlan_mgt.tag.ext_csa.new_channel", CSA_FIELDS)

    def test_correlation_and_bounded_history(self):
        history = EventHistory(2)
        history.add(DfsEvent(DfsKind.RADAR, 1, 5620, 124))
        self.assertTrue(history.radar_for(5620, 5))
        history.add(DfsEvent(DfsKind.CAC_STARTED, 2))
        history.add(DfsEvent(DfsKind.NOP_FINISHED, 3))
        self.assertEqual(len(history.items), 2)
        self.assertFalse(history.radar_for(5620, 5))

    def test_future_radar_does_not_correlate_to_earlier_csa(self):
        history = EventHistory()
        history.add(DfsEvent(DfsKind.RADAR, 20, 5620, 124))
        self.assertFalse(history.radar_for(5620, 15))

    def test_signal_thresholds(self):
        self.assertEqual(proximity(-90)[0], "VERY FAR / HEAVILY OBSTRUCTED")
        self.assertEqual(proximity(-75)[0], "FAR OR OBSTRUCTED")
        self.assertEqual(proximity(-40)[0], "VERY CLOSE")

    def test_responsive_layout_lines_fit_and_event_survives(self):
        ap = AccessPoint(
            "AA:BB:CC:DD:EE:FF", "A very long network name", -50, 124, 5620
        )
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
        self.assertEqual(notice.expires, 22)
        self.assertEqual(notice.title, "RADAR DETECTED")

    def test_stopped_monitor_is_unavailable(self):
        monitor = DfsEventMonitor("phy1")
        monitor.started = True
        monitor.process = Mock()
        monitor.process.poll.return_value = 1
        self.assertFalse(monitor.available)
        monitor.stderr.close()

    def test_plain_dfs_preserves_rssi_attribute(self):
        self.assertEqual(event_attr("-", True, 123), 123)

    def test_paused_csa_is_deferred_and_countdown_does_not_retune(self):
        app = Application(Mock(), Adapter("wlan1", "phy1"))
        ap = AccessPoint("AA", "Office", -50, 5, 5975)
        app.aps[ap.bssid] = ap
        app.channels = {
            2432: Channel(2432, 5),
            5975: Channel(5975, 5, radar=True),
            6115: Channel(6115, 33),
        }
        capture = Mock(channel_switches=queue.Queue())
        capture.channel_switches.put(ChannelSwitch(1, "AA", 5, 33, switch_count=2))
        app._dfs_events(capture, apply=False)
        self.assertEqual(ap.channel, 5)
        self.assertEqual(ap.event_label, "-")

        app._dfs_events(capture, apply=True)
        self.assertEqual(ap.event_label, "MOVE")
        self.assertEqual(ap.frequency, 5975)

        capture.channel_switches.put(ChannelSwitch(2, "AA", 5, 33, switch_count=0))
        app._dfs_events(capture)
        self.assertEqual(ap.frequency, 6115)

    def test_duplicate_channel_number_resolves_within_source_band(self):
        app = Application(Mock(), Adapter("wlan1", "phy1"))
        ap = AccessPoint("AA", "Office", -50, 1, 5955)
        app.aps[ap.bssid] = ap
        app.channels = {
            2432: Channel(2432, 5),
            5955: Channel(5955, 1),
            5975: Channel(5975, 5),
        }
        capture = Mock(channel_switches=queue.Queue())
        capture.channel_switches.put(ChannelSwitch(1, "AA", 1, 5, switch_count=0))

        app._dfs_events(capture)

        self.assertEqual(ap.frequency, 5975)

    def test_channel_only_event_matches_only_target_channel_and_refreshes_state(self):
        app = Application(Mock(), Adapter("wlan1", "phy1"))
        target = AccessPoint("AA", "Office", -50, 36, 5180)
        app.aps[target.bssid] = target
        app.hunt = target
        app.channels = {5180: Channel(5180, 36, radar=True, dfs_state="CAC")}

        app._apply_local_dfs_event(DfsEvent(DfsKind.RADAR, 1, channel=100))
        self.assertIsNone(app.hunt_notice)
        app._apply_local_dfs_event(DfsEvent(DfsKind.NOP_FINISHED, 2, channel=36))
        self.assertEqual(app.channels[5180].dfs_state, "USABLE")
        self.assertEqual(app.hunt_notice.bssid, "AA")


if __name__ == "__main__":
    unittest.main()
