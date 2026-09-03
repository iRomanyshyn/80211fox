import unittest
from unittest.mock import patch
from pathlib import Path
from tempfile import TemporaryDirectory

from fox80211.model import AccessPoint, normalize_mac
from fox80211.tui import beep_interval, proximity
from fox80211.system import _device_product


class CoreTests(unittest.TestCase):
    def test_mac_normalization_and_filter(self):
        ap = AccessPoint("58:CB:52:12:34:56", "Office", -50, 124, 5620)
        self.assertEqual(normalize_mac("58-cb.52"), "58cb52")
        self.assertTrue(ap.matches("office"))
        self.assertTrue(ap.matches("58cb5212"))
        self.assertTrue(ap.matches("cb:52:12"))
        self.assertFalse(ap.matches("guest"))

    def test_ewma(self):
        ap = AccessPoint("00:00:00:00:00:00", "x", -60, 1, 2412, average=-60)
        ap.update(-40, 1, 2412)
        self.assertEqual(ap.average, -55)

    @patch("fox80211.model.time.monotonic", side_effect=[105.0, 111.0])
    def test_recent_rssi_uses_rolling_time_window(self, monotonic):
        ap = AccessPoint("00:00:00:00:00:00", "x", -60, 1, 2412, last_seen=99.0)
        ap.update(-40, 1, 2412)
        ap.update(-20, 1, 2412)
        self.assertEqual(ap.recent_rssi(10.0, now=111.0), -30)

    @patch("fox80211.model.time.monotonic", side_effect=[105.0, 111.0])
    def test_update_prunes_rssi_history_without_rendering(self, monotonic):
        ap = AccessPoint("00:00:00:00:00:00", "x", -60, 1, 2412, last_seen=90.0)
        ap.update(-40, 1, 2412)
        ap.update(-20, 1, 2412)
        self.assertEqual(list(ap.rssi_history), [(105.0, -40), (111.0, -20)])

    def test_strength_drives_label_and_cadence(self):
        self.assertEqual(proximity(-80)[0], "FAR OR OBSTRUCTED")
        self.assertEqual(proximity(-30)[0], "VERY CLOSE")
        self.assertLess(beep_interval(-35), beep_interval(-75))

    def test_usb_product_can_be_found_on_parent(self):
        with TemporaryDirectory() as directory:
            parent = Path(directory) / "usb-device"
            child = parent / "interface"
            child.mkdir(parents=True)
            (parent / "product").write_text("Netgear A6210\n")
            self.assertEqual(_device_product(child), "Netgear A6210")


if __name__ == "__main__":
    unittest.main()
