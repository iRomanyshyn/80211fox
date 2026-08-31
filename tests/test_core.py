import unittest

from fox80211.model import AccessPoint, normalize_mac
from fox80211.tui import beep_interval, proximity


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

    def test_strength_drives_label_and_cadence(self):
        self.assertEqual(proximity(-80)[0], "WEAK")
        self.assertEqual(proximity(-30)[0], "VERY CLOSE")
        self.assertLess(beep_interval(-35), beep_interval(-75))


if __name__ == "__main__":
    unittest.main()
