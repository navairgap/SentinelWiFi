"""Tests for SentinelWiFi's local AP and device history."""

import json
import os
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from sentinelwifi import history


class TestHistoryPersistence(unittest.TestCase):
    def test_first_run_sets_baseline_and_second_run_reports_changes(self):
        with tempfile.TemporaryDirectory() as td:
            history_path = os.path.join(td, "history.json")
            ap1 = SimpleNamespace(bssid="AA:BB:CC:DD:EE:01", ssid="Home")
            ap2 = SimpleNamespace(bssid="AA:BB:CC:DD:EE:02", ssid="Guest")
            device1 = SimpleNamespace(mac="10:20:30:40:50:01", ip="192.168.1.10")
            device2 = SimpleNamespace(mac="10:20:30:40:50:02", ip="192.168.1.11")

            with patch.object(history, "HISTORY_FILE", history_path), \
                 patch.object(history, "DATA_DIR", td):
                first = history.update([ap1], [device1])
                second = history.update([ap1, ap2], [device2])

                with open(history_path, encoding="utf-8") as stream:
                    saved = json.load(stream)

                self.assertEqual(first.runs, 1)
                self.assertEqual(first.new_aps, [])
                self.assertEqual(first.new_devices, [])
                self.assertEqual(second.runs, 2)
                self.assertEqual([ap.bssid for ap in second.new_aps], [ap2.bssid])
                self.assertEqual([device.mac for device in second.new_devices], [device2.mac])
                self.assertEqual(second.gone_devices, [device1.mac])

            self.assertEqual(saved["runs"], 2)
            self.assertEqual(saved["aps"][ap2.bssid], ap2.ssid)
            self.assertEqual(saved["devices"][device2.mac], device2.ip)
            self.assertEqual(os.listdir(td), ["history.json"])

    def test_malformed_history_starts_from_empty_state(self):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "history.json")
            with open(path, "w", encoding="utf-8") as stream:
                stream.write("{not valid json")
            with patch.object(history, "HISTORY_FILE", path):
                self.assertEqual(
                    history._load(),
                    {"runs": 0, "aps": {}, "devices": {}},
                )


if __name__ == "__main__":
    unittest.main()
