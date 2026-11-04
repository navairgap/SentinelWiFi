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

    def test_gone_device_lookup_builds_current_mac_set_once(self):
        class CountingDevices(list):
            iterations = 0

            def __iter__(self):
                self.iterations += 1
                return super().__iter__()

        with tempfile.TemporaryDirectory() as td:
            first = SimpleNamespace(mac="AA:00:00:00:00:01", ip="192.0.2.1")
            second = SimpleNamespace(mac="AA:00:00:00:00:02", ip="192.0.2.2")
            current = CountingDevices([second])
            with patch.object(history, "HISTORY_FILE", os.path.join(td, "history.json")), \\
                 patch.object(history, "DATA_DIR", td):
                history.update([], [first, second])
                diff = history.update([], current)

            self.assertEqual(diff.gone_devices, [first.mac])
            self.assertEqual(current.iterations, 2)

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

    def test_failed_atomic_replace_preserves_snapshot_and_cleans_temp_file(self):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "history.json")
            with patch.object(history, "HISTORY_FILE", path), \
                 patch.object(history, "DATA_DIR", td):
                history.update([], [])
                with open(path, encoding="utf-8") as stream:
                    original = stream.read()

                with patch.object(history.os, "replace", side_effect=OSError("replace failed")):
                    with self.assertRaisesRegex(OSError, "replace failed"):
                        history.update([], [])

                with open(path, encoding="utf-8") as stream:
                    self.assertEqual(stream.read(), original)
                self.assertEqual(os.listdir(td), ["history.json"])

    def test_history_with_invalid_field_types_resets_to_empty_state(self):
        invalid_payloads = [
            "[]",
            '{"runs": true, "aps": {}, "devices": {}}',
            '{"runs": 2, "aps": [], "devices": {}}',
            '{"runs": 2, "aps": {}, "devices": {"aa:bb": 7}}',
        ]
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "history.json")
            with patch.object(history, "HISTORY_FILE", path):
                for payload in invalid_payloads:
                    with self.subTest(payload=payload):
                        with open(path, "w", encoding="utf-8") as stream:
                            stream.write(payload)
                        self.assertEqual(
                            history._load(),
                            {"runs": 0, "aps": {}, "devices": {}},
                        )


if __name__ == "__main__":
    unittest.main()
