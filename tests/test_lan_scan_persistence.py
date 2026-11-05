"""Regression tests for local known-device history persistence."""

import json
import os
import stat
import tempfile
import unittest
from unittest.mock import patch

from sentinelwifi import lan_scan


class KnownDevicePersistenceTests(unittest.TestCase):
    def test_invalid_json_shapes_do_not_crash_or_create_entries(self):
        payloads = (
            "[]",
            "null",
            '"mac-list"',
            '{"macs": "AA:BB:CC:DD:EE:FF"}',
            '{"macs": ["not-a-mac", 7, null]}',
        )
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "known_devices.json")
            with patch.object(lan_scan, "KNOWN_DEVICES_FILE", path):
                for payload in payloads:
                    with self.subTest(payload=payload):
                        with open(path, "w", encoding="utf-8") as stream:
                            stream.write(payload)
                        self.assertEqual(lan_scan._load_known(), set())

    def test_valid_macs_are_normalized_and_invalid_entries_ignored(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "known_devices.json")
            with open(path, "w", encoding="utf-8") as stream:
                json.dump({"macs": ["aa:bb:cc:dd:ee:ff", "bad", 42]}, stream)
            with patch.object(lan_scan, "KNOWN_DEVICES_FILE", path):
                self.assertEqual(lan_scan._load_known(), {"AA:BB:CC:DD:EE:FF"})

    def test_save_is_atomic_and_uses_private_file_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "known_devices.json")
            with patch.object(lan_scan, "KNOWN_DEVICES_FILE", path), \
                 patch.object(lan_scan, "DATA_DIR", directory):
                lan_scan._save_known({"AA:BB:CC:DD:EE:FF"})
                with open(path, encoding="utf-8") as stream:
                    self.assertEqual(json.load(stream), {"macs": ["AA:BB:CC:DD:EE:FF"]})
                self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
                self.assertEqual(os.listdir(directory), ["known_devices.json"])


if __name__ == "__main__":
    unittest.main()
