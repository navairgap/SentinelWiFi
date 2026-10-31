"""Persistence tests for SentinelWiFi's local configuration file."""

import json
import os
import tempfile
import unittest
from unittest.mock import patch

from sentinelwifi import config


class TestConfigPersistence(unittest.TestCase):
    def test_save_creates_parent_and_round_trips_valid_settings(self):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "state", "config.json")
            with patch.object(config, "CONFIG_FILE", path):
                config.save_config({
                    "watch_interval": 120,
                    "notify": True,
                    "trusted_bssids": ["aa:bb:cc:dd:ee:ff"],
                    "ignored_setting": "not persisted",
                })
                with open(path, encoding="utf-8") as stream:
                    saved = json.load(stream)

        self.assertEqual(saved["watch_interval"], 120)
        self.assertTrue(saved["notify"])
        self.assertEqual(saved["trusted_bssids"], ["aa:bb:cc:dd:ee:ff"])
        self.assertEqual(saved["preferred_iface"], config.DEFAULTS["preferred_iface"])
        self.assertNotIn("ignored_setting", saved)

    def test_invalid_values_fall_back_to_defaults(self):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "config.json")
            with patch.object(config, "CONFIG_FILE", path):
                config.save_config({
                    "watch_interval": True,
                    "port_scan_timeout": float("inf"),
                    "notify": "yes",
                    "trusted_bssids": ["not-a-mac"],
                })
                with open(path, encoding="utf-8") as stream:
                    saved = json.load(stream)

        for key in ("watch_interval", "port_scan_timeout", "notify", "trusted_bssids"):
            with self.subTest(key=key):
                self.assertEqual(saved[key], config.DEFAULTS[key])

    def test_failed_replace_preserves_previous_file_and_cleans_temp_file(self):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "config.json")
            with patch.object(config, "CONFIG_FILE", path):
                config.save_config({"watch_interval": 90})
                with open(path, encoding="utf-8") as stream:
                    original = stream.read()

                with patch.object(config.os, "replace", side_effect=OSError("replace failed")):
                    with self.assertRaisesRegex(OSError, "replace failed"):
                        config.save_config({"watch_interval": 180})

                with open(path, encoding="utf-8") as stream:
                    self.assertEqual(stream.read(), original)
                self.assertEqual(os.listdir(td), ["config.json"])


if __name__ == "__main__":
    unittest.main()
