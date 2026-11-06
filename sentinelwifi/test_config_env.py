"""Notification-override tests for the local configuration loader.

For auditing networks you own or are authorized to test.
"""

import json
import os
import tempfile
import unittest
from unittest.mock import patch

from sentinelwifi import config


class NotificationOverrideTests(unittest.TestCase):
    def test_only_explicit_truthy_values_disable_notifications(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "config.json")
            with open(path, "w", encoding="utf-8") as stream:
                json.dump({"notify": True}, stream)

            with patch.object(config, "CONFIG_FILE", path):
                for value in ("1", "true", "TRUE", "yes", "on"):
                    with self.subTest(value=value), patch.dict(os.environ, {
                        "SENTINELWIFI_NO_NOTIFY": value
                    }):
                        self.assertFalse(config.load_config()["notify"])

                for value in ("0", "false", "off", ""):
                    with self.subTest(value=value), patch.dict(os.environ, {
                        "SENTINELWIFI_NO_NOTIFY": value
                    }):
                        self.assertTrue(config.load_config()["notify"])

    def test_missing_override_preserves_saved_preference(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "config.json")
            with open(path, "w", encoding="utf-8") as stream:
                json.dump({"notify": True}, stream)
            with patch.object(config, "CONFIG_FILE", path):
                with patch.dict(os.environ, {}, clear=True):
                    self.assertTrue(config.load_config()["notify"])


if __name__ == "__main__":
    unittest.main()
