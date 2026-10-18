"""Tests for vendors, DHCP parsing, ports helpers, report rendering, and
the demo dataset. For auditing networks you own or are authorized to test."""

import json
import os
import tempfile
import unittest

from sentinelwifi.dhcp import parse_leases_text
from sentinelwifi.ports import PORTS, risk_summary, OpenPort
from sentinelwifi.vendors import lookup_vendor


class TestVendors(unittest.TestCase):
    def test_known_prefixes(self):
        self.assertEqual(lookup_vendor("B8:27:EB:12:34:56"),
                         "Raspberry Pi Foundation")
        self.assertEqual(lookup_vendor("a4:b1:97:00:11:22"), "Apple")

    def test_unknown(self):
        self.assertEqual(lookup_vendor("FF:FF:FF:00:00:00"), "Unknown vendor")
        self.assertEqual(lookup_vendor(""), "Unknown vendor")


class TestDhcpParse(unittest.TestCase):
    def test_extracts_servers(self):
        text = """
lease {
  interface "wlp2s0";
  option dhcp-server-identifier 192.168.1.1;
}
lease {
  option dhcp-server-identifier 10.0.0.66;
}
"""
        self.assertEqual(parse_leases_text(text),
                         {"192.168.1.1", "10.0.0.66"})

    def test_empty(self):
        self.assertEqual(parse_leases_text("no leases here"), set())


class TestPorts(unittest.TestCase):
    def test_risky_ports_flagged(self):
        svc = {"10.0.0.5": [OpenPort(23, PORTS[23]), OpenPort(443, "HTTPS")]}
        notes = risk_summary(svc)
        self.assertEqual(len(notes), 1)
        self.assertIn("Telnet", notes[0])
        self.assertIn("10.0.0.5", notes[0])

    def test_curated_list_reasonable(self):
        self.assertLessEqual(len(PORTS), 30)
        self.assertIn(7547, PORTS)   # TR-069 router exploit target
        self.assertIn(23, PORTS)     # Telnet
        self.assertIn(5900, PORTS)   # VNC


class TestReportAndDemo(unittest.TestCase):
    def test_demo_json_and_html(self):
        import sentinel
        from sentinelwifi.report import report_to_json, write_html_report
        data = sentinel._demo_data()
        payload = json.loads(report_to_json(data))
        self.assertIn("score", payload)
        self.assertGreater(len(payload["devices"]), 0)
        self.assertGreater(len(payload["score"]["findings"]), 0)
        with tempfile.TemporaryDirectory() as td:
            path = write_html_report(data, os.path.join(td, "r.html"))
            html = open(path).read()
        self.assertIn("Findings", html)
        self.assertIn("grade", html)


if __name__ == "__main__":
    unittest.main()


class TestNeighParse(unittest.TestCase):
    def test_standard_order(self):
        from sentinelwifi.lan_scan import _parse_neigh
        text = ("192.168.1.1 dev wlp3s0 lladdr 10:20:30:40:50:60 REACHABLE\n"
                "192.168.1.5 dev wlp3s0  failed\n"
                "192.168.1.9 dev wlp3s0 lladdr aa:bb:cc:dd:ee:ff STALE\n")
        self.assertEqual(_parse_neigh(text),
                         [("192.168.1.1", "10:20:30:40:50:60"),
                          ("192.168.1.9", "AA:BB:CC:DD:EE:FF")])

    def test_lladdr_first_order(self):
        from sentinelwifi.lan_scan import _parse_neigh
        text = "192.168.1.2 lladdr de:ad:be:ef:00:01 dev eth0 REACHABLE\n"
        self.assertEqual(_parse_neigh(text),
                         [("192.168.1.2", "DE:AD:BE:EF:00:01")])


class TestArpScan(unittest.TestCase):
    def test_returns_enriched_devices(self):
        import sys
        import types
        from unittest.mock import patch
        from sentinelwifi import lan_scan

        class Packet:
            def __truediv__(self, other):
                return self

        fake_scapy = types.ModuleType("scapy.all")
        fake_scapy.Ether = lambda **kwargs: Packet()
        fake_scapy.ARP = lambda **kwargs: Packet()
        fake_scapy.srp = lambda *args, **kwargs: (
            [(None, types.SimpleNamespace(psrc="192.168.1.1", hwsrc="AA:BB:CC:DD:EE:FF"))],
            [],
        )
        fake_scapy_parent = types.ModuleType("scapy")
        fake_scapy_parent.__path__ = []

        with patch.dict(sys.modules, {"scapy": fake_scapy_parent, "scapy.all": fake_scapy}), \
             patch.object(lan_scan, "local_network_info", return_value=("192.168.1.9", "192.168.1.1", "eth0")), \
             patch.object(lan_scan, "self_mac", return_value="11:22:33:44:55:66"), \
             patch.object(lan_scan.socket, "gethostbyaddr", return_value=("router.local", [], [])):
            devices = lan_scan.arp_scan("192.168.1.0/24")

        self.assertEqual(len(devices), 1)
        self.assertEqual(devices[0].ip, "192.168.1.1")
        self.assertTrue(devices[0].is_gateway)
        self.assertFalse(devices[0].is_self)
        self.assertEqual(devices[0].hostname, "router.local")


class TestMalformedNeighbors(unittest.TestCase):
    def test_missing_mac_and_invalid_ip_are_skipped(self):
        from sentinelwifi.lan_scan import _parse_neigh
        text = (
            "192.168.1.1 dev eth0 lladdr REACHABLE\n"
            "not-an-ip dev eth0 lladdr 10:20:30:40:50:60 STALE\n"
            "192.168.1.2 dev eth0 lladdr de:ad:be:ef:00:01 REACHABLE\n"
        )
        self.assertEqual(
            _parse_neigh(text),
            [("192.168.1.2", "DE:AD:BE:EF:00:01")],
        )


class TestServiceScanArguments(unittest.TestCase):
    def test_empty_port_selection_scans_nothing(self):
        from sentinelwifi.ports import scan_services
        self.assertEqual(scan_services(["192.168.1.10"], ports={}), {})

    def test_nonpositive_timeout_is_rejected(self):
        from sentinelwifi.ports import scan_services
        with self.assertRaises(ValueError):
            scan_services(["192.168.1.10"], timeout=0)

    def test_invalid_port_is_rejected(self):
        from sentinelwifi.ports import scan_services
        with self.assertRaises(ValueError):
            scan_services(["192.168.1.10"], ports={70000: "invalid"})


class TestConfigValidation(unittest.TestCase):
    def test_invalid_values_fall_back_to_defaults(self):
        from unittest.mock import patch
        from sentinelwifi import config as config_module

        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "config.json")
            with open(path, "w") as f:
                json.dump({
                    "watch_interval": "fast",
                    "port_scan_timeout": -1,
                    "notify": "yes",
                    "trusted_bssids": "AA:BB:CC:DD:EE:FF",
                    "preferred_iface": 7,
                    "port_scan_enabled": False,
                }, f)
            with patch.object(config_module, "CONFIG_FILE", path):
                loaded = config_module.load_config()

        self.assertEqual(loaded["watch_interval"], config_module.DEFAULTS["watch_interval"])
        self.assertEqual(loaded["port_scan_timeout"], config_module.DEFAULTS["port_scan_timeout"])
        self.assertFalse(loaded["notify"])
        self.assertEqual(loaded["trusted_bssids"], [])
        self.assertEqual(loaded["preferred_iface"], "")
        self.assertFalse(loaded["port_scan_enabled"])

    def test_valid_values_are_preserved(self):
        from unittest.mock import patch
        from sentinelwifi import config as config_module

        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "config.json")
            with open(path, "w") as f:
                json.dump({
                    "watch_interval": 120,
                    "port_scan_timeout": 1.25,
                    "notify": True,
                    "trusted_bssids": ["AA:BB:CC:DD:EE:FF"],
                    "preferred_iface": "wlan0",
                }, f)
            with patch.object(config_module, "CONFIG_FILE", path):
                loaded = config_module.load_config()

        self.assertEqual(loaded["watch_interval"], 120)
        self.assertEqual(loaded["port_scan_timeout"], 1.25)
        self.assertTrue(loaded["notify"])
        self.assertEqual(loaded["trusted_bssids"], ["AA:BB:CC:DD:EE:FF"])
        self.assertEqual(loaded["preferred_iface"], "wlan0")


class TestLocalNetworkSocketCleanup(unittest.TestCase):
    def test_socket_closes_when_connect_fails(self):
        from unittest.mock import patch
        from sentinelwifi import lan_scan

        fake_socket = unittest.mock.MagicMock()
        fake_socket.__enter__.return_value = fake_socket
        fake_socket.connect.side_effect = OSError("no network")
        with patch.object(lan_scan.socket, "socket", return_value=fake_socket):
            result = lan_scan.local_network_info()

        self.assertEqual(result, ("", "", ""))
        fake_socket.__exit__.assert_called_once()


class TestDefaultGatewayParsing(unittest.TestCase):
    def test_malformed_route_entries_are_skipped(self):
        from unittest.mock import mock_open, patch
        from sentinelwifi.lan_scan import _default_gateway

        routes = (
            "Iface Destination Gateway Flags\n"
            "malformed\n"
            "eth0 00000000 NOTHEX 0003\n"
            "wlan0 00000000 0101A8C0 0003\n"
        )
        with patch("builtins.open", mock_open(read_data=routes)):
            self.assertEqual(_default_gateway(), "192.168.1.1")
