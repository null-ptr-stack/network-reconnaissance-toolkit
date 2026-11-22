
import sys
import unittest

from pathlib import Path

sys.path.insert(
    0,
    str(Path(__file__).resolve().parents[1] / "src")
)

from nrt import validate_target, validate_ports


class TestTargetValidation(unittest.TestCase):

    def test_valid_private_ip(self):
        self.assertEqual(
            validate_target("192.168.1.10"),
            "192.168.1.10/32"
        )

    def test_valid_private_network(self):
        self.assertEqual(
            validate_target("10.0.0.0/24"),
            "10.0.0.0/24"
        )

    def test_public_ip_rejected(self):
        with self.assertRaises(ValueError):
            validate_target("8.8.8.8")

    def test_invalid_ip_rejected(self):
        with self.assertRaises(ValueError):
            validate_target("invalid-ip")

    def test_oversized_network_rejected(self):
        with self.assertRaises(ValueError):
            validate_target("10.0.0.0/16")

    def test_ipv6_rejected(self):
        with self.assertRaises(ValueError):
            validate_target("2001:db8::1")

    def test_valid_ports(self):
        self.assertEqual(
            validate_ports("22,80,443"),
            "22,80,443"
        )

    def test_valid_port_range(self):
        self.assertEqual(
            validate_ports("1-1000"),
            "1-1000"
        )

    def test_invalid_port(self):
        with self.assertRaises(ValueError):
            validate_ports("99999")

    def test_invalid_port_syntax(self):
        with self.assertRaises(ValueError):
            validate_ports("80;rm")


if __name__ == "__main__":
    unittest.main()

