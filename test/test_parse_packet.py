"""Unit tests for PXE packet parser."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.logic import parse_packet


def _section(title: str) -> None:
    print(f"\n  {'=' * 60}")
    print(f"  {title}")
    print(f"  {'=' * 60}")


def _ok(msg: str) -> None:
    print(f"  [+] {msg}")


def _info(msg: str) -> None:
    print(f"  [*] {msg}")


def _make_pxe_request() -> bytes:
    """Build a minimal BOOTREQUEST with PXE option (option 60)."""
    pkt = bytearray(240)
    pkt[0] = 1  # BOOTREQUEST
    pkt[4:8] = b"\x01\x02\x03\x04"  # transaction id
    pkt[28:34] = b"\xaa\xbb\xcc\xdd\xee\xff"  # client MAC
    pkt[236:240] = b"\x63\x82\x53\x63"  # DHCP magic cookie
    # options: tag 60 (len 9) = b'PXEClient', end(255)
    pkt += bytes([60, 9]) + b"PXEClient"
    pkt += bytes([255])
    return bytes(pkt)


class TestParsePacket(unittest.TestCase):
    def test_valid_pxe_request(self) -> None:
        _section("parse_packet: valid PXE request")
        data = _make_pxe_request()
        addr = ("127.0.0.1", 4011)
        info = parse_packet(data, addr)
        self.assertIsNotNone(info)
        self.assertEqual(info["client_address"], addr)
        self.assertEqual(info["transaction_id"], b"\x01\x02\x03\x04")
        self.assertEqual(info["mac_readable"], "aa:bb:cc:dd:ee:ff")
        _ok("PXE request parsed correctly")

    def test_short_packet_returns_none(self) -> None:
        _section("parse_packet: short packet")
        result = parse_packet(b"\x01\x02\x03", ("127.0.0.1", 4011))
        self.assertIsNone(result)
        _ok("Short packet returns None")

    def test_non_bootrequest_returns_none(self) -> None:
        _section("parse_packet: non-bootrequest")
        pkt = bytearray(240)
        pkt[0] = 2  # BOOTREPLY, not BOOTREQUEST
        pkt[236:240] = b"\x63\x82\x53\x63"
        result = parse_packet(bytes(pkt), ("127.0.0.1", 4011))
        self.assertIsNone(result)
        _ok("Non-bootrequest returns None")

    def test_missing_magic_cookie_returns_none(self) -> None:
        _section("parse_packet: missing magic cookie")
        pkt = bytearray(240)
        pkt[0] = 1  # BOOTREQUEST
        result = parse_packet(bytes(pkt), ("127.0.0.1", 4011))
        self.assertIsNone(result)
        _ok("Missing magic cookie returns None")

    def test_no_pxe_option_returns_none(self) -> None:
        _section("parse_packet: no PXE option")
        pkt = bytearray(240)
        pkt[0] = 1  # BOOTREQUEST
        pkt[236:240] = b"\x63\x82\x53\x63"
        # Add option 60 but with wrong vendor class
        pkt += bytes([60, 5]) + b"Linux"
        pkt += bytes([255])
        result = parse_packet(bytes(pkt), ("127.0.0.1", 4011))
        self.assertIsNone(result)
        _ok("Non-PXE vendor class returns None")


if __name__ == "__main__":
    print()
    print(f"  {'#' * 62}")
    print(f"  #   PXE PACKET PARSER — UNIT TESTS")
    print(f"  {'#' * 62}")
    print()
    unittest.main(verbosity=2)
