"""Unit tests for PXE packet parser."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.proxydhcp import parse_packet, _detect_boot_file


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
        _section("parse_packet: valid PXE request (bare PXEClient)")
        data = _make_pxe_request()
        addr = ("127.0.0.1", 4011)
        info = parse_packet(data, addr)
        self.assertIsNotNone(info)
        self.assertEqual(info["client_address"], addr)
        self.assertEqual(info["transaction_id"], b"\x01\x02\x03\x04")
        self.assertEqual(info["mac_readable"], "aa:bb:cc:dd:ee:ff")
        self.assertEqual(info["boot_file"], "undionly.kpxe")
        _ok("PXE request parsed, default boot_file = undionly.kpxe")

    def test_bios_pxe_request(self) -> None:
        _section("parse_packet: BIOS PXE (Arch:0)")
        pkt = bytearray(240)
        pkt[0] = 1
        pkt[4:8] = b"\x01\x02\x03\x04"
        pkt[28:34] = b"\xaa\xbb\xcc\xdd\xee\xff"
        pkt[236:240] = b"\x63\x82\x53\x63"
        vendor = b"PXEClient:Arch:00000:UNDI:003000"
        pkt += bytes([60, len(vendor)]) + vendor
        pkt += bytes([255])
        info = parse_packet(bytes(pkt), ("127.0.0.1", 4011))
        self.assertIsNotNone(info)
        self.assertEqual(info["boot_file"], "undionly.kpxe")
        _ok("BIOS client → undionly.kpxe")

    def test_efi_pxe_request(self) -> None:
        _section("parse_packet: EFI PXE (Arch:7)")
        pkt = bytearray(240)
        pkt[0] = 1
        pkt[4:8] = b"\x01\x02\x03\x04"
        pkt[28:34] = b"\xaa\xbb\xcc\xdd\xee\xff"
        pkt[236:240] = b"\x63\x82\x53\x63"
        vendor = b"PXEClient:Arch:00007:UNDI:003000"
        pkt += bytes([60, len(vendor)]) + vendor
        pkt += bytes([255])
        info = parse_packet(bytes(pkt), ("127.0.0.1", 4011))
        self.assertIsNotNone(info)
        self.assertEqual(info["boot_file"], "ipxe.efi")
        _ok("EFI client → ipxe.efi")

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



# -----------------------------------------------------------------------
# _detect_boot_file edge cases
# -----------------------------------------------------------------------

class TestDetectBootFile(unittest.TestCase):
    def test_bios_arch_0(self) -> None:
        _section("_detect_boot_file: BIOS (Arch:0)")
        result = _detect_boot_file(b"PXEClient:Arch:00000:UNDI:003000")
        self.assertEqual(result, "undionly.kpxe")
        _ok("Arch 0 → undionly.kpxe")

    def test_efi_arch_6(self) -> None:
        _section("_detect_boot_file: EFI (Arch:6)")
        result = _detect_boot_file(b"PXEClient:Arch:00006:UNDI:003000")
        self.assertEqual(result, "ipxe.efi")
        _ok("Arch 6 → ipxe.efi")

    def test_efi_arch_7(self) -> None:
        _section("_detect_boot_file: EFI (Arch:7)")
        result = _detect_boot_file(b"PXEClient:Arch:00007:UNDI:003000")
        self.assertEqual(result, "ipxe.efi")
        _ok("Arch 7 → ipxe.efi")

    def test_efi_arch_9(self) -> None:
        _section("_detect_boot_file: EFI (Arch:9)")
        result = _detect_boot_file(b"PXEClient:Arch:00009:UNDI:003000")
        self.assertEqual(result, "ipxe.efi")
        _ok("Arch 9 → ipxe.efi")

    def test_bare_pxeclient(self) -> None:
        _section("_detect_boot_file: bare PXEClient")
        result = _detect_boot_file(b"PXEClient")
        self.assertEqual(result, "undionly.kpxe")
        _ok("Bare PXEClient → undionly.kpxe (safe default)")

    def test_malformed_vendor_class(self) -> None:
        _section("_detect_boot_file: malformed")
        result = _detect_boot_file(b"garbage\xff\xfe")
        self.assertEqual(result, "undionly.kpxe")
        _ok("Malformed vendor class → undionly.kpxe")

    def test_empty_vendor_class(self) -> None:
        _section("_detect_boot_file: empty")
        result = _detect_boot_file(b"")
        self.assertEqual(result, "undionly.kpxe")
        _ok("Empty vendor class → undionly.kpxe")

    def test_arch_without_colon(self) -> None:
        _section("_detect_boot_file: Arch without colon")
        result = _detect_boot_file(b"PXEClient:Arch")
        self.assertEqual(result, "undionly.kpxe")
        _ok("Incomplete Arch field → undionly.kpxe")


# -----------------------------------------------------------------------
# send_proxy_reply unit tests
# -----------------------------------------------------------------------

class TestSendProxyReply(unittest.TestCase):
    def test_sends_proxy_reply(self) -> None:
        _section("send_proxy_reply: builds and sends packet")
        from src.proxydhcp import send_proxy_reply

        mock_sock = unittest.mock.MagicMock()
        client_info = {
            "client_address": ("10.0.0.50", 4011),
            "transaction_id": b"\x01\x02\x03\x04",
            "mac_raw": b"\xaa\xbb\xcc\xdd\xee\xff",
            "mac_readable": "aa:bb:cc:dd:ee:ff",
            "boot_file": "undionly.kpxe",
        }

        send_proxy_reply(mock_sock, client_info)

        mock_sock.sendto.assert_called_once()
        sent_data, target = mock_sock.sendto.call_args[0]
        self.assertEqual(target, ("10.0.0.50", 4011))
        self.assertEqual(sent_data[0], 2)
        self.assertEqual(sent_data[4:8], b"\x01\x02\x03\x04")
        self.assertEqual(sent_data[28:34], b"\xaa\xbb\xcc\xdd\xee\xff")
        self.assertEqual(sent_data[236:240], b"\x63\x82\x53\x63")
        self.assertIn(b"undionly.kpxe", sent_data)
        self.assertIn(b"PXEClient", sent_data)
        _ok("Proxy reply packet correctly built and sent")

    def test_sends_ipxe_efi_boot_file(self) -> None:
        _section("send_proxy_reply: ipxe.efi boot file")
        from src.proxydhcp import send_proxy_reply

        mock_sock = unittest.mock.MagicMock()
        client_info = {
            "client_address": ("10.0.0.50", 4011),
            "transaction_id": b"\x01\x02\x03\x04",
            "mac_raw": b"\xaa\xbb\xcc\xdd\xee\xff",
            "mac_readable": "aa:bb:cc:dd:ee:ff",
            "boot_file": "ipxe.efi",
        }

        send_proxy_reply(mock_sock, client_info)

        sent_data = mock_sock.sendto.call_args[0][0]
        self.assertIn(b"ipxe.efi", sent_data)
        _ok("Proxy reply contains ipxe.efi")


if __name__ == "__main__":
    print()
    print(f"  {'#' * 62}")
    print(f"  #   PXE PACKET PARSER — UNIT TESTS")
    print(f"  {'#' * 62}")
    print()
    unittest.main(verbosity=2)
