import socket
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.dhcp_server import (
    IPPool,
    _parse_dhcp_request,
    _build_bootp_packet,
    DHCP_DISCOVER,
    DHCP_OFFER,
    DHCP_REQUEST,
    DHCP_ACK,
    MAGIC_COOKIE,
    OPT_MESSAGE_TYPE,
    OPT_SERVER_ID,
    OPT_SUBNET_MASK,
    OPT_ROUTER,
    OPT_DNS,
    OPT_BROADCAST,
    OPT_DOMAIN,
    OPT_VENDOR_CLASS,
    OPT_TFTP_SERVER,
    OPT_BOOT_FILE,
    OPT_END,
)


def _section(title: str) -> None:
    print(f"\n  {'=' * 60}")
    print(f"  {title}")
    print(f"  {'=' * 60}")


def _ok(msg: str) -> None:
    print(f"  [+] {msg}")


# -----------------------------------------------------------------------
# IPPool tests
# -----------------------------------------------------------------------

class TestIPPool(unittest.TestCase):
    def test_allocate_first_ip(self) -> None:
        _section("IPPool: first allocation")
        pool = IPPool()
        ip = pool.allocate("aa:bb:cc:dd:ee:ff")
        self.assertEqual(ip, "192.168.42.100")
        _ok("First IP is 192.168.42.100")

    def test_allocate_reuses_lease(self) -> None:
        _section("IPPool: reuse lease")
        pool = IPPool()
        ip1 = pool.allocate("aa:bb:cc:dd:ee:ff")
        ip2 = pool.allocate("aa:bb:cc:dd:ee:ff")
        self.assertEqual(ip1, ip2)
        self.assertEqual(len(pool.leases), 1)
        _ok("Same MAC gets same IP")

    def test_allocate_different_macs(self) -> None:
        _section("IPPool: different MACs")
        pool = IPPool()
        ip1 = pool.allocate("aa:bb:cc:dd:ee:ff")
        ip2 = pool.allocate("11:22:33:44:55:66")
        self.assertNotEqual(ip1, ip2)
        self.assertEqual(ip1, "192.168.42.100")
        self.assertEqual(ip2, "192.168.42.101")
        _ok("Different MACs get sequential IPs")

    def test_allocate_pool_wraparound(self) -> None:
        _section("IPPool: wraparound")
        pool = IPPool(next_ip=199, max_ip=200)
        pool.allocate("aa:bb:cc:dd:ee:01")
        pool.allocate("aa:bb:cc:dd:ee:02")
        ip = pool.allocate("aa:bb:cc:dd:ee:03")
        self.assertEqual(ip, "192.168.42.100")
        _ok("Wraps to 100 after exhausting pool")

    def test_allocate_custom_subnet(self) -> None:
        _section("IPPool: custom subnet")
        pool = IPPool(subnet="10.0.0")
        ip = pool.allocate("aa:bb:cc:dd:ee:ff")
        self.assertEqual(ip, "10.0.0.100")
        _ok("Respects custom subnet")

    def test_allocate_sequential(self) -> None:
        _section("IPPool: sequential allocation")
        pool = IPPool()
        macs = [f"aa:bb:cc:dd:ee:{i:02x}" for i in range(5)]
        ips = [pool.allocate(m) for m in macs]
        expected = [f"192.168.42.{100 + i}" for i in range(5)]
        self.assertEqual(ips, expected)
        _ok("Five sequential allocations succeed")


# -----------------------------------------------------------------------
# _parse_dhcp_request tests
# -----------------------------------------------------------------------

class TestParseDhcpRequest(unittest.TestCase):
    def _make_packet(self, msg_type: int, is_pxe: bool = False) -> bytes:
        pkt = bytearray(240)
        pkt[0] = 1
        pkt[4:8] = b"\x01\x02\x03\x04"
        pkt[28:34] = b"\xaa\xbb\xcc\xdd\xee\xff"
        pkt[236:240] = MAGIC_COOKIE
        opts = bytearray()
        opts += bytes([OPT_MESSAGE_TYPE, 1, msg_type])
        if is_pxe:
            opts += bytes([OPT_VENDOR_CLASS, 9]) + b"PXEClient"
        opts += bytes([OPT_END])
        return bytes(pkt + opts)

    def test_parses_discover(self) -> None:
        _section("parse_dhcp: DISCOVER")
        result = _parse_dhcp_request(self._make_packet(DHCP_DISCOVER))
        self.assertIsNotNone(result)
        self.assertEqual(result["msg_type"], DHCP_DISCOVER)
        self.assertFalse(result["is_pxe"])
        _ok("DISCOVER parsed correctly")

    def test_parses_pxe_discover(self) -> None:
        _section("parse_dhcp: PXE DISCOVER")
        result = _parse_dhcp_request(self._make_packet(DHCP_DISCOVER, is_pxe=True))
        self.assertIsNotNone(result)
        self.assertTrue(result["is_pxe"])
        _ok("PXE DISCOVER detected")

    def test_parses_request(self) -> None:
        _section("parse_dhcp: REQUEST")
        result = _parse_dhcp_request(self._make_packet(DHCP_REQUEST))
        self.assertIsNotNone(result)
        self.assertEqual(result["msg_type"], DHCP_REQUEST)
        _ok("REQUEST parsed correctly")

    def test_parses_fields(self) -> None:
        _section("parse_dhcp: field extraction")
        result = _parse_dhcp_request(self._make_packet(DHCP_DISCOVER, is_pxe=True))
        self.assertEqual(result["xid"], b"\x01\x02\x03\x04")
        self.assertEqual(result["mac"], b"\xaa\xbb\xcc\xdd\xee\xff")
        self.assertEqual(result["mac_str"], "aa:bb:cc:dd:ee:ff")
        _ok("xid, mac, mac_str extracted correctly")

    def test_short_packet_returns_none(self) -> None:
        self.assertIsNone(_parse_dhcp_request(b"\x00" * 100))
        _ok("Short packet returns None")

    def test_wrong_opcode_returns_none(self) -> None:
        _section("parse_dhcp: wrong opcode")
        data = bytearray(240)
        data[0] = 2
        data[236:240] = MAGIC_COOKIE
        data += bytes([OPT_MESSAGE_TYPE, 1, DHCP_DISCOVER, OPT_END])
        self.assertIsNone(_parse_dhcp_request(bytes(data)))
        _ok("BOOTREPLY returns None")

    def test_no_magic_cookie_returns_none(self) -> None:
        _section("parse_dhcp: no magic cookie")
        data = bytearray(240)
        data[0] = 1
        self.assertIsNone(_parse_dhcp_request(bytes(data)))
        _ok("Missing magic cookie returns None")

    def test_unknown_msg_type_returns_none(self) -> None:
        _section("parse_dhcp: unknown msg type")
        result = _parse_dhcp_request(self._make_packet(99))
        self.assertIsNone(result)
        _ok("Unknown message type returns None")

    def test_pxe_in_wrong_tag(self) -> None:
        _section("parse_dhcp: PXEClient in wrong tag")
        pkt = bytearray(240)
        pkt[0] = 1
        pkt[4:8] = b"\x01\x02\x03\x04"
        pkt[28:34] = b"\xaa\xbb\xcc\xdd\xee\xff"
        pkt[236:240] = MAGIC_COOKIE
        opts = bytearray()
        opts += bytes([OPT_MESSAGE_TYPE, 1, DHCP_DISCOVER])
        opts += bytes([61, 9]) + b"PXEClient"
        opts += bytes([OPT_END])
        result = _parse_dhcp_request(bytes(pkt + opts))
        self.assertIsNotNone(result)
        self.assertFalse(result["is_pxe"])
        _ok("PXEClient in option 61 not treated as PXE")

    def test_options_before_magic_cookie_ignored(self) -> None:
        _section("parse_dhcp: options outside option area")
        pkt = bytearray(240)
        pkt[0] = 1
        pkt[4:8] = b"\x01\x02\x03\x04"
        pkt[28:34] = b"\xaa\xbb\xcc\xdd\xee\xff"
        pkt[236:240] = MAGIC_COOKIE
        opts = bytearray()
        opts += bytes([OPT_MESSAGE_TYPE, 1, DHCP_DISCOVER])
        opts += bytes([OPT_END])
        result = _parse_dhcp_request(bytes(pkt + opts))
        self.assertIsNotNone(result)
        _ok("Options parsed from correct offset")


# -----------------------------------------------------------------------
# _build_bootp_packet tests
# -----------------------------------------------------------------------

class TestBuildBootpPacket(unittest.TestCase):
    def setUp(self) -> None:
        self.request = {
            "xid": b"\x01\x02\x03\x04",
            "mac": b"\xaa\xbb\xcc\xdd\xee\xff",
            "mac_str": "aa:bb:cc:dd:ee:ff",
            "msg_type": DHCP_DISCOVER,
            "is_pxe": True,
        }
        self.ip = "192.168.42.100"
        self.server_ip = "192.168.42.129"

    def _walk_options(self, data: bytes) -> dict[int, bytes]:
        options = data[240:]
        result: dict[int, bytes] = {}
        i = 0
        while i < len(options):
            tag = options[i]
            if tag == OPT_END:
                break
            if i + 1 >= len(options):
                break
            length = options[i + 1]
            value = options[i + 2 : i + 2 + length]
            result[tag] = value
            i += 2 + length
        return result

    def test_bootp_header_fields(self) -> None:
        _section("build_bootp: header fields")
        pkt = _build_bootp_packet(self.request, self.ip, self.server_ip, DHCP_OFFER, "undionly.kpxe")
        self.assertEqual(pkt[0], 2)
        self.assertEqual(pkt[1], 1)
        self.assertEqual(pkt[2], 6)
        self.assertEqual(pkt[4:8], b"\x01\x02\x03\x04")
        self.assertEqual(pkt[28:34], b"\xaa\xbb\xcc\xdd\xee\xff")
        self.assertEqual(pkt[236:240], MAGIC_COOKIE)
        _ok("BOOTP header correctly populated")

    def test_yiaddr_and_siaddr(self) -> None:
        _section("build_bootp: yiaddr/siaddr")
        pkt = _build_bootp_packet(self.request, self.ip, self.server_ip, DHCP_OFFER, "undionly.kpxe")
        self.assertEqual(pkt[16:20], socket.inet_aton(self.ip))
        self.assertEqual(pkt[20:24], socket.inet_aton(self.server_ip))
        self.assertEqual(pkt[24:28], socket.inet_aton(self.server_ip))
        _ok("yiaddr, siaddr, giaddr set correctly")

    def test_dhcp_offer_options(self) -> None:
        _section("build_bootp: DHCP OFFER options")
        pkt = _build_bootp_packet(self.request, self.ip, self.server_ip, DHCP_OFFER, "undionly.kpxe")
        opts = self._walk_options(pkt)
        self.assertEqual(opts[OPT_MESSAGE_TYPE], bytes([DHCP_OFFER]))
        self.assertEqual(opts[OPT_SERVER_ID], socket.inet_aton(self.server_ip))
        self.assertEqual(opts[OPT_SUBNET_MASK], socket.inet_aton("255.255.255.0"))
        self.assertEqual(opts[OPT_VENDOR_CLASS], b"PXEClient")
        self.assertEqual(opts[OPT_TFTP_SERVER], socket.inet_aton(self.server_ip))
        _ok("OFFER includes all required options")

    def test_dhcp_ack_options(self) -> None:
        _section("build_bootp: DHCP ACK options")
        pkt = _build_bootp_packet(self.request, self.ip, self.server_ip, DHCP_ACK, "undionly.kpxe")
        opts = self._walk_options(pkt)
        self.assertEqual(opts[OPT_MESSAGE_TYPE], bytes([DHCP_ACK]))
        _ok("ACK has correct message type")

    def test_router_and_dns(self) -> None:
        _section("build_bootp: router and DNS")
        pkt = _build_bootp_packet(self.request, self.ip, self.server_ip, DHCP_OFFER, "undionly.kpxe")
        opts = self._walk_options(pkt)
        self.assertEqual(opts[OPT_ROUTER], socket.inet_aton(self.server_ip))
        self.assertEqual(opts[OPT_DNS], socket.inet_aton(self.server_ip))
        _ok("Router and DNS set to server IP")

    def test_boot_file_option(self) -> None:
        _section("build_bootp: boot file")
        pkt = _build_bootp_packet(self.request, self.ip, self.server_ip, DHCP_ACK, "ipxe.efi")
        opts = self._walk_options(pkt)
        self.assertEqual(opts[OPT_BOOT_FILE], b"ipxe.efi\x00")
        _ok("Boot file is null-terminated")

    def test_broadcast_option(self) -> None:
        _section("build_bootp: broadcast address")
        pkt = _build_bootp_packet(self.request, self.ip, self.server_ip, DHCP_OFFER, "undionly.kpxe")
        opts = self._walk_options(pkt)
        self.assertEqual(opts[OPT_BROADCAST], socket.inet_aton("192.168.42.255"))
        _ok("Broadcast address derived from server IP's subnet")

    def test_different_server_subnet(self) -> None:
        _section("build_bootp: different subnet")
        pkt = _build_bootp_packet(self.request, "10.0.0.50", "10.0.0.1", DHCP_OFFER, "undionly.kpxe")
        opts = self._walk_options(pkt)
        self.assertEqual(opts[OPT_BROADCAST], socket.inet_aton("10.0.0.255"))
        self.assertEqual(opts[OPT_SUBNET_MASK], socket.inet_aton("255.255.255.0"))
        _ok("Broadcast matches server's subnet")


if __name__ == "__main__":
    print()
    print(f"  {'#' * 62}")
    print(f"  #   DHCP SERVER — UNIT TESTS")
    print(f"  {'#' * 62}")
    print()
    unittest.main(verbosity=2)
