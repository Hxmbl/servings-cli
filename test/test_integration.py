import socket
import struct
import sys
import threading
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.proxydhcp import parse_packet
from src.tftp import TFTP_RRQ, TFTP_DATA, TFTP_ACK, TFTP_ERROR


def _section(title: str) -> None:
    print(f"\n  {'=' * 60}")
    print(f"  {title}")
    print(f"  {'=' * 60}")


def _ok(msg: str) -> None:
    print(f"  [+] {msg}")


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", 0))
        return s.getsockname()[1]


def _make_pxe_discover(
    xid: bytes = b"\xde\xad\xbe\xef",
    mac: bytes = b"\x00\x11\x22\x33\x44\x55",
    vendor: bytes = b"PXEClient",
) -> bytes:
    pkt = bytearray(240)
    pkt[0] = 1
    pkt[4:8] = xid
    pkt[28:34] = mac
    pkt[236:240] = b"\x63\x82\x53\x63"
    pkt += bytes([60, len(vendor)]) + vendor
    pkt += bytes([255])
    return bytes(pkt)


# -----------------------------------------------------------------------
# ProxyDHCP integration tests
# -----------------------------------------------------------------------

class TestProxyDHCPIntegration(unittest.TestCase):
    def _start_server(self) -> tuple[int, threading.Event, threading.Thread]:
        from src.proxydhcp import _proxydhcp_listener
        port = _find_free_port()
        shutdown = threading.Event()
        t = threading.Thread(target=_proxydhcp_listener, args=(port, shutdown), daemon=True)
        t.start()
        time.sleep(0.15)
        return port, shutdown, t

    def test_responds_to_pxe_discover(self) -> None:
        _section("ProxyDHCP: responds to PXE DISCOVER")
        port, shutdown, t = self._start_server()

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3.0)
        sock.sendto(_make_pxe_discover(), ("127.0.0.1", port))

        try:
            data, addr = sock.recvfrom(2048)
        except socket.timeout:
            shutdown.set()
            sock.close()
            t.join(timeout=1)
            self.fail("No response from ProxyDHCP listener")

        shutdown.set()
        sock.close()
        t.join(timeout=1)

        self.assertGreater(len(data), 240)
        self.assertEqual(data[0], 2)
        self.assertEqual(data[4:8], b"\xde\xad\xbe\xef")
        self.assertEqual(data[28:34], b"\x00\x11\x22\x33\x44\x55")
        self.assertEqual(data[236:240], b"\x63\x82\x53\x63")
        _ok(f"Got ProxyDHCP reply ({len(data)} bytes)")

    def test_reply_contains_pxe_options(self) -> None:
        _section("ProxyDHCP: reply has PXE options")
        port, shutdown, t = self._start_server()

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3.0)
        sock.bind(("", 0))
        sock.sendto(_make_pxe_discover(), ("127.0.0.1", port))

        try:
            data, _ = sock.recvfrom(2048)
        except socket.timeout:
            shutdown.set()
            sock.close()
            t.join(timeout=1)
            self.fail("No response")

        shutdown.set()
        sock.close()
        t.join(timeout=1)

        opts = data[240:]
        self.assertIn(b"PXEClient", opts)
        self.assertIn(b"undionly.kpxe", opts)
        self.assertIn(data[240:243], [b"\x35\x01\x05"])
        _ok("Reply contains PXEClient, undionly.kpxe, DHCPACK")

    def test_reply_uses_source_port(self) -> None:
        _section("ProxyDHCP: reply goes to source port")
        port, shutdown, t = self._start_server()

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3.0)
        sock.bind(("127.0.0.1", 0))
        client_port = sock.getsockname()[1]
        sock.sendto(_make_pxe_discover(), ("127.0.0.1", port))

        try:
            data, addr = sock.recvfrom(2048)
        except socket.timeout:
            shutdown.set()
            sock.close()
            t.join(timeout=1)
            self.fail("No response")

        shutdown.set()
        sock.close()
        t.join(timeout=1)

        self.assertEqual(addr, ("127.0.0.1", port))
        _ok("Reply sent from server port")

    def test_non_pxe_request_ignored(self) -> None:
        _section("ProxyDHCP: non-PXE request ignored")
        port, shutdown, t = self._start_server()

        non_pxe = bytearray(240)
        non_pxe[0] = 1
        non_pxe[4:8] = b"\xde\xad\xbe\xef"
        non_pxe[28:34] = b"\x00\x11\x22\x33\x44\x55"
        non_pxe[236:240] = b"\x63\x82\x53\x63"
        non_pxe += bytes([60, 5]) + b"Linux"
        non_pxe += bytes([255])

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1.5)
        sock.sendto(bytes(non_pxe), ("127.0.0.1", port))

        try:
            data, _ = sock.recvfrom(2048)
            shutdown.set()
            sock.close()
            t.join(timeout=1)
            self.fail("Should not respond to non-PXE request")
        except socket.timeout:
            pass

        shutdown.set()
        sock.close()
        t.join(timeout=1)
        _ok("Non-PXE request correctly ignored")

    def test_efi_client_gets_ipxe_efi(self) -> None:
        _section("ProxyDHCP: EFI client gets ipxe.efi")
        port, shutdown, t = self._start_server()

        vendor = b"PXEClient:Arch:00007:UNDI:003000"
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3.0)
        sock.bind(("", 0))
        sock.sendto(_make_pxe_discover(vendor=vendor), ("127.0.0.1", port))

        try:
            data, _ = sock.recvfrom(2048)
        except socket.timeout:
            shutdown.set()
            sock.close()
            t.join(timeout=1)
            self.fail("No response")

        shutdown.set()
        sock.close()
        t.join(timeout=1)

        self.assertIn(b"ipxe.efi", data)
        _ok("EFI client receives ipxe.efi boot file")

    def test_multiple_clients(self) -> None:
        _section("ProxyDHCP: multiple clients")
        port, shutdown, t = self._start_server()

        socks = []
        try:
            for i, (mac, xid) in enumerate([
                (b"\x00\x11\x22\x33\x44\x55", b"\x01\x00\x00\x01"),
                (b"\xaa\xbb\xcc\xdd\xee\xff", b"\x02\x00\x00\x02"),
                (b"\x11\x22\x33\x44\x55\x66", b"\x03\x00\x00\x03"),
            ]):
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(3.0)
                s.bind(("", 0))
                s.sendto(_make_pxe_discover(xid=xid, mac=mac), ("127.0.0.1", port))
                socks.append(s)

            for i, s in enumerate(socks):
                data, _ = s.recvfrom(2048)
                self.assertEqual(data[0], 2)
                self.assertEqual(data[4:8], [b"\x01\x00\x00\x01", b"\x02\x00\x00\x02", b"\x03\x00\x00\x03"][i])
                self.assertEqual(data[28:34], [
                    b"\x00\x11\x22\x33\x44\x55",
                    b"\xaa\xbb\xcc\xdd\xee\xff",
                    b"\x11\x22\x33\x44\x55\x66",
                ][i])
        finally:
            shutdown.set()
            for s in socks:
                s.close()
            t.join(timeout=1)
        _ok("Three concurrent clients all get correct responses")


# -----------------------------------------------------------------------
# TFTP integration tests
# -----------------------------------------------------------------------

class TestTFTPIntegration(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = TemporaryDirectory()
        self.boot_dir = Path(self.tmpdir.name)
        self.boot_file = self.boot_dir / "undionly.kpxe"
        self.boot_file.write_bytes(b"FAKE_IPXE_" + b"x" * 2000)

    def tearDown(self) -> None:
        self.tmpdir.cleanup()

    def _start_server(self) -> tuple[int, threading.Event, threading.Thread]:
        from src.tftp import _tftp_listener
        port = _find_free_port()
        shutdown = threading.Event()
        t = threading.Thread(target=_tftp_listener, args=(port, self.boot_dir, shutdown), daemon=True)
        t.start()
        time.sleep(0.15)
        return port, shutdown, t

    def _rrq(self, filename: str) -> bytes:
        return struct.pack("!H", TFTP_RRQ) + filename.encode() + b"\x00octet\x00"

    def test_serves_first_block(self) -> None:
        _section("TFTP: first DATA block")
        port, shutdown, t = self._start_server()

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3.0)
        sock.sendto(self._rrq("undionly.kpxe"), ("127.0.0.1", port))

        try:
            data, addr = sock.recvfrom(2048)
        except socket.timeout:
            shutdown.set()
            sock.close()
            t.join(timeout=1)
            self.fail("No TFTP response")

        opcode = struct.unpack("!H", data[:2])[0]
        self.assertEqual(opcode, TFTP_DATA)
        block = struct.unpack("!H", data[2:4])[0]
        self.assertEqual(block, 1)
        expected = self.boot_file.read_bytes()[:512]
        self.assertEqual(data[4:], expected)
        _ok(f"Block 1 received ({len(data[4:])} bytes)")

        shutdown.set()
        sock.close()
        t.join(timeout=1)

    def test_serves_full_file_multi_block(self) -> None:
        _section("TFTP: multi-block transfer")
        port, shutdown, t = self._start_server()

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3.0)
        sock.sendto(self._rrq("undionly.kpxe"), ("127.0.0.1", port))

        received = bytearray()
        expected_data = self.boot_file.read_bytes()
        expected_blocks = (len(expected_data) + 511) // 512

        for block_num in range(1, expected_blocks + 1):
            try:
                data, addr = sock.recvfrom(2048)
            except socket.timeout:
                shutdown.set()
                sock.close()
                t.join(timeout=1)
                self.fail(f"Timeout waiting for block {block_num}")

            opcode = struct.unpack("!H", data[:2])[0]
            self.assertEqual(opcode, TFTP_DATA)
            self.assertEqual(struct.unpack("!H", data[2:4])[0], block_num)
            received.extend(data[4:])

            ack = struct.pack("!HH", TFTP_ACK, block_num)
            sock.sendto(ack, addr)

        self.assertEqual(bytes(received), expected_data)
        _ok(f"Full file received ({len(received)} bytes in {expected_blocks} blocks)")

        shutdown.set()
        sock.close()
        t.join(timeout=1)

    def test_rejects_unknown_file(self) -> None:
        _section("TFTP: unknown file rejected")
        port, shutdown, t = self._start_server()

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3.0)
        sock.sendto(self._rrq("unknown.bin"), ("127.0.0.1", port))

        try:
            data, _ = sock.recvfrom(2048)
        except socket.timeout:
            shutdown.set()
            sock.close()
            t.join(timeout=1)
            self.fail("No error response")

        opcode = struct.unpack("!H", data[:2])[0]
        self.assertEqual(opcode, TFTP_ERROR)
        _ok("Unknown file triggers TFTP error")

        shutdown.set()
        sock.close()
        t.join(timeout=1)

    def test_rejects_allowed_but_missing_file(self) -> None:
        _section("TFTP: allowed file but missing on disk")
        port, shutdown, t = self._start_server()

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3.0)
        sock.sendto(self._rrq("ipxe.efi"), ("127.0.0.1", port))

        try:
            data, _ = sock.recvfrom(2048)
        except socket.timeout:
            shutdown.set()
            sock.close()
            t.join(timeout=1)
            self.fail("No error response")

        opcode = struct.unpack("!H", data[:2])[0]
        self.assertEqual(opcode, TFTP_ERROR)
        _ok("Missing allowed file triggers TFTP error")

        shutdown.set()
        sock.close()
        t.join(timeout=1)

    def test_apple_mac_path_prefix_stripped(self) -> None:
        _section("TFTP: Apple PXE MAC prefix")
        port, shutdown, t = self._start_server()

        rrq = self._rrq("/01-aa-bb-cc-dd-ee-ff/undionly.kpxe")
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3.0)
        sock.sendto(rrq, ("127.0.0.1", port))

        try:
            data, _ = sock.recvfrom(2048)
        except socket.timeout:
            shutdown.set()
            sock.close()
            t.join(timeout=1)
            self.fail("No response for Apple PXE path")

        opcode = struct.unpack("!H", data[:2])[0]
        self.assertEqual(opcode, TFTP_DATA)
        _ok("Apple PXE MAC path prefix stripped correctly")

        shutdown.set()
        sock.close()
        t.join(timeout=1)

    def test_last_block_is_short(self) -> None:
        _section("TFTP: last block is short")
        port, shutdown, t = self._start_server()

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3.0)
        sock.sendto(self._rrq("undionly.kpxe"), ("127.0.0.1", port))

        expected_data = self.boot_file.read_bytes()
        expected_blocks = (len(expected_data) + 511) // 512
        last_data = b""

        for block_num in range(1, expected_blocks + 1):
            try:
                data, addr = sock.recvfrom(2048)
            except socket.timeout:
                shutdown.set()
                sock.close()
                t.join(timeout=1)
                self.fail(f"Timeout on block {block_num}")

            opcode = struct.unpack("!H", data[:2])[0]
            self.assertEqual(opcode, TFTP_DATA)
            self.assertEqual(struct.unpack("!H", data[2:4])[0], block_num)
            last_data = data[4:]

            ack = struct.pack("!HH", TFTP_ACK, block_num)
            sock.sendto(ack, addr)

        self.assertLess(len(last_data), 512)
        _ok(f"Last block is short ({len(last_data)} bytes < 512)")

        shutdown.set()
        sock.close()
        t.join(timeout=1)


# -----------------------------------------------------------------------
# HTTP integration tests
# -----------------------------------------------------------------------

class TestHTTPIntegration(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = TemporaryDirectory()
        self.boot_dir = Path(self.tmpdir.name)
        self.kernel_file = self.boot_dir / "vmlinuz-linux"
        self.kernel_file.write_bytes(b"KERNEL_" + b"x" * 10000)
        self.iso_file = self.boot_dir / "ubuntu.iso"
        self.iso_file.write_bytes(b"ISO_" + b"y" * 5000)
        self.initrd_file = self.boot_dir / "initrd.img"
        self.initrd_file.write_bytes(b"INITRD_" + b"z" * 8000)

    def tearDown(self) -> None:
        self.tmpdir.cleanup()

    def _start_server(self) -> tuple[int, threading.Event, threading.Thread]:
        from src.http_server import _http_server
        port = _find_free_port()
        shutdown = threading.Event()
        t = threading.Thread(target=_http_server, args=(port, self.boot_dir, shutdown), daemon=True)
        t.start()
        time.sleep(0.15)
        return port, shutdown, t

    def _get(self, port: int, path: str) -> tuple[int, dict[str, str], bytes]:
        import urllib.request
        req = urllib.request.Request(f"http://127.0.0.1:{port}{path}")
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, dict(resp.headers), resp.read()

    def test_serves_kernel_with_correct_type(self) -> None:
        _section("HTTP: serve kernel")
        port, shutdown, t = self._start_server()
        try:
            status, headers, body = self._get(port, "/vmlinuz-linux")
            self.assertEqual(status, 200)
            self.assertEqual(body, self.kernel_file.read_bytes())
            self.assertEqual(headers.get("Content-Type"), "application/octet-stream")
        finally:
            shutdown.set()
            t.join(timeout=1)
        _ok("Kernel served with correct MIME type")

    def test_serves_iso_with_correct_type(self) -> None:
        _section("HTTP: serve ISO")
        port, shutdown, t = self._start_server()
        try:
            status, headers, body = self._get(port, "/ubuntu.iso")
            self.assertEqual(status, 200)
            self.assertEqual(body, self.iso_file.read_bytes())
            self.assertEqual(headers.get("Content-Type"), "application/x-iso9660-image")
        finally:
            shutdown.set()
            t.join(timeout=1)
        _ok("ISO served with correct MIME type")

    def test_serves_initrd(self) -> None:
        _section("HTTP: serve initrd")
        port, shutdown, t = self._start_server()
        try:
            status, _, body = self._get(port, "/initrd.img")
            self.assertEqual(status, 200)
            self.assertEqual(body, self.initrd_file.read_bytes())
        finally:
            shutdown.set()
            t.join(timeout=1)
        _ok("Initrd served correctly")

    def test_content_length_matches_file(self) -> None:
        _section("HTTP: Content-Length")
        port, shutdown, t = self._start_server()
        try:
            status, headers, body = self._get(port, "/vmlinuz-linux")
            self.assertEqual(status, 200)
            self.assertEqual(int(headers.get("Content-Length", "0")), self.kernel_file.stat().st_size)
            self.assertEqual(len(body), self.kernel_file.stat().st_size)
        finally:
            shutdown.set()
            t.join(timeout=1)
        _ok("Content-Length matches file size")

    def test_404_for_missing_file(self) -> None:
        _section("HTTP: 404 missing file")
        port, shutdown, t = self._start_server()
        try:
            import urllib.error
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                self._get(port, "/nonexistent.iso")
            self.assertEqual(ctx.exception.code, 404)
        finally:
            shutdown.set()
            t.join(timeout=1)
        _ok("Missing file returns 404")

    def test_403_for_traversal(self) -> None:
        _section("HTTP: 403 traversal")
        port, shutdown, t = self._start_server()
        try:
            import urllib.error
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                self._get(port, "/../../../etc/passwd")
            self.assertEqual(ctx.exception.code, 403)
        finally:
            shutdown.set()
            t.join(timeout=1)
        _ok("Directory traversal blocked with 403")

    def test_404_for_root_path(self) -> None:
        _section("HTTP: 404 root path")
        port, shutdown, t = self._start_server()
        try:
            import urllib.error
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                self._get(port, "/")
            self.assertEqual(ctx.exception.code, 404)
        finally:
            shutdown.set()
            t.join(timeout=1)
        _ok("Root path returns 404")

    def test_large_file_streaming(self) -> None:
        _section("HTTP: large file streaming")
        large_file = self.boot_dir / "large.iso"
        large_file.write_bytes(b"LARGE_" + b"a" * 300 * 1024)

        port, shutdown, t = self._start_server()
        try:
            status, headers, body = self._get(port, "/large.iso")
            self.assertEqual(status, 200)
            self.assertEqual(len(body), large_file.stat().st_size)
            self.assertEqual(body, large_file.read_bytes())
        finally:
            shutdown.set()
            t.join(timeout=1)
        _ok(f"Large file ({large_file.stat().st_size} bytes) streamed correctly")

    def test_extra_path_served(self) -> None:
        _section("HTTP: extra_paths")
        from src.http_server import BootHTTPHandler
        extra_dir = Path(self.tmpdir.name) / "extra"
        extra_dir.mkdir()
        extra_file = extra_dir / "test.efi"
        extra_file.write_bytes(b"EXTRA_EFI")
        BootHTTPHandler.extra_paths = [extra_dir]

        port, shutdown, t = self._start_server()
        try:
            status, _, body = self._get(port, "/extra/test.efi")
            self.assertEqual(status, 200)
            self.assertEqual(body, b"EXTRA_EFI")
        finally:
            BootHTTPHandler.extra_paths = []
            shutdown.set()
            t.join(timeout=1)
        _ok("Extra path file served correctly")


if __name__ == "__main__":
    print()
    print(f"  {'#' * 62}")
    print(f"  #   INTEGRATION TESTS (real sockets)")
    print(f"  {'#' * 62}")
    print()
    unittest.main(verbosity=2)
