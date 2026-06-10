"""Unit tests for TFTP and HTTP boot server components."""

import io
import socket
import struct
import sys
import tempfile
import unittest
from http.server import HTTPServer
from pathlib import Path
from threading import Thread
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.logic import (
    BootHTTPHandler,
    TFTP_ACK,
    TFTP_BLOCK_SIZE,
    TFTP_DATA,
    TFTP_ERROR,
    TFTP_RRQ,
    _label_from_filename,
    generate_boot_config,
    parse_tftp_rrq,
)


def _section(title: str) -> None:
    print(f"\n  {'=' * 60}")
    print(f"  {title}")
    print(f"  {'=' * 60}")


def _ok(msg: str) -> None:
    print(f"  [+] {msg}")


def _info(msg: str) -> None:
    print(f"  [*] {msg}")


def _make_rrq(filename: str) -> bytes:
    """Build a minimal TFTP Read Request packet."""
    return struct.pack("!H", TFTP_RRQ) + filename.encode() + b"\x00octet\x00"


# -----------------------------------------------------------------------
# TFTP Parser Tests
# -----------------------------------------------------------------------

class TestParseTftpRRQ(unittest.TestCase):
    def test_valid_rrq(self) -> None:
        _section("parse_tftp_rrq: valid request")
        data = _make_rrq("undionly.kpxe")
        result = parse_tftp_rrq(data)
        self.assertEqual(result, "undionly.kpxe")
        _ok("Parsed filename correctly")

    def test_valid_rrq_ipxe(self) -> None:
        _section("parse_tftp_rrq: ipxe.efi")
        data = _make_rrq("ipxe.efi")
        result = parse_tftp_rrq(data)
        self.assertEqual(result, "ipxe.efi")
        _ok("Parsed ipxe.efi correctly")

    def test_short_packet_returns_none(self) -> None:
        _section("parse_tftp_rrq: short packet")
        result = parse_tftp_rrq(b"\x00")
        self.assertIsNone(result)
        _ok("Short packet returns None")

    def test_non_rrq_returns_none(self) -> None:
        _section("parse_tftp_rrq: non-RRQ opcode")
        data = struct.pack("!H", TFTP_DATA) + b"test"
        result = parse_tftp_rrq(data)
        self.assertIsNone(result)
        _ok("Non-RRQ opcode returns None")

    def test_missing_null_terminator(self) -> None:
        _section("parse_tftp_rrq: no null terminator")
        data = struct.pack("!H", TFTP_RRQ) + b"no-null-here"
        result = parse_tftp_rrq(data)
        self.assertIsNone(result)
        _ok("Missing null returns None")


# -----------------------------------------------------------------------
# HTTP Handler Tests
# -----------------------------------------------------------------------

class TestBootHTTPHandler(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp()
        self.boot_root = Path(self.tmpdir)
        BootHTTPHandler.boot_root = self.boot_root

    def tearDown(self) -> None:
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _make_handler(self, method: str, path: str, body: bytes = b"") -> BootHTTPHandler:
        """Create a handler with a mock request."""
        handler = BootHTTPHandler.__new__(BootHTTPHandler)
        handler.path = path
        handler.command = method
        handler.requestline = f"{method} {path} HTTP/1.1"
        handler.request_version = "HTTP/1.1"
        handler.request = MagicMock()
        handler.client_address = ("127.0.0.1", 12345)
        handler.wfile = io.BytesIO()
        handler.rfile = io.BytesIO()
        handler.headers = {}
        handler.close = MagicMock()
        return handler

    def test_serves_file(self) -> None:
        _section("BootHTTPHandler: serve file")
        (self.boot_root / "vmlinuz").write_bytes(b"fake-kernel-data")
        handler = self._make_handler("GET", "/vmlinuz")
        handler.do_GET()
        output = handler.wfile.getvalue()
        self.assertIn(b"fake-kernel-data", output)
        _ok("Served file content correctly")

    def test_404_for_missing_file(self) -> None:
        _section("BootHTTPHandler: missing file")
        handler = self._make_handler("GET", "/nonexistent.iso")
        handler.do_GET()
        output = handler.wfile.getvalue()
        self.assertIn(b"404", output)
        _ok("Returned 404 for missing file")

    def test_404_for_empty_path(self) -> None:
        _section("BootHTTPHandler: empty path")
        handler = self._make_handler("GET", "/")
        handler.do_GET()
        output = handler.wfile.getvalue()
        self.assertIn(b"404", output)
        _ok("Returned 404 for empty path")

    def test_directory_traversal_blocked(self) -> None:
        _section("BootHTTPHandler: directory traversal")
        handler = self._make_handler("GET", "/../../../etc/passwd")
        handler.do_GET()
        output = handler.wfile.getvalue()
        self.assertIn(b"403", output)
        _ok("Blocked directory traversal")

    def test_serves_initrd(self) -> None:
        _section("BootHTTPHandler: initrd")
        (self.boot_root / "initrd.img").write_bytes(b"fake-initrd")
        handler = self._make_handler("GET", "/initrd.img")
        handler.do_GET()
        output = handler.wfile.getvalue()
        self.assertIn(b"fake-initrd", output)
        _ok("Served initrd correctly")


# -----------------------------------------------------------------------
# TFTP File Send Tests
# -----------------------------------------------------------------------

class TestTftpSendFile(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp()
        self.boot_root = Path(self.tmpdir)

    def tearDown(self) -> None:
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_send_small_file(self) -> None:
        """Test sending a file smaller than one TFTP block."""
        from src.logic import _tftp_send_file

        _section("TFTP send: small file")
        test_file = self.boot_root / "test.kpxe"
        content = b"hello-boot"
        test_file.write_bytes(content)

        # Create a mock socket that records sent data
        mock_sock = MagicMock()
        # First recvfrom returns an ACK for block 1
        ack_pkt = struct.pack("!HH", TFTP_ACK, 1)
        mock_sock.recvfrom.return_value = (ack_pkt, ("127.0.0.1", 1234))

        _tftp_send_file(mock_sock, test_file, ("127.0.0.1", 1234))

        # Verify DATA packet was sent
        mock_sock.sendto.assert_called_once()
        sent_data = mock_sock.sendto.call_args[0][0]
        opcode, block = struct.unpack("!HH", sent_data[:4])
        self.assertEqual(opcode, TFTP_DATA)
        self.assertEqual(block, 1)
        self.assertEqual(sent_data[4:], content)
        _ok(f"Sent {len(content)} bytes in 1 block")

    def test_send_large_file_multi_block(self) -> None:
        """Test sending a file larger than 512 bytes."""
        from src.logic import _tftp_send_file

        _section("TFTP send: multi-block file")
        test_file = self.boot_root / "test.kpxe"
        content = b"x" * 1500  # 3 blocks needed
        test_file.write_bytes(content)

        mock_sock = MagicMock()
        # Return ACKs for blocks 1, 2, 3
        mock_sock.recvfrom.side_effect = [
            (struct.pack("!HH", TFTP_ACK, 1), ("127.0.0.1", 1234)),
            (struct.pack("!HH", TFTP_ACK, 2), ("127.0.0.1", 1234)),
            (struct.pack("!HH", TFTP_ACK, 3), ("127.0.0.1", 1234)),
        ]

        _tftp_send_file(mock_sock, test_file, ("127.0.0.1", 1234))

        self.assertEqual(mock_sock.sendto.call_count, 3)
        _ok("Sent 1500 bytes in 3 blocks")

    def test_missing_file_sends_error(self) -> None:
        """Test that a missing file sends an ERROR packet."""
        from src.logic import _tftp_send_file

        _section("TFTP send: missing file")
        missing = self.boot_root / "nope.kpxe"

        mock_sock = MagicMock()

        _tftp_send_file(mock_sock, missing, ("127.0.0.1", 1234))

        mock_sock.sendto.assert_called_once()
        sent_data = mock_sock.sendto.call_args[0][0]
        opcode, error_code = struct.unpack("!HH", sent_data[:4])
        self.assertEqual(opcode, TFTP_ERROR)
        _ok("Sent ERROR packet for missing file")


# -----------------------------------------------------------------------
# Boot Config Generator Tests
# -----------------------------------------------------------------------

class TestLabelFromFilename(unittest.TestCase):
    def test_iso_label(self) -> None:
        _section("_label_from_filename: ISO")
        result = _label_from_filename("arch-linux-2024.01.iso")
        self.assertEqual(result, "Arch Linux 2024.01")
        _ok(f"'arch-linux-2024.01.iso' -> '{result}'")

    def test_kernel_label(self) -> None:
        _section("_label_from_filename: kernel")
        result = _label_from_filename("vmlinuz-linux")
        self.assertEqual(result, "Vmlinuz Linux")
        _ok(f"'vmlinuz-linux' -> '{result}'")

    def test_acronym_preserved(self) -> None:
        _section("_label_from_filename: acronym")
        result = _label_from_filename("fedora-kde-live.iso")
        self.assertEqual(result, "Fedora KDE Live")
        _ok(f"'fedora-kde-live.iso' -> '{result}'")


class TestGenerateBootConfig(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp()
        self.boot_root = Path(self.tmpdir)

    def tearDown(self) -> None:
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_generates_from_isos(self) -> None:
        _section("generate_boot_config: ISOs")
        (self.boot_root / "arch-linux.iso").write_bytes(b"x")
        (self.boot_root / "ubuntu-22.04.iso").write_bytes(b"x")
        cfg_path = generate_boot_config(self.boot_root)
        self.assertTrue(cfg_path.exists())
        content = cfg_path.read_text()
        self.assertIn("arch-linux.iso", content)
        self.assertIn("ubuntu-22.04.iso", content)
        self.assertIn("sanboot", content)
        _ok(f"Generated boot.cfg with 2 ISOs ({len(content)} bytes)")

    def test_generates_from_kernel_initrd_pairs(self) -> None:
        _section("generate_boot_config: kernel+initrd pairs")
        (self.boot_root / "vmlinuz-linux").write_bytes(b"k")
        (self.boot_root / "initramfs-linux.img").write_bytes(b"i")
        cfg_path = generate_boot_config(self.boot_root)
        content = cfg_path.read_text()
        self.assertIn("vmlinuz-linux", content)
        self.assertIn("initramfs-linux.img", content)
        self.assertIn("kernel /vmlinuz-linux", content)
        self.assertIn("initrd /initramfs-linux.img", content)
        _ok("Generated boot.cfg with kernel+initrd pair")

    def test_empty_directory(self) -> None:
        _section("generate_boot_config: empty dir")
        cfg_path = generate_boot_config(self.boot_root)
        content = cfg_path.read_text()
        self.assertIn("No bootable images found", content)
        _ok("Empty directory produces placeholder menu")

    def test_ignores_boot_cfg_and_bootloaders(self) -> None:
        _section("generate_boot_config: ignored files")
        (self.boot_root / "boot.cfg").write_bytes(b"old")
        (self.boot_root / "undionly.kpxe").write_bytes(b"x")
        (self.boot_root / "ipxe.efi").write_bytes(b"x")
        cfg_path = generate_boot_config(self.boot_root)
        content = cfg_path.read_text()
        self.assertIn("No bootable images found", content)
        self.assertNotIn("boot.cfg", content.split("item")[-1] if "item" in content else "")
        _ok("Ignored boot.cfg and bootloader files")

    def test_mixed_content(self) -> None:
        _section("generate_boot_config: mixed")
        (self.boot_root / "arch-linux.iso").write_bytes(b"x")
        (self.boot_root / "vmlinuz-linux").write_bytes(b"k")
        (self.boot_root / "initramfs-linux.img").write_bytes(b"i")
        cfg_path = generate_boot_config(self.boot_root)
        content = cfg_path.read_text()
        self.assertIn("arch-linux.iso", content)
        self.assertIn("vmlinuz-linux", content)
        self.assertIn("Disk Images", content)
        self.assertIn("Kernel + Initrd", content)
        _ok("Mixed ISOs and kernels generate correct sections")


if __name__ == "__main__":
    print()
    print(f"  {'#' * 62}")
    print(f"  #   TFTP & HTTP SERVER COMPONENT TESTS")
    print(f"  {'#' * 62}")
    print()
    unittest.main(verbosity=2)
