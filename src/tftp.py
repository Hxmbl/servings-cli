"""TFTP server — serves the bootstrap loader (undionly.kpxe / ipxe.efi) to PXE clients."""

import selectors
import socket
import struct
import threading
from pathlib import Path


TFTP_RRQ = 1
TFTP_DATA = 3
TFTP_ACK = 4
TFTP_ERROR = 5
TFTP_BLOCK_SIZE = 512

ALLOWED_BOOT_FILES = frozenset({b"undionly.kpxe", b"ipxe.efi"})


def parse_tftp_rrq(data: bytes) -> str | None:
    """Extract filename from a TFTP Read Request (RRQ) packet.

    RRQ format: [opcode:2][filename:N][0][mode:N][0]
    Returns the filename string, or None if malformed.
    """
    if len(data) < 4:
        return None
    opcode = struct.unpack("!H", data[:2])[0]
    if opcode != TFTP_RRQ:
        return None

    null_pos = data.find(b"\x00", 2)
    if null_pos == -1:
        return None
    return data[2:null_pos].decode("ascii", errors="replace")


def _tftp_send_next_block(sock: socket.socket, addr: tuple[str, int], state: dict) -> bool:
    """Send next DATA block for an active transfer. Returns True if transfer is complete (last block)."""
    file_data = state["file_data"]
    block_num = state["block_num"] + 1
    offset = state["offset"]

    chunk = file_data[offset : offset + TFTP_BLOCK_SIZE]
    data_pkt = struct.pack("!HH", TFTP_DATA, block_num) + chunk
    sock.sendto(data_pkt, addr)

    state["block_num"] = block_num
    state["offset"] = offset + len(chunk)

    return len(chunk) < TFTP_BLOCK_SIZE


def _tftp_listener(port: int, boot_dir: Path, shutdown: threading.Event) -> None:
    """UDP listener for TFTP Read Requests with support for concurrent transfers."""
    sel = selectors.DefaultSelector()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("", port))
    sock.setblocking(False)
    sel.register(sock, selectors.EVENT_READ)

    print(f"[*] TFTP listening on UDP {port} (root: {boot_dir})")

    # Active transfers: client_addr -> {file_data: bytes, block_num: int, offset: int}
    transfers: dict[tuple[str, int], dict] = {}

    while not shutdown.is_set():
        events = sel.select(timeout=1.0)

        for _key, _mask in events:
            while True:
                try:
                    data, addr = sock.recvfrom(2048)
                except BlockingIOError:
                    break

                if addr in transfers:
                    state = transfers[addr]
                    if len(data) < 4:
                        del transfers[addr]
                        continue
                    opcode = struct.unpack("!H", data[:2])[0]
                    if opcode != TFTP_ACK:
                        del transfers[addr]
                        continue
                    ack_block = struct.unpack("!H", data[2:4])[0]
                    if ack_block != state["block_num"]:
                        del transfers[addr]
                        continue
                    done = _tftp_send_next_block(sock, addr, state)
                    if done:
                        del transfers[addr]
                else:
                    filename = parse_tftp_rrq(data)
                    if not filename:
                        continue

                    filename_bytes = filename.encode("ascii")
                    if filename_bytes not in ALLOWED_BOOT_FILES:
                        print(f"[!] TFTP: rejecting unknown file '{filename}' from {addr}")
                        error_pkt = struct.pack("!HH", TFTP_ERROR, 2) + b"Access denied\x00"
                        sock.sendto(error_pkt, addr)
                        continue

                    file_path = boot_dir / filename
                    if not file_path.exists():
                        print(f"[!] TFTP: {filename} not found at {file_path}")
                        error_pkt = struct.pack("!HH", TFTP_ERROR, 1) + b"File not found\x00"
                        sock.sendto(error_pkt, addr)
                        continue

                    print(f"[+] TFTP: serving {filename} to {addr}")
                    try:
                        file_data = file_path.read_bytes()
                    except OSError as e:
                        print(f"[!] TFTP: failed to read {file_path.name}: {e}")
                        error_pkt = struct.pack("!HH", TFTP_ERROR, 1) + b"File not found\x00"
                        sock.sendto(error_pkt, addr)
                        continue

                    state: dict = {"file_data": file_data, "block_num": 0, "offset": 0}
                    done = _tftp_send_next_block(sock, addr, state)
                    if not done:
                        transfers[addr] = state
