"""PXE boot server components.

Three concurrent listeners handle the PXE boot chain:

1. ProxyDHCP (UDP 4011) - Tells PXE clients where to find the bootloader
2. TFTP (UDP 69/6969) - Serves the initial bootstrap loader (undionly.kpxe)
3. HTTP (TCP 8080) - Streams heavy payloads (kernel, initrd, squashfs) via iPXE

All three run in a shared ThreadPoolExecutor so they don't block each other.
"""

import os
import socket
import struct
import threading
from concurrent.futures import ThreadPoolExecutor
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path


# ---------------------------------------------------------------------------
# ProxyDHCP
# ---------------------------------------------------------------------------

def parse_packet(data: bytes, addr: tuple[str, int]) -> dict[str, object] | None:
    """Parse a DHCP/BOOTP packet and return PXE client info if valid."""
    if len(data) < 240:
        return None

    if data[0] != 1:  # BOOTREQUEST
        return None

    transaction_id = data[4:8]
    client_mac = data[28:34]
    mac_readable = ":".join(f"{b:02x}" for b in client_mac)

    if data[236:240] != b"\x63\x82\x53\x63":  # DHCP magic cookie
        return None

    options_bytes = data[240:]
    cursor = 0

    while cursor < len(options_bytes):
        tag = options_bytes[cursor]
        if tag == 255:
            break
        if cursor + 1 >= len(options_bytes):
            break
        length = options_bytes[cursor + 1]
        value = options_bytes[cursor + 2 : cursor + 2 + length]

        if tag == 60 and b"PXEClient" in value:
            print(f"[+] PXE request from {mac_readable} (TxID={transaction_id.hex()})")
            return {
                "client_address": addr,
                "transaction_id": transaction_id,
                "mac_raw": client_mac,
                "mac_readable": mac_readable,
            }

        cursor += 2 + length

    return None


def send_proxy_reply(sock: socket.socket, client_info: dict[str, object]) -> None:
    """Build and send a ProxyDHCP reply with boot file info."""
    print(f"[*] Replying to {client_info['mac_readable']}...")

    packet = bytearray(240)

    packet[0] = 2  # BOOTREPLY
    packet[1] = 1  # htype: ethernet
    packet[2] = 6  # hlen
    packet[3] = 0  # hops

    packet[4:8] = client_info["transaction_id"]
    packet[28:34] = client_info["mac_raw"]

    packet[236:240] = b"\x63\x82\x53\x63"

    packet += b"\x35\x01\x05"  # Option 53: DHCPACK
    packet += b"\x3c\x09PXEClient"  # Option 60

    boot_file = b"undionly.kpxe\x00"
    packet += b"\x43" + bytes([len(boot_file)]) + boot_file  # Option 67

    packet += b"\xff"  # End

    target_address = (client_info["client_address"][0], 68)
    sock.sendto(packet, target_address)
    print(f"[+] Sent {len(packet)} bytes to {target_address}")


def _proxydhcp_listener(port: int) -> None:
    """UDP listener for ProxyDHCP requests."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("", port))
        print(f"[*] ProxyDHCP listening on UDP {port}")

        while True:
            data, addr = s.recvfrom(2048)
            client_info = parse_packet(data, addr)
            if client_info:
                send_proxy_reply(s, client_info)


# ---------------------------------------------------------------------------
# TFTP
# ---------------------------------------------------------------------------

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


def _tftp_send_file(sock: socket.socket, file_path: Path, addr: tuple[str, int]) -> None:
    """Send a file to a TFTP client in 512-byte DATA blocks."""
    try:
        file_data = file_path.read_bytes()
    except OSError as e:
        print(f"[!] TFTP: failed to read {file_path.name}: {e}")
        error_pkt = struct.pack("!HH", TFTP_ERROR, 1) + b"File not found\x00"
        sock.sendto(error_pkt, addr)
        return

    block_num = 1
    offset = 0

    while True:
        chunk = file_data[offset : offset + TFTP_BLOCK_SIZE]
        data_pkt = struct.pack("!HH", TFTP_DATA, block_num) + chunk
        sock.sendto(data_pkt, addr)

        # Wait for ACK
        try:
            ack_data, _ = sock.recvfrom(512)
        except socket.timeout:
            print(f"[!] TFTP: ACK timeout for block {block_num}")
            return

        if len(ack_data) < 4:
            return
        ack_opcode, ack_block = struct.unpack("!HH", ack_data[:4])
        if ack_opcode != TFTP_ACK or ack_block != block_num:
            print(f"[!] TFTP: unexpected ACK (got {ack_opcode}/{ack_block}, expected {TFTP_ACK}/{block_num})")
            return

        offset += TFTP_BLOCK_SIZE
        block_num += 1

        if len(chunk) < TFTP_BLOCK_SIZE:
            break  # last block sent


def _tftp_listener(port: int, boot_dir: Path) -> None:
    """UDP listener for TFTP Read Requests."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("", port))
        s.settimeout(1.0)
        print(f"[*] TFTP listening on UDP {port} (root: {boot_dir})")

        while True:
            try:
                data, addr = s.recvfrom(2048)
            except socket.timeout:
                continue

            filename = parse_tftp_rrq(data)
            if not filename:
                continue

            filename_bytes = filename.encode("ascii")
            if filename_bytes not in ALLOWED_BOOT_FILES:
                print(f"[!] TFTP: rejecting unknown file '{filename}' from {addr}")
                error_pkt = struct.pack("!HH", TFTP_ERROR, 2) + b"Access denied\x00"
                s.sendto(error_pkt, addr)
                continue

            file_path = boot_dir / filename
            if not file_path.exists():
                print(f"[!] TFTP: {filename} not found at {file_path}")
                error_pkt = struct.pack("!HH", TFTP_ERROR, 1) + b"File not found\x00"
                s.sendto(error_pkt, addr)
                continue

            print(f"[+] TFTP: serving {filename} to {addr}")
            _tftp_send_file(s, file_path, addr)


# ---------------------------------------------------------------------------
# HTTP Image Streamer
# ---------------------------------------------------------------------------

MIME_TYPES = {
    ".kernel": "application/octet-stream",
    ".bzImage": "application/octet-stream",
    ".vmlinuz": "application/octet-stream",
    ".initrd": "application/octet-stream",
    ".img": "application/octet-stream",
    ".squashfs": "application/octet-stream",
    ".iso": "application/x-iso9660-image",
    ".kpxe": "application/octet-stream",
    ".efi": "application/octet-stream",
    ".pxe": "application/octet-stream",
    ".cfg": "text/plain",
    ".conf": "text/plain",
}


class BootHTTPHandler(BaseHTTPRequestHandler):
    """Serves boot assets from the configured boot directory."""

    boot_root: Path = Path(".")

    def do_GET(self) -> None:
        path = self.path.lstrip("/")
        if not path:
            self.send_error(404)
            return

        # Prevent directory traversal
        full_path = (self.boot_root / path).resolve()
        if not str(full_path).startswith(str(self.boot_root.resolve())):
            self.send_error(403)
            return

        if not full_path.exists() or full_path.is_dir():
            self.send_error(404)
            return

        try:
            data = full_path.read_bytes()
            ext = full_path.suffix.lower()
            content_type = MIME_TYPES.get(ext, "application/octet-stream")
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(data)
        except OSError as e:
            print(f"[!] HTTP: error serving {path}: {e}")
            self.send_error(500)

    def log_message(self, format: str, *args: object) -> None:
        print(f"[+] HTTP {args[0]}")


def _http_server(port: int, boot_root: Path) -> None:
    """Start the HTTP file server."""
    BootHTTPHandler.boot_root = boot_root
    server = HTTPServer(("0.0.0.0", port), BootHTTPHandler)
    print(f"[*] HTTP listening on TCP {port} (root: {boot_root})")
    server.serve_forever()


# ---------------------------------------------------------------------------
# iPXE Boot Config Generator
# ---------------------------------------------------------------------------

_INITRD_EXTENSIONS = frozenset({".initrd", ".img"})
_INITRD_NAMES = frozenset({"initrd", "initramfs"})
_IGNORED_NAMES = frozenset({"boot.cfg", ".DS_Store", "undionly.kpxe", "ipxe.efi"})


def _is_initrd(path: Path) -> bool:
    """Check if a file looks like an initrd/initramfs."""
    ext = path.suffix.lower()
    if ext in _INITRD_EXTENSIONS:
        return True
    name_lower = path.name.lower()
    return any(pattern in name_lower for pattern in _INITRD_NAMES)


def _is_kernel(path: Path) -> bool:
    """Check if a file looks like a bootable kernel."""
    ext = path.suffix.lower()
    if ext in (".kernel", ".vmlinuz", ".bzImage", ""):
        return True
    name_lower = path.name.lower()
    if name_lower.startswith("vmlinuz") or name_lower.startswith("bzimage"):
        return True
    return False


def _label_from_filename(name: str) -> str:
    """Turn 'arch-linux-2024.01.iso' into 'Arch Linux'."""
    label = name.rsplit(".", 1)[0]  # strip extension
    label = label.replace("-", " ").replace("_", " ")
    # Title-case but keep short acronyms uppercase
    words = []
    for w in label.split():
        if len(w) <= 3 and w.isalnum():
            words.append(w.upper())
        else:
            words.append(w.capitalize())
    return " ".join(words)


def generate_boot_config(boot_dir: Path) -> Path:
    """Scan boot_dir for bootable images and write an iPXE menu script.

    Detects three patterns:
        - .iso files           -> booted via sanboot (direct ISO boot)
        - vmlinuz + initrd     -> booted via kernel/initrd direct boot
        - standalone kernels   -> booted via kernel-only direct boot

    Writes boot.cfg to boot_dir and returns its path.
    """
    iso_files: list[str] = []
    kernel_initrd_pairs: list[tuple[str, str]] = []
    standalone_kernels: list[str] = []

    # Collect all relevant files (skip ignored)
    all_files: dict[str, Path] = {}
    for f in sorted(boot_dir.iterdir()):
        if f.is_file() and f.name not in _IGNORED_NAMES:
            all_files[f.name.lower()] = f

    # Pass 1: ISOs are unambiguous
    claimed: set[str] = set()
    for name, path in all_files.items():
        if path.suffix.lower() == ".iso":
            iso_files.append(path.name)
            claimed.add(name)

    # Pass 2: Identify initrds
    initrds: dict[str, str] = {}  # base_name -> original filename
    for name, path in all_files.items():
        if name in claimed:
            continue
        if _is_initrd(path):
            # Use stem (without common suffixes) as the pairing key
            base = path.stem.lower()
            # Strip common prefixes/suffixes for pairing
            for prefix in ("initramfs-", "initrd-"):
                if base.startswith(prefix):
                    base = base[len(prefix):]
                    break
            for suffix in ("-initrd", "-initramfs", "_initrd", "_initramfs"):
                if base.endswith(suffix):
                    base = base[: -len(suffix)]
                    break
            initrds[base] = path.name
            claimed.add(name)

    # Pass 3: Identify kernels and pair with initrds
    for name, path in all_files.items():
        if name in claimed:
            continue
        if _is_kernel(path):
            base = path.stem.lower()
            # Strip common prefixes for pairing: "vmlinuz-" -> ""
            for prefix in ("vmlinuz-", "bzimage-"):
                if base.startswith(prefix):
                    base = base[len(prefix):]
                    break

            if base in initrds:
                kernel_initrd_pairs.append((path.name, initrds.pop(base)))
                claimed.add(name)
            else:
                standalone_kernels.append(path.name)
                claimed.add(name)

    # Remaining unclaimed .img files become standalone
    for name, path in all_files.items():
        if name not in claimed and path.suffix.lower() in (".img", ".kernel", ".vmlinuz", ".bzImage"):
            standalone_kernels.append(path.name)
            claimed.add(name)

    # Build iPXE script
    script = "#!ipxe\n"
    script += "# Auto-generated by Servings. Do not edit.\n"
    script += "# Reboot the server to regenerate from current disk images.\n\n"
    script += "set timeout 30000\n\n"
    script += ":menu\n"
    script += "menu Servings PXE Boot Server\n"

    has_items = bool(iso_files or kernel_initrd_pairs or standalone_kernels)

    if iso_files:
        script += "item --gap -- Disk Images\n"
        for iso in iso_files:
            key = iso.replace(" ", "_").replace(".", "_")
            script += f"item {key}    {_label_from_filename(iso)}\n"

    if kernel_initrd_pairs:
        script += "item --gap -- Kernel + Initrd\n"
        for kern, initrd in kernel_initrd_pairs:
            key = kern.replace(" ", "_").replace(".", "_")
            script += f"item {key}    {_label_from_filename(kern)}\n"

    if standalone_kernels:
        script += "item --gap -- Kernels\n"
        for kern in standalone_kernels:
            key = kern.replace(" ", "_").replace(".", "_")
            script += f"item {key}    {_label_from_filename(kern)}\n"

    if not has_items:
        script += "item --gap -- No bootable images found\n"
        script += "item --gap -- Place .iso, .vmlinuz, or .kernel files here\n"
        script += "goto boot_none\n"

    script += "\nchoose target || goto boot_none\n\n"

    # Emit boot handlers for ISOs
    for iso in iso_files:
        key = iso.replace(" ", "_").replace(".", "_")
        script += f":{key}\n"
        script += f"set boot-path /{iso}\n"
        script += "sanboot ${boot-path} || goto failed\n\n"

    # Emit boot handlers for kernel+initrd pairs
    for kern, initrd in kernel_initrd_pairs:
        key = kern.replace(" ", "_").replace(".", "_")
        script += f":{key}\n"
        script += f"kernel /{kern} || goto failed\n"
        script += f"initrd /{initrd} || goto failed\n"
        script += "boot || goto failed\n\n"

    # Emit boot handlers for standalone kernels
    for kern in standalone_kernels:
        key = kern.replace(" ", "_").replace(".", "_")
        script += f":{key}\n"
        script += f"kernel /{kern} || goto failed\n"
        script += "boot || goto failed\n\n"

    script += ":boot_none\n"
    script += "echo No bootable images found.\n"
    script += "echo Place .iso, .vmlinuz, or .kernel files in the boot directory.\n"
    script += "sleep 5\n"
    script += "goto menu\n\n"

    script += ":failed\n"
    script += "echo Boot failed. Returning to menu in 5 seconds...\n"
    script += "sleep 5\n"
    script += "goto menu\n"

    cfg_path = boot_dir / "boot.cfg"
    cfg_path.write_text(script)
    print(f"[+] Generated boot.cfg ({len(iso_files)} ISOs, {len(kernel_initrd_pairs)} pairs, {len(standalone_kernels)} kernels)")
    return cfg_path


# ---------------------------------------------------------------------------
# Thread Orchestration
# ---------------------------------------------------------------------------

def serve(
    port: int = 4011,
    tftp_port: int = 6969,
    http_port: int = 8080,
    boot_dir: str = ".",
) -> None:
    """Start all three PXE boot servers concurrently.

    Spawns ProxyDHCP, TFTP, and HTTP into a shared thread pool.
    All three must be running for a full PXE boot to succeed.

    Port notes:
        - ProxyDHCP: 4011 is standard for ProxyDHCP (not 67/68 which need root)
        - TFTP: 6969 default because 69 needs root; use 69 on rooted devices
        - HTTP: 8080 is standard for alt HTTP; iPXE hits this for heavy payloads
    """
    root = Path(boot_dir).resolve()
    if not root.exists():
        print(f"[!] Boot directory does not exist: {root}")
        raise SystemExit(1)

    # Generate iPXE menu from whatever's in the boot directory
    try:
        generate_boot_config(root)
    except OSError as e:
        print(f"[!] Could not generate boot.cfg: {e}")

    print(f"[*] Servings PXE Boot Server")
    print(f"    ProxyDHCP : UDP {port}")
    print(f"    TFTP      : UDP {tftp_port}")
    print(f"    HTTP      : TCP {http_port}")
    print(f"    Boot dir  : {root}")
    print()

    executor = ThreadPoolExecutor(max_workers=6)
    executor.submit(_proxydhcp_listener, port)
    executor.submit(_tftp_listener, tftp_port, root)
    executor.submit(_http_server, http_port, root)

    try:
        while True:
            pass
    except KeyboardInterrupt:
        print("\n[*] Shutting down...")
        executor.shutdown(wait=False, cancel_futures=True)
