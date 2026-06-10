#!/usr/bin/env python3
"""Send a realistic PXE BOOTREQUEST to a ProxyDHCP listener on loopback.

Usage: python3 scripts/send_pxe_request.py [--mac AA:BB:CC:DD:EE:FF] [--bind-port 68]

If binding to port 68 fails (requires root), the script falls back to an
ephemeral port but still sends a proper BOOTP/DHCP packet to 127.0.0.1:4011.
"""

import argparse
import random
import socket
import struct
import sys


def mac_to_bytes(mac: str) -> bytes:
    """Convert AA:BB:CC:DD:EE:FF string to bytes."""
    return bytes(int(x, 16) for x in mac.split(":"))


def build_bootrequest(mac_bytes: bytes, xid: bytes | None = None) -> bytes:
    """Build a minimal BOOTP/DHCP DISCOVER packet with PXE option."""
    header = struct.pack(
        "!BBBB4sHH4s4s4s4s16s64s128s",
        1,  # op: BOOTREQUEST
        1,  # htype: ethernet
        6,  # hlen: mac length
        0,  # hops
        xid or random.getrandbits(32).to_bytes(4, "big"),
        0,  # secs
        0,  # flags
        b"\x00" * 4,  # ciaddr
        b"\x00" * 4,  # yiaddr
        b"\x00" * 4,  # siaddr
        b"\x00" * 4,  # giaddr
        mac_bytes + b"\x00" * 10,  # chaddr (padded to 16)
        b"\x00" * 64,  # sname
        b"\x00" * 128,  # file
    )

    cookie = b"\x63\x82\x53\x63"
    opt53 = b"\x35\x01\x01"  # Option 53: DHCPDISCOVER
    opt60 = b"\x3c" + bytes([len(b"PXEClient")]) + b"PXEClient"  # Option 60: PXEClient
    end = b"\xff"

    return header + cookie + opt53 + opt60 + end


def hexdump(data: bytes) -> str:
    """Return space-separated hex string."""
    return " ".join(f"{x:02x}" for x in data)


def main() -> None:
    p = argparse.ArgumentParser(description="Send PXE BOOTREQUEST to ProxyDHCP listener")
    p.add_argument("--mac", default="aa:bb:cc:dd:ee:ff", help="client MAC address")
    p.add_argument("--bind-port", type=int, default=0, help="bind local port (e.g. 68)")
    p.add_argument("--target", default="127.0.0.1", help="target host")
    p.add_argument("--port", type=int, default=4011, help="target port")
    args = p.parse_args()

    try:
        mac_bytes = mac_to_bytes(args.mac)
    except Exception:
        print("[!] Invalid MAC format. Use AA:BB:CC:DD:EE:FF")
        sys.exit(1)

    pkt = build_bootrequest(mac_bytes)

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(2.0)

    if args.bind_port:
        try:
            s.bind(("127.0.0.1", args.bind_port))
            print(f"[*] Bound to 127.0.0.1:{args.bind_port}")
        except PermissionError:
            print(f"[!] Permission denied binding to port {args.bind_port}; continuing without bind")
        except OSError as e:
            print(f"[!] Bind failed: {e}; continuing without bind")

    print(f"[*] Sending {len(pkt)} bytes to {args.target}:{args.port} (mac={args.mac})")
    s.sendto(pkt, (args.target, args.port))

    try:
        data, addr = s.recvfrom(4096)
        print(f"[+] Received {len(data)} bytes from {addr}")
        print(hexdump(data[:240]))
    except socket.timeout:
        print("[!] No reply received (timeout)")

    s.close()


if __name__ == "__main__":
    main()
