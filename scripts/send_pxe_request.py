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
import time


def mac_to_bytes(mac):
    return bytes(int(x, 16) for x in mac.split(":"))


def build_bootrequest(mac_bytes, xid=None):
    # BOOTP header fields
    op = 1
    htype = 1
    hlen = 6
    hops = 0
    xid = xid or random.getrandbits(32).to_bytes(4, "big")
    secs = 0
    flags = 0
    ciaddr = b"\x00\x00\x00\x00"
    yiaddr = b"\x00\x00\x00\x00"
    siaddr = b"\x00\x00\x00\x00"
    giaddr = b"\x00\x00\x00\x00"

    chaddr = mac_bytes + b"\x00" * (16 - len(mac_bytes))
    sname = b"\x00" * 64
    file = b"\x00" * 128

    # Pack fixed 236-byte BOOTP header
    header = struct.pack(
        "!BBBB4sHH4s4s4s4s16s64s128s",
        op,
        htype,
        hlen,
        hops,
        xid,
        secs,
        flags,
        ciaddr,
        yiaddr,
        siaddr,
        giaddr,
        chaddr,
        sname,
        file,
    )

    # Magic cookie + options
    cookie = b"\x63\x82\x53\x63"
    # Option 53 = DHCP Message Type (1 = DHCPDISCOVER)
    opt53 = b"\x35\x01\x01"
    # Option 60 = Vendor Class Identifier = PXEClient
    opt60 = b"\x3c" + bytes([len(b"PXEClient")]) + b"PXEClient"
    # End option
    end = b"\xff"

    return header + cookie + opt53 + opt60 + end


def hexdump(b):
    return " ".join(f"{x:02x}" for x in b)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--mac", default="aa:bb:cc:dd:ee:ff")
    p.add_argument("--bind-port", type=int, default=0, help="bind local port (e.g. 68)")
    p.add_argument("--target", default="127.0.0.1", help="target host")
    p.add_argument("--port", type=int, default=4011, help="target port")
    args = p.parse_args()

    mac = args.mac
    try:
        mac_bytes = mac_to_bytes(mac)
    except Exception:
        print("Invalid MAC format. Use AA:BB:CC:DD:EE:FF")
        sys.exit(1)

    pkt = build_bootrequest(mac_bytes)

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(2.0)

    bound = False
    if args.bind_port:
        try:
            s.bind(("127.0.0.1", args.bind_port))
            bound = True
            print(f"Bound to 127.0.0.1:{args.bind_port}")
        except PermissionError:
            print(f"Permission denied binding to port {args.bind_port}; continuing without bind")
        except OSError as e:
            print(f"Bind failed: {e}; continuing without bind")

    print(f"Sending {len(pkt)} bytes to {args.target}:{args.port} (mac={mac})")
    s.sendto(pkt, (args.target, args.port))

    # Try to receive reply (ProxyDHCP may send to port 68); only works if bound
    try:
        data, addr = s.recvfrom(4096)
        print(f"Received {len(data)} bytes from {addr}")
        print(hexdump(data[:240]))
    except socket.timeout:
        print("No reply received (timeout)")

    s.close()


if __name__ == "__main__":
    main()
