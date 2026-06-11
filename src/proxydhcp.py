"""ProxyDHCP server — intercepts PXE client requests and directs them to the bootloader."""

import socket
import struct


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
        s.settimeout(1.0)
        print(f"[*] ProxyDHCP listening on UDP {port}")

        while True:
            try:
                data, addr = s.recvfrom(2048)
            except socket.timeout:
                continue
            client_info = parse_packet(data, addr)
            if client_info:
                send_proxy_reply(s, client_info)
