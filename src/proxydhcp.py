"""ProxyDHCP server — intercepts PXE client requests and directs them to the bootloader.

Non-root mode (port 4011): only responds to PXE clients after Android's DHCP assigns an IP.
Root mode (port 67): full DHCP server that replaces Android's dnsmasq entirely.

The non-root path is limited — Android's DHCP doesn't advertise PXE options,
so the PC never contacts port 4011. Root mode is required for USB tethering PXE.
"""

import socket
import struct
import threading


def parse_packet(data: bytes, addr: tuple[str, int]) -> dict[str, object] | None:
    """Parse a DHCP/BOOTP packet and return PXE client info if valid.

    Returns a dict with client_address, transaction_id, mac_raw, mac_readable.
    Returns None if the packet isn't a valid PXE request.
    """
    if len(data) < 240:
        return None

    if data[0] != 1:  # BOOTREQUEST — client → server
        return None

    transaction_id = data[4:8]
    client_mac = data[28:34]
    mac_readable = ":".join(f"{b:02x}" for b in client_mac)

    # DHCP magic cookie marks the start of the options field
    if data[236:240] != b"\x63\x82\x53\x63":
        return None

    # Walk options looking for vendor class (option 60) containing "PXEClient"
    options_bytes = data[240:]
    cursor = 0

    while cursor < len(options_bytes):
        tag = options_bytes[cursor]
        if tag == 255:  # end marker
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
    """Build and send a ProxyDHCP reply with boot file info.

    Only sends the PXE options (60, 67) — the IP was already assigned
    by Android's DHCP server. This is ProxyDHCP, not full DHCP.
    """
    print(f"[*] Replying to {client_info['mac_readable']}...")

    packet = bytearray(240)

    # BOOTP header
    packet[0] = 2        # BOOTREPLY
    packet[1] = 1        # htype: ethernet
    packet[2] = 6        # hlen: MAC length
    packet[3] = 0        # hops

    packet[4:8] = client_info["transaction_id"]
    packet[28:34] = client_info["mac_raw"]

    # DHCP magic cookie — required before options
    packet[236:240] = b"\x63\x82\x53\x63"

    # DHCP options — what the PXE client needs to find the boot file
    packet += b"\x35\x01\x05"          # option 53: DHCPACK
    packet += b"\x3c\x09PXEClient"     # option 60: vendor class (marks this as PXE)
    boot_file = b"undionly.kpxe\x00"
    packet += b"\x43" + bytes([len(boot_file)]) + boot_file  # option 67: boot file name
    packet += b"\xff"                   # end marker

    # Reply to the actual source port — not hardcoded 68
    # PXE clients may send from ephemeral ports
    target_address = (client_info["client_address"][0], client_info["client_address"][1])
    sock.sendto(packet, target_address)
    print(f"[+] Sent {len(packet)} bytes to {target_address}")


def _proxydhcp_listener(port: int, shutdown: threading.Event) -> None:
    """UDP listener for ProxyDHCP requests on non-root (port 4011).

    Limitation: Android's DHCP answers first and doesn't include PXE options,
    so the PC never contacts this port. Root mode (port 67) is needed for
    USB tethering PXE boot.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.bind(("", port))
        s.settimeout(1.0)
        print(f"[*] ProxyDHCP listening on UDP {port}")

        while not shutdown.is_set():
            try:
                data, addr = s.recvfrom(2048)
            except socket.timeout:
                continue
            client_info = parse_packet(data, addr)
            if client_info:
                send_proxy_reply(s, client_info)
