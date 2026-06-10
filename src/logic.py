"""PXE ProxyDHCP helpers.

Concise, developer-facing comments that explain the few important offsets
and the TLV parsing behavior. Keep implementation unchanged; focus on
clarity for anyone reading the code.
"""

import socket
from concurrent.futures import ThreadPoolExecutor
from http.server import HTTPServer, SimpleHTTPRequestHandler


def parse_packet(data, addr):
    # Quick sanity: header + cookie must be present
    if len(data) < 240:
        return None
    # opcode 1 == BOOTREQUEST from client
    if data[0] != 1:
        return None

    # Transaction ID (bytes 4-7) and client hardware address (bytes 28-33)
    transaction_id = data[4:8]
    client_mac = data[28:34]
    mac_readable = ":".join(f"{b:02x}" for b in client_mac)

    # DHCP magic cookie (bytes 236-239) must match before options
    if data[236:240] != b"\x63\x82\x53\x63":
        return None

    # Options start at byte 240 — parse TLV (tag, len, value)
    options_bytes = data[240:]
    cursor = 0

    while cursor < len(options_bytes):
        tag = options_bytes[cursor]
        if tag == 255:  # end option
            break
        if cursor + 1 >= len(options_bytes):  # malformed
            break
        length = options_bytes[cursor + 1]
        value = options_bytes[cursor + 2 : cursor + 2 + length]

        # Option 60 = Vendor Class Identifier; PXEClient appears here
        if tag == 60 and b"PXEClient" in value:
            print(
                f"[Parser] Valid PXE Request: MAC={mac_readable} TxID={transaction_id.hex()}"
            )
            return {
                "client_address": addr,
                "transaction_id": transaction_id,
                "mac_raw": client_mac,
                "mac_readable": mac_readable,
            }

        cursor += 2 + length

    return None


def send_proxy_reply(socket_channel, client_info):
    # Build minimal ProxyDHCP reply with options 53, 60, 67, and 255 end marker.
    print(f"[Engine] Constructing ProxyDHCP reply for {client_info['mac_readable']}...")

    packet = bytearray(240)  # fixed BOOTP/DHCP header size

    # Basic header fields (opcode, htype, hlen, hops)
    packet[0] = 2  # BOOTREPLY
    packet[1] = 1  # htype: ethernet
    packet[2] = 6  # hlen: mac length
    packet[3] = 0  # hops

    # Echo transaction id and client mac into the reply so client matches it
    packet[4:8] = client_info["transaction_id"]
    packet[28:34] = client_info["mac_raw"]

    # Magic cookie before options
    packet[236:240] = b"\x63\x82\x53\x63"

    # Options (append to the header)
    packet += b"\x35\x01\x05"  # Option 53: DHCPACK
    packet += b"\x3c\x09PXEClient"  # Option 60: Vendor Class

    boot_file = b"undionly.kpxe\x00"
    packet += b"\x43" + bytes([len(boot_file)]) + boot_file  # Option 67

    packet += b"\xff"  # End

    target_address = (client_info["client_address"][0], 68)
    socket_channel.sendto(packet, target_address)
    print(f"[Engine] Sent {len(packet)} bytes to {target_address}")


def await_device(port=4011):
    # Run UDP listener in threadpool; hand valid PXE requests to replyer
    def _listen():
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("", port))
            print(f"Listening for PXE packets on port {port}...")

            while True:
                data, addr = s.recvfrom(2048)
                client_info = parse_packet(data, addr)
                if client_info:
                    send_proxy_reply(s, client_info)

    executor = ThreadPoolExecutor(max_workers=3)
    executor.submit(_listen)
