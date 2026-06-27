"""Quick-start script — starts servings-cli with sensible defaults.

Usage:
  python src/start_direct.py
  SERVER_IP=192.168.1.100 HTTP_PORT=8081 python src/start_direct.py
"""

import os, sys, threading
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from pathlib import Path
from src.http_server import _http_server, BootHTTPHandler
from src.tftp import _tftp_listener
from src.proxydhcp import _proxydhcp_listener

boot_dir = Path(os.path.expanduser("~/servings-boot"))
os.makedirs(boot_dir, exist_ok=True)

server_ip = os.environ.get("SERVER_IP", "192.168.42.129")
dhcp_port = int(os.environ.get("DHCP_PORT", "4011"))
tftp_port = int(os.environ.get("TFTP_PORT", "6969"))
http_port = int(os.environ.get("HTTP_PORT", "8080"))

shutdown = threading.Event()

threads = [
    threading.Thread(target=_proxydhcp_listener, args=(dhcp_port, shutdown), daemon=True),
    threading.Thread(target=_tftp_listener, args=(tftp_port, boot_dir, shutdown), daemon=True),
    threading.Thread(target=_http_server, args=(http_port, boot_dir, shutdown), daemon=True),
]

for t in threads:
    t.start()

print("[*] servings-cli servers started")
print(f"[*] ProxyDHCP : UDP {dhcp_port}")
print(f"[*] TFTP      : UDP {tftp_port}")
print(f"[*] HTTP      : TCP {http_port}")
print(f"[*] Server IP : {server_ip}")
print(f"[*] Boot dir  : {boot_dir}")

try:
    shutdown.wait()
except KeyboardInterrupt:
    shutdown.set()
