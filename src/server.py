"""Thread orchestration — launches all three boot servers concurrently."""

import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from src.proxydhcp import _proxydhcp_listener
from src.tftp import _tftp_listener
from src.http_server import _http_server
from src.boot_config import generate_boot_config


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
            time.sleep(3600)
    except KeyboardInterrupt:
        print("\n[*] Shutting down...")
        executor.shutdown(wait=False, cancel_futures=True)
