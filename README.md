# servings-termux

Run a full PXE/Boot server directly from your phone. No need for a USB.

Serves three protocols to chainload any x86_64 machine over USB tether or Wi-Fi:

1. **ProxyDHCP** (UDP 4011) -- intercepts PXE clients and directs them to your phone
2. **TFTP** (UDP 6969) -- serves the initial bootstrap loader (`undionly.kpxe` / `ipxe.efi`)
3. **HTTP** (TCP 8080) -- streams kernels, initrd, squashfs, and ISO files at full link speed

An iPXE `boot.cfg` menu is auto-generated from whatever ISOs / kernels you drop in the boot directory.

## Install

```bash
pip install -e .
```

Requires Python 3.12+ and Termux on Android.

## Setup (Termux)

```bash
# Allow Termux access to shared storage
termux-setup-storage

# Place your disk images somewhere in shared storage
mkdir -p /sdcard/Disk Images/
cp archlinux-*.iso /sdcard/Disk Images/

# Drop a PXE bootloader in the same directory
# (download from http://boot.ipxe.org/undionly.kpxe)
```

## Usage

```bash
# Auto-detect Termux storage, start all three servers
servings serve

# Custom ports and explicit boot directory
servings serve \
  --port 4011 \
  --tftp-port 6969 \
  --http-port 8080 \
  --boot-dir /sdcard/Disk Images/
```

On rooted devices, set `--tftp-port 69` to use the standard TFTP port.

## How it works

1. Phone runs a ProxyDHCP server on the local network (USB tethering or Wi-Fi)
2. Client machine sends a DHCP discover with option 60 (PXEClient)
3. Server detects the PXE client and replies with the boot filename (`undionly.kpxe`)
4. Client requests the file over TFTP; the phone streams it in 512-byte blocks
5. iPXE boots in the client's RAM and requests `boot.cfg` over HTTP from the phone
6. The auto-generated menu lists every ISO and kernel+initrd pair found in the boot dir
7. User picks an entry; iPXE either `sanboot`s the ISO directly or loads the kernel+initrd

## Boot directory auto-detection

If no `--boot-dir` is specified, the server checks these paths in order:

- `/sdcard/Disk Images/`
- `/storage/emulated/0/Disk Images/`
- Current working directory (fallback)

Place `.iso` files for direct ISO boot, or `vmlinuz-*` + `initramfs-*.img` pairs for kernel+initrd boot. The server generates an iPXE menu script (`boot.cfg`) on every start.

## Tests

```bash
python3 -m unittest discover -s test -v
```

## Notes

- ProxyDHCP on port 4011 avoids the need for root (standard DHCP uses 67/68)
- TFTP defaults to port 6969 because port 69 requires root on Android
- The auto-generated `boot.cfg` is not versioned -- delete it to force a fresh scan
- Will be recoded in Rust someday

## License

No.
