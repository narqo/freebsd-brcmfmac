# brcmfmac — FreeBSD native WiFi driver for BCM4350

Kernel module (KLD) for the Broadcom BCM4350 FullMAC WiFi adapter,
built into the 2016 MacBook Pro (PCIe device `14e4:43a3`).

## Project status

This is an experimental project. The module still shows stability problems. As of Feb 2026 I DO NOT recommend using it other than for testing purposes.

Works for WPA2-PSK on 2.4GHz and 5GHz.

### AI disclosure

The code of the project was mainly written by AI coding agents, with very low supervision (_vibe coding over many coding sessions, using [pi agent](https://pi.dev) and Claude Opus family of models_). The code is not guaranteed to be free of bugs or security vulnerabilities, and should be used with caution.

## Prerequisites

Tested on FreeBSD 15 running on a MacBook Pro (13-inch, 2016).

```
uname -a
FreeBSD v6rmbp.16 15.0-RELEASE-p3 FreeBSD 15.0-RELEASE-p3 releng/15.0-n281008-5cf7232732d5 GENERIC amd64

pciconf -lv
···
none4@pci0:2:0:0:	class=0x028000 rev=0x05 hdr=0x00 vendor=0x14e4 device=0x43a3 subvendor=0x106b subdevice=0x0159
    vendor     = 'Broadcom Inc. and subsidiaries'
    device     = 'BCM4350 802.11ac Wireless Network Adapter'
    class      = network
```

## Build

Requires FreeBSD 15 with kernel sources in `/usr/src` and Zig 0.16-dev.

```
make
```

## Install

Copy the firmware file to `/boot/firmware/`:

- `brcmfmac4350c2-pcie.bin` (required)
- `brcmfmac4350c2-pcie.txt` (optional, NVRAM configuration)

These are the standard Linux firmware files from `linux-firmware`.

Copy the built module to `/boot/modules/` and load the module:

```
cp if_brcmfmac.ko /boot/modules/
kldload if_brcmfmac
```

Check the module was associated with the device:

```
pciconf -ll | grep brcmfmac
brcmfmac0@pci0:2:0:0:	028000   05   00   14e4   43a3   106b   0159
```

## Usage

```
ifconfig wlan0 create wlandev brcmfmac0
ifconfig wlan0 up scan
wpa_supplicant -iwlan0 -c/etc/wpa_supplicant.conf -B
dhclient wlan0
```

Test the connection:

```
wpa_cli -i wlan0 status
ping -S <wlan0_addr> -c 5 freebsd.org
```

To load at boot, add to `/boot/loader.conf`:

```
if_brcmfmac_load="YES"
```

## Sysctls

| Name | Description |
|------|-------------|
| `dev.brcmfmac.0.psk` | WPA passphrase |
| `dev.brcmfmac.0.pm` | Power management (0=off, 1=PM1, 2=PM2) |
| `dev.brcmfmac.0.debug` | Debug verbosity |

## Documentation

- `docs/00-progress.md` — milestones, known issues
- `docs/01-decisions.md` — design decisions and rationale
- `spec/` — brcmfmac driver specification (data structures, bus layer, protocol, firmware interface)

## References

- [FreeBSD kernel development workflow](https://freebsdfoundation.org/our-work/journal/browser-based-edition/development-workflow-and-ci/freebsd-kernel-development-workflow/)
- [FreeBSD WiFi development](https://freebsdfoundation.org/our-work/journal/browser-based-edition/networking-3/freebsd-wifi-development/)

## Acknowledgements

brcmfmac driver specification is based on the Linux brcmfmac driver by Broadcom Corporation, licensed ISC.
