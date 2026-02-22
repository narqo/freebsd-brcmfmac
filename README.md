# brcmfmac — FreeBSD native WiFi driver for BCM4350

Kernel module (KLD) for the Broadcom BCM4350 FullMAC WiFi adapter,
built into the 2016 MacBook Pro (PCIe device `14e4:43a3`).

## Prerequisites

Tested on FreeBSD 15 running on a MacBook Pro (13-inch, 2016).

```
% uname -a
FreeBSD v6rmbp.16 15.0-RELEASE-p3 FreeBSD 15.0-RELEASE-p3 releng/15.0-n281008-5cf7232732d5 GENERIC amd64

% pciconf -lv
···
ppt0@pci0:2:0:0:	class=0x028000 rev=0x05 hdr=0x00 vendor=0x14e4 device=0x43a3 subvendor=0x106b subdevice=0x0159
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

Copy the firmware files to `/boot/firmware/`:

- `brcmfmac4350c2-pcie.bin`
- `brcmfmac4350c2-pcie.txt`

These are the standard Linux firmware files from `linux-firmware`.

Copy the built module to `/boot/modules/` and load the module:

```
cp if_brcmfmac.ko /boot/modules/
kldload if_brcmfmac
```

## Usage

```
ifconfig wlan0 create wlandev brcmfmac0
ifconfig wlan0 up
wpa_supplicant -Dbsd -iwlan0 -c/etc/wpa_supplicant.conf -B
dhclient wlan0
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

## Status

Works for WPA2-PSK on 2.4GHz and 5GHz.

## Documentation

- `docs/00-progress.md` — milestones, known issues
- `docs/01-decisions.md` — design decisions and rationale
- `spec/` — brcmfmac driver specification (data structures, bus layer, protocol, firmware interface)

## Acknowledgements

brcmfmac driver specification is based on the Linux brcmfmac driver by Broadcom Corporation, licensed ISC.
