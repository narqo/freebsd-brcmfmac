# brcmfmac — FreeBSD native WiFi driver for BCM4350

Kernel module (KLD) for Broadcom BCM4350 FullMAC WiFi (PCIe device
`14e4:43a3`). Written from scratch using native FreeBSD APIs — no
LinuxKPI.

Tested on FreeBSD 15 with the BCM4350c2 in a 2016 MacBook Pro.

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
