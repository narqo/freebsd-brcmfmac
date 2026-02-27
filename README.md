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
ifconfig wlan0
wlan0: flags=8843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> metric 0 mtu 1500
	options=0
	ether f4:0f:24:2a:72:e3
	inet 192.168.188.103 netmask 0xffffff00 broadcast 192.168.188.255
	groups: wlan
	ssid █████████ channel 60 (5300 MHz 11a ht/40+) bssid 1c██████:3c
	country 511 authmode WPA2/802.11i privacy ON deftxkey UNDEF
	AES-CCM 2:128-bit AES-CCM 3:128-bit AES-CCM ucast:128-bit txpower 0
	bmiss 7 mcastrate 6 mgmtrate 6 scanvalid 60 -ht -htcompat -ampdu
	ampdulimit 64k -amsdu -stbc -ldpc -uapsd wme roaming MANUAL
	parent interface: brcmfmac0
	media: IEEE 802.11 Wireless Ethernet MCS mode 11na
	status: associated
	nd6 options=29<PERFORMNUD,IFDISABLED,AUTO_LINKLOCAL>
	
wpa_cli -i wlan0 status
bssid=1c██████:3c
freq=0
ssid=█████████
id=0
mode=station
pairwise_cipher=CCMP
group_cipher=CCMP
key_mgmt=WPA2-PSK
wpa_state=COMPLETED
ip_address=192.168.188.103
address=f4:0f:24:2a:72:e3
uuid=d03cceab-ae63-5d24-a150-7e37e9b1eddd

traceroute -iwlan0 1.1.1.1
traceroute to 1.1.1.1 (1.1.1.1), 64 hops max, 40 byte packets
 1  192.168.188.1 (192.168.188.1)  12.302 ms  7.721 ms  9.861 ms
 2  ██████  9.397 ms  11.290 ms  9.459 ms
 3  ██████  9.886 ms  11.670 ms  9.882 ms
 4  i689729BA.versanet.de (104.151.41.186)  9.751 ms  8.576 ms  9.460 ms
 5  62.214.73.216 (62.214.73.216)  9.396 ms  12.534 ms  9.304 ms
 6  62.214.73.217 (62.214.73.217)  9.658 ms  12.861 ms  9.257 ms
 7  one.one.one.one (1.1.1.1)  9.818 ms  8.199 ms  10.187 ms
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
