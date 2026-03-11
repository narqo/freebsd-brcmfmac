# brcmfmac Driver Specification

## Scope

This document specifies the Linux brcmfmac FullMAC WiFi driver for Broadcom wireless chipsets, covering target configurations:

| Target | Bus | Chip ID | Protocol | Firmware |
|--------|-----|---------|----------|----------|
| BCM4345/6 | SDIO | `0x4345` | BCDC | `brcmfmac43455-sdio.bin` |
| BCM4350 | PCIe | `0x4350` | msgbuf | `brcmfmac4350c2-pcie.bin` |

The driver is FullMAC: firmware handles the 802.11 MAC (scanning, authentication, association). The host sends high-level commands and exchanges Ethernet frames, not 802.11 frames.

## Document structure

The specification is ordered bottom-up: hardware and bus first, then protocol, firmware interface, wireless operations, and finally lifecycle (initialization, data path).

| Chapter | Content |
|---------|---------|
| [00-overview](00-overview.md) | Architecture, key concepts (this file) |
| [01-bus-pcie](01-bus-pcie.md) | PCIe bus: BAR mapping, DMA rings, interrupts, firmware download |
| [02-bus-sdio](02-bus-sdio.md) | SDIO bus: backplane window, SDPCM framing, clock/power, DPC |
| [03-protocol-msgbuf](03-protocol-msgbuf.md) | msgbuf protocol (PCIe): ring messages, IOCTL, flow rings |
| [04-protocol-bcdc](04-protocol-bcdc.md) | BCDC protocol (SDIO): command/data headers, firmware signaling |
| [05-firmware-interface](05-firmware-interface.md) | FWIL: ioctl/iovar encoding, command execution |
| [06-event-handling](06-event-handling.md) | Firmware events: packet format, dispatch, handlers |
| [07-cfg80211-operations](07-cfg80211-operations.md) | Wireless ops: scan, connect, keys, security, AP mode |
| [08-initialization](08-initialization.md) | Probe, firmware download, attach, cfg80211 setup |
| [09-data-path](09-data-path.md) | TX/RX packet flow for both bus types |
| [10-chip-specifics](10-chip-specifics.md) | Per-chip: IDs, firmware selection, RAM layout, quirks |
| [A1-firmware-commands](A1-firmware-commands.md) | Command and IOVAR reference |
| [A2-structures](A2-structures.md) | Firmware structure definitions |
| [A3-data-structures](A3-data-structures.md) | Host driver data structures |

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                       cfg80211                          │
│              (wireless configuration API)                │
├─────────────────────────────────────────────────────────┤
│                    brcmf_cfg80211                        │
│          (scan, connect, keys, AP mode, ...)             │
├─────────────────────────────────────────────────────────┤
│                        FWIL                              │
│     (firmware interface: ioctl/iovar encoding)           │
├───────────────────────┬─────────────────────────────────┤
│    BCDC + fwsignal    │         msgbuf                  │
│     (SDIO / USB)      │         (PCIe)                  │
├───────────────────────┼─────────────────────────────────┤
│     SDIO bus layer    │      PCIe bus layer             │
│   (bcmsdh.c, sdio.c) │        (pcie.c)                 │
├───────────────────────┴─────────────────────────────────┤
│                  Hardware + Firmware                     │
└─────────────────────────────────────────────────────────┘
```

Everything above FWIL is bus-independent. The protocol layer and below differ by bus type.

## Key concepts

### FullMAC communication model

```
Host → Firmware:  Commands (scan, connect), Queries (get/set variables), TX data
Firmware → Host:  Events (scan results, link status), RX data
```

All multi-byte firmware fields are little-endian, except event messages which are big-endian (they arrive in Ethernet frames with Broadcom OUI encapsulation).

### Protocol selection

Determined at probe time by bus type:
- **PCIe** → `BRCMF_PROTO_MSGBUF`: DMA ring buffers, per-flow TX rings, pre-posted RX buffers
- **SDIO** → `BRCMF_PROTO_BCDC`: byte-stream commands over SDPCM framing, TLV-based firmware signaling for flow control

### Interface model

- `brcmf_pub` — one per physical device; holds bus, protocol, cfg80211 state
- `brcmf_if` — per virtual interface (up to 16); indexed by `bsscfgidx`
- `brcmf_cfg80211_vif` — cfg80211 state per VIF (connection profile, SME state)
- `brcmf_bus` — bus abstraction with ops table; union of PCIe/SDIO/USB private data

### Firmware files

Each chip+bus combination requires:
1. **Firmware binary** (`.bin`) — dongle executable
2. **NVRAM** (`.txt`, optional) — board-specific calibration and configuration
3. **CLM blob** (`.clm_blob`, optional) — regulatory/country data

File names are constructed from chip ID, revision, and bus type. Board-type-specific NVRAM is tried first (`<base>.<board_type>.txt`).
