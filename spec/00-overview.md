# brcmfmac Driver Specification

## Overview

brcmfmac is a Linux FullMAC WiFi driver for Broadcom wireless chipsets. This specification documents the driver architecture for re-implementation on FreeBSD.

**Target hardware**: BCM4350 (PCI device `0x14e4:0x43a3`)

**Key distinction**: brcmfmac is a FullMAC driver. The firmware handles 802.11 MAC layer operations (scanning, authentication, association). The host driver communicates with firmware via commands and events.

---
**Hardware-specific notes**

Throughout this specification, sections marked with "**BCM4350 note**" contain hardware-specific details discovered during FreeBSD driver development. These notes apply to firmware version 7.35.180.133 and may not apply to other Broadcom chips or firmware versions.

---

## Document structure

| File | Description |
|------|-------------|
| **00-overview.md** | This file, high-level architecture |
| **01-data-structures.md** | Core data structures |
| **02-bus-layer.md** | PCIe bus interface and DMA rings |
| **03-protocol-layer.md** | msgbuf protocol for host-firmware communication |
| **04-firmware-interface.md** | FWIL layer (firmware ioctl/iovar) |
| **05-event-handling.md** | Firmware event processing |
| **06-cfg80211-operations.md** | Wireless configuration operations |
| **07-initialization.md** | Driver and firmware initialization sequence |
| **08-data-path.md** | TX/RX packet flow |
| **09-firmware-commands.md** | Command reference |
| **10-structures-reference.md** | Firmware structure definitions |

## Architecture layers

```
┌─────────────────────────────────────────────────────────┐
│                    cfg80211 / mac80211                  │
│              (Wireless configuration API)               │
├─────────────────────────────────────────────────────────┤
│                     brcmf_cfg80211                      │
│         (cfg80211 ops: scan, connect, keys, etc.)       │
├─────────────────────────────────────────────────────────┤
│                        FWIL                             │
│    (Firmware Interface Layer: ioctl/iovar encoding)     │
├─────────────────────────────────────────────────────────┤
│                       Protocol                          │
│  (BCDC for SDIO/USB, msgbuf for PCIe)                   │
├─────────────────────────────────────────────────────────┤
│                      Bus Layer                          │
│    (PCIe/SDIO/USB - hardware abstraction)               │
├─────────────────────────────────────────────────────────┤
│                   Hardware + Firmware                   │
└─────────────────────────────────────────────────────────┘
```

## Key concepts

### FullMAC vs SoftMAC

**SoftMAC** (mac80211): Host software handles 802.11 MAC operations. Driver receives/transmits raw 802.11 frames.

**FullMAC** (cfg80211): Firmware handles 802.11 MAC. Host sends high-level commands (scan, connect). Driver receives/transmits Ethernet frames.

brcmfmac is FullMAC. The driver:
- Sends commands to firmware (scan channels, connect to AP)
- Receives events from firmware (scan results, connection status)
- Exchanges Ethernet frames (not 802.11 frames)

### Communication model

Host ↔ Firmware communication:

1. **Commands** (host → firmware): Trigger actions (scan, associate)
2. **Queries** (host ↔ firmware): Get/set variables
3. **Events** (firmware → host): Async notifications (scan done, link up/down)
4. **Data** (bidirectional): Ethernet frames

### Interface model

- `brcmf_pub`: Global driver context (one per physical device)
- `brcmf_if`: Virtual interface (multiple per device, supports STA + AP + P2P)
- `brcmf_cfg80211_vif`: cfg80211 virtual interface state
- `brcmf_bus`: Bus abstraction (PCIe/SDIO/USB)

## PCIe-specific details

For BCM4350 (target hardware):

- Protocol: msgbuf (ring-based DMA)
- Shared memory: TCM (Tightly Coupled Memory) accessible via BAR1
- Firmware: `brcmfmac4350c2-pcie.bin`
- NVRAM: `brcmfmac4350c2-pcie.txt`

### Memory regions

| Region | BAR | Description |
|--------|-----|-------------|
| Registers | BAR0 | PCIe core, chip control |
| TCM | BAR1 | Firmware memory, shared structures |

### Interrupt model

MSI interrupts from firmware to host:
- Mailbox doorbell: Firmware signals new messages in D2H rings
- Console output: Debug messages (optional)

Host to firmware:
- Write doorbell register to signal new messages in H2D rings
