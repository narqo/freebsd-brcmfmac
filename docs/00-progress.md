# Progress Tracker

## Current status

**Milestone 1: PCI device probe** - DONE
**Milestone 2: Firmware download** - DONE
**Milestone 3: DMA ring setup** - IN PROGRESS

## Build and test

Cannot build or test locally. Requires FreeBSD 15 host with kernel headers.

```sh
cd /path/to/brcmfmac2
make clean; make
sudo kldload ./brcmfmac.ko
dmesg | tail -40
sudo kldunload brcmfmac
```

## Recent changes

Implemented DMA ring setup:
- Read ring info structure from TCM
- Allocate DMA-coherent buffers for 5 common rings
- Write ring descriptors (base addr, depth, item size) to TCM
- DMA index buffer allocation when DMA_INDEX flag set
- Scratch and ring update buffer allocation

## Milestones

### Milestone 1: PCI device probe (DONE)

- [x] Native FreeBSD PCI driver registration
- [x] BAR0/BAR2 mapping
- [x] Chip ID read (BCM4350 rev 5)

### Milestone 2: Firmware download (DONE)

- [x] EROM parser (DMP format, 12-bit core IDs)
- [x] Core enumeration: ARM CR4, D11, PCIe2
- [x] Watchdog reset + config register touch
- [x] set_passive: halt ARM, disable D11
- [x] Copy firmware to TCM
- [x] RAM size adjustment from firmware header
- [x] set_active: write reset vector, release ARM
- [x] Poll for shared RAM address
- [x] Parse shared RAM structure (version 5, flags 0x20005)
- [x] Signal host ready

Firmware boots in ~100ms. Shared RAM at 0x1dcf10.
Shared info: max_rxbufpost=255, ring_info_addr=0x23b374.

### Milestone 3: DMA ring setup (DONE)

Goal: Initialize DMA rings for msgbuf protocol.

- [x] Read ring info from TCM (ringmem, index pointers, max rings)
- [x] Allocate DMA-coherent buffers for common rings (5 rings)
- [x] Write ring descriptors to TCM (base addr, max items, item size)
- [x] Set up DMA index buffers if DMA_INDEX flag set
- [x] Allocate scratch and ring-update DMA buffers
- [x] Test on hardware

Tested: max_flowrings=40, max_submission=42, max_completion=3.
DMA_INDEX flag not set (flags=0x20005), indices stored in TCM.

### Milestone 4: Interrupt and msgbuf init (NEXT)

- [ ] MSI interrupt setup
- [ ] Post initial RX buffers to RX post ring
- [ ] Post IOCTL response and event buffers
- [ ] Basic IOCTL command support

### Future milestones

- Firmware command interface (FWIL)
- Event handling
- net80211 integration
- Data path (TX/RX)
