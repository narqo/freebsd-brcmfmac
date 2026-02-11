# Progress Tracker

## Current status

**Milestone 5: Interface initialization** - DONE

## Build and test

See docs/02-build-test.md for full workflow.

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

### Milestone 3: DMA ring setup (DONE)

- [x] Read ring info from TCM (ringmem, index pointers, max rings)
- [x] Allocate DMA-coherent buffers for common rings (5 rings)
- [x] Write ring descriptors to TCM (base addr, max items, item size)
- [x] Set up DMA index buffers if DMA_INDEX flag set
- [x] Allocate scratch and ring-update DMA buffers

### Milestone 4: Interrupt and msgbuf init (DONE)

- [x] MSI interrupt setup
- [x] Post IOCTL response buffers (8)
- [x] Post event buffers (8)
- [x] Post initial RX data buffers (255)
- [x] IOCTL request/response via control submit/complete rings
- [x] IOVAR support (brcmf_fil_iovar_data_get/set, brcmf_fil_iovar_int_set/get)
- [x] Query firmware version string

Tested: Firmware version 7.35.180.133 (Nov 26 2015).

### Milestone 5: Interface initialization (DONE)

- [x] Get MAC address from firmware (`cur_etheraddr` iovar)
- [x] Create net80211 interface (ieee80211com)
- [x] Basic ifconfig support (VAP create, interface up)
- [x] State change callbacks (INIT, SCAN, AUTH, ASSOC, RUN)

Tested: MAC address f4:0f:24:2a:72:e3, wlan0 created and brought up.

### Milestone 6: Scan support (NEXT)

- [ ] Implement escan (enhanced scan) via firmware
- [ ] Process BRCMF_E_ESCAN_RESULT events
- [ ] Report scan results to net80211
- [ ] Scan abort handling

### Future milestones

- Association (BRCMF_C_SET_SSID, security config)
- Data path (TX/RX flowrings)
- Power management
- WPA/WPA2 support

## Code structure

| Module | Purpose |
|--------|---------|
| pcie.c | PCIe bus layer: BAR mapping, DMA, ring allocation, interrupts, firmware load |
| msgbuf.c | Message buffer protocol: ring operations, D2H processing, IOCTL handling |
| core.c | Chip core management: enumeration, reset, firmware download state |
| fwil.c | Firmware interface layer: IOVAR get/set operations |
| cfg.c | net80211 interface: VAP management, scan, connect |
| brcmfmac.zig | EROM parser (pure Zig, no TLS/kernel deps) |
