# Progress Tracker

## Current status

**Milestone 6: Scan support** - IN PROGRESS

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

### Milestone 6: Scan support (DONE)

- [x] Implement escan (enhanced scan) via firmware
- [x] Configure firmware event mask (`event_msgs` iovar)
- [x] Process BRCMF_E_ESCAN_RESULT events
- [x] Parse BSS info structures from scan results
- [x] Chanspec decoding for correct channel numbers (2.4GHz and 5GHz)
- [x] RSSI extraction from scan results
- [x] Deferred scan completion via taskqueue
- [x] Scan result caching
- [ ] Report scan results to net80211 (ieee80211_add_scan causes crashes)
- [ ] Event buffer re-posting after consumption

Tested: Finding BSSes with correct channels (1, 6, 60) and RSSI values (-45 to -72 dBm).
Known issue: ieee80211_add_scan crashes, needs investigation.
Known issue: Subsequent escans may timeout.

### Milestone 7: Association (IN PROGRESS)

- [x] Handle IEEE80211_S_AUTH state transition (calls brcmf_join_bss)
- [x] Set SSID via BRCMF_C_SET_SSID ioctl
- [x] Enable BRCMF_E_LINK and BRCMF_E_SET_SSID events
- [x] Handle link events in brcmf_link_event()
- [ ] Test with open network
- [ ] Handle IEEE80211_S_RUN transition on link up
- [ ] Handle disconnection

### Future milestones

- Data path (TX/RX flowrings)
- WPA/WPA2 support (key management)
- Power management

## Known issues

See docs/03-known-issues.md for tracked bugs.

## Code structure

| Module | Purpose |
|--------|---------|
| pcie.c | PCIe bus layer: BAR mapping, DMA, ring allocation, interrupts, firmware load |
| msgbuf.c | Message buffer protocol: ring operations, D2H processing, IOCTL handling |
| core.c | Chip core management: enumeration, reset, firmware download state |
| fwil.c | Firmware interface layer: IOVAR get/set operations |
| cfg.c | net80211 interface: VAP management, scan, connect |
| brcmfmac.zig | EROM parser (pure Zig, no TLS/kernel deps) |
