# Progress Tracker

## Current status

**Milestone 8: Data path** - IN PROGRESS (TX works, RX not working)

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
- [x] Re-post IOCTL response and event buffers after consumption

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
- [x] Directed scan for hidden SSIDs
- [x] Poll-based IOCTL completion (fixes timeouts)
- [x] Handle GEN_STATUS and RING_STATUS message types
- [x] Override ic_scan_curchan to prevent net80211 crashes

Tested: Finding BSSes with correct channels and RSSI values.
Note: ieee80211_add_scan disabled (crashes); results cached internally.

### Milestone 7: Association (DONE - control plane)

- [x] Handle link events via taskqueue (deferred from interrupt context)
- [x] Direct join when scan finds target BSS (bypass net80211 scan state machine)
- [x] Set SSID via BRCMF_C_SET_SSID ioctl
- [x] Process BRCMF_E_LINK and BRCMF_E_SET_SSID events
- [x] Update iv_bss node with BSSID and channel
- [x] Set ic_curchan/ic_bsschan before RUN transition
- [x] Transition to IEEE80211_S_RUN state on link up
- [x] Handle disconnection (transition to SCAN state)

Tested: Successfully associated to hidden AP "TestAP" (open network).
Interface shows `status: associated`.

### Milestone 8: Data path (IN PROGRESS)

- [x] Flow ring creation (MSGBUF_TYPE_FLOW_RING_CREATE)
- [x] Flow ring ID calculation (flowid + BRCMF_NROF_H2D_COMMON_MSGRINGS)
- [x] TCM ring descriptor setup for flow rings
- [x] TX packet submission (MSGBUF_TYPE_TX_POST)
- [x] TX buffer tracking with DMA mapping
- [ ] TX completion handling - may need verification
- [ ] RX completion handling - NOT WORKING
- [ ] Packet delivery to net80211

**Current state:**
- Flowring created successfully (status 0)
- TX function called, packets submitted to ring
- No RX completions observed - firmware not sending received packets

**Suspected issues:**
1. RX buffers may not be associated with interface/flowring
2. Need to enable data path in firmware via iovar
3. Ring index addresses may be incorrect

### Future milestones

- WPA/WPA2 support (key management, sup_wpa iovar)
- Power management
- Proper scan result reporting to net80211

## Known issues

See docs/03-known-issues.md for tracked bugs.

## Code structure

| Module | Purpose |
|--------|---------|
| pcie.c | PCIe bus layer: BAR mapping, DMA, ring allocation, interrupts, firmware load |
| msgbuf.c | Message buffer protocol: ring operations, D2H processing, IOCTL handling, TX/RX |
| core.c | Chip core management: enumeration, reset, firmware download state |
| fwil.c | Firmware interface layer: IOVAR get/set operations |
| cfg.c | net80211 interface: VAP management, scan, connect |
| brcmfmac.zig | EROM parser (pure Zig, no TLS/kernel deps) |
