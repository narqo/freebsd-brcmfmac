# Progress Tracker

## Current status

**Milestone 8: Data path** - TX works, RX completions missing

## Milestones

### Milestone 1-7: DONE

### Milestone 8: Data path (IN PROGRESS)

**Working:**
- [x] Flow ring creation and TX submission
- [x] TX completions received (TX_STATUS status=0, firmware sends frames OTA)
- [x] Flowring index slots correctly sized (4 bytes per slot)
- [x] TX data format: DMA addr past ETH header, data_len excludes header
- [x] Scan no longer crashes (overrode ic_scan_curchan with timeout scheduling)

**Not working:**
- [ ] RX completions - firmware consumed 255 RXPOST buffers but RX_w stays 0
- [ ] kldunload crashes (scan_curchan_task accesses NULL ss_vap during teardown)

**Key debug findings:**
- RXPOST_r = 255: firmware consumed ALL posted RX buffers
- RX_w = 0: firmware wrote zero RX completions
- TX_STATUS status=0: packets successfully transmitted OTA

**Possible causes of RX silence:**
1. Firmware writing RX complete write pointer to wrong address (DMA index mode?)
2. RX complete ring address mismatch
3. Firmware using buffers internally (beacons) without generating completions
4. Missing iovar to enable data path RX

### Scan crash fix

Root cause: `scan_curchan_task` accesses `ss->ss_vap` (at offset 0x6a) which
is NULL. The default swscan `scan_curchan` does `IEEE80211_DPRINTF(ss->ss_vap, ...)`
which dereferences the NULL vap pointer.

Fix: Override `ic_scan_curchan` with our own that skips the DPRINTF but still
enqueues the timeout task to maintain proper scan timing. Uses knowledge of
swscan's private `scan_state` layout to access `ss_scan_curchan` timeout_task.

## Code structure

| Module | Purpose |
|--------|---------|
| pcie.c | PCIe bus: BAR mapping, DMA, ring alloc, interrupts, firmware load |
| msgbuf.c | msgbuf protocol: ring ops, D2H processing, IOCTL, TX/RX |
| core.c | Chip core management: enumeration, reset, firmware download |
| fwil.c | Firmware interface: IOVAR get/set |
| cfg.c | net80211: VAP management, scan, connect |
| brcmfmac.zig | EROM parser (pure Zig) |
