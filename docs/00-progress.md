# Progress Tracker

## Current status

**Milestone 8: Data path** - COMPLETE. TX and RX working, ping succeeds bidirectionally.

## Milestones

### Milestone 1-7: DONE

### Milestone 8: Data path (COMPLETE)

- [x] Flow ring creation and TX submission
- [x] TX completions received (TX_STATUS status=0)
- [x] RX completions received (firmware delivers both broadcast and unicast frames)
- [x] Bidirectional ping works (14-116ms RTT)
- [x] ARP resolution works (broadcast and unicast)
- [x] VAP-level transmit bypass (no net80211 802.11 encapsulation for FullMAC)
- [x] kldunload works cleanly
- [x] scan_curchan crash fix (set ss_vap before enqueue)
- [x] No re-join when already associated (link_up guard)

**Key fixes:**
1. **VAP transmit override**: net80211's `ieee80211_vap_transmit` encapsulates
   ethernet frames into 802.11 before calling `ic_transmit`. For FullMAC, the
   firmware handles 802.11 encapsulation. Override `if_transmit` on the VAP to
   send raw ethernet frames directly to the firmware, bypassing net80211's
   encapsulation.

2. **No re-join guard**: `brcmf_scan_complete_task` would issue `SET_SSID` every
   time a scan found the target BSS, even when already associated. Fixed with
   `if (sc->link_up) return`.

3. **scan_curchan crash fix**: Set `ss_vap` from TAILQ_FIRST in
   `brcmf_scan_curchan` before enqueuing the timeout task.

### Milestone 9: Debug cleanup (COMPLETE)

- [x] Remove verbose TX/RX logging from interrupt path
- [x] Remove ring index dumps
- [x] Remove hex dumps of RX frames
- [x] Keep error-path logging only
- [x] Disable firmware console reader (keep code for future debug)

### Milestone 10: WPA2 support (IN PROGRESS)

- [x] Set wsec (wireless security mode) - detected from capability field
- [x] Set wpa_auth (WPA authentication type) - WPA2_AUTH_PSK
- [x] Add iv_key_set/iv_key_delete callbacks for key installation
- [x] Add wsec_key IOVAR support
- [x] Fix scan result BSSID matching (handle zero BSSID as "any")
- [x] Fix IE offset parsing (ie_offset=0 means IEs follow fixed struct)
- [x] Enable firmware supplicant (`sup_wpa=1`)
- [x] Push PSK via `BRCMF_C_SET_WSEC_PMK`
- [x] Add sysctl `dev.brcmfmac.0.psk` for passphrase input
- [ ] Test WPA2 association end-to-end on real hardware

**Current status**: Firmware supplicant approach implemented. Set PSK via
`sysctl dev.brcmfmac.0.psk="passphrase"`, then `ifconfig wlan0 ssid <network>`.
Driver enables `sup_wpa=1`, pushes PMK, then joins. Firmware handles 4-way
handshake internally. See `docs/01-decisions.md` for rationale.

### Milestone 11: Latency optimization (TODO)

- [ ] Investigate interrupt coalescing
- [ ] Consider moving D2H processing to taskqueue
- [ ] Piggyback D2H polling on TX path

### Milestone 12: Robustness (TODO)

- [ ] Handle LINK_DOWN event (disassociation)
- [ ] RX buffer pool management under load
- [ ] TX flow control / backpressure
- [ ] Audit error paths for leaks

### Milestone 13: ifconfig scan support (TODO)

- [ ] Populate ieee80211_scan_entry from brcmf_scan_result
- [ ] Feed results into net80211 scan cache
- [ ] Support `ifconfig wlan0 list scan`

## Code structure

| Module | Purpose | Lines |
|--------|---------|-------|
| pcie.c | PCIe bus: BAR mapping, DMA, ring alloc, interrupts, firmware load | 1161 |
| msgbuf.c | msgbuf protocol: ring ops, D2H processing, IOCTL, TX/RX | 1469 |
| cfg.c | net80211: VAP lifecycle, attach/detach, link events, transmit | 566 |
| cfg.h | Shared definitions for cfg/scan/security modules | 213 |
| scan.c | Scan: escan requests, result processing, chanspec conversion | 327 |
| security.c | Security: wsec/wpa_auth, key installation | 119 |
| core.c | Chip core management: enumeration, reset, firmware download | 307 |
| fwil.c | Firmware interface: IOVAR get/set | 136 |
| brcmfmac.zig | EROM parser (pure Zig) | 222 |
| **Total** | | ~4520 |
