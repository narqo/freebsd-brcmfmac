# Progress Tracker

## Current status

**Milestone 8: Data path** - TX and RX working! Ping succeeds bidirectionally.

## Milestones

### Milestone 1-7: DONE

### Milestone 8: Data path (WORKING)

**Working:**
- [x] Flow ring creation and TX submission
- [x] TX completions received (TX_STATUS status=0)
- [x] RX completions received (firmware delivers both broadcast and unicast frames)
- [x] Bidirectional ping works (14-116ms RTT)
- [x] ARP resolution works (broadcast and unicast)
- [x] VAP-level transmit bypass (no net80211 802.11 encapsulation for FullMAC)
- [x] kldunload works cleanly
- [x] scan_curchan crash fix (set ss_vap before enqueue)
- [x] No re-join when already associated (link_up guard)

**Key fixes in this session:**
1. **VAP transmit override**: net80211's `ieee80211_vap_transmit` encapsulates
   ethernet frames into 802.11 before calling `ic_transmit`. For FullMAC, the
   firmware handles 802.11 encapsulation. Override `if_transmit` on the VAP to
   send raw ethernet frames directly to the firmware, bypassing net80211's
   encapsulation. Without this, TX frames had garbled ethernet headers (802.11
   header data instead of ethernet src/dst MACs).

2. **No re-join guard**: `brcmf_scan_complete_task` would issue `SET_SSID` every
   time a scan found the target BSS, even when already associated. This caused
   repeated disassociation/reassociation cycles, which disrupted the firmware's
   RX path (unicast delivery stopped). Fixed with `if (sc->link_up) return`.

3. **scan_curchan crash fix**: Set `ss_vap` from TAILQ_FIRST in
   `brcmf_scan_curchan` before enqueuing the timeout task, preventing the
   page fault when `scan_curchan_task` accesses `ss_vap->iv_debug`.

**Remaining issues:**
- Latency is high (10-116ms, avg ~40ms) — possibly power management related
- No broadcast RX in stable association (may need allmulti reconfiguration)
- kldunload of old (buggy) modules crashes on destroy

## Code structure

| Module | Purpose |
|--------|---------|
| pcie.c | PCIe bus: BAR mapping, DMA, ring alloc, interrupts, firmware load |
| msgbuf.c | msgbuf protocol: ring ops, D2H processing, IOCTL, TX/RX |
| core.c | Chip core management: enumeration, reset, firmware download |
| fwil.c | Firmware interface: IOVAR get/set |
| cfg.c | net80211: VAP management, scan, connect, TX override |
| brcmfmac.zig | EROM parser (pure Zig) |
