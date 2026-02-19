# Progress Tracker

## Current status

**Milestone 10: WPA2 support** - IN PROGRESS. RSN IE mismatch resolved.
4-way handshake completes, pairwise key installs. Group key install and
encrypted data path need testing (blocked by intermittent SET_SSID firmware
failures on test AP).

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

### Milestone 9: Debug cleanup (COMPLETE)

### Milestone 10: WPA2 support (IN PROGRESS)

- [x] Set wsec (wireless security mode) - detected from capability field
- [x] Set wpa_auth (WPA authentication type) - WPA2_AUTH_PSK
- [x] Add iv_key_set/iv_key_delete callbacks for key installation
- [x] Add wsec_key IOVAR support
- [x] Fix scan result BSSID matching (handle zero BSSID as "any")
- [x] Fix IE offset parsing (128-byte offset for ie_length=0 entries)
- [x] Fix ieee80211_add_scan crash (NULL sp->tstamp pointer)
- [x] Scan cache populated with RSN IEs (`ifconfig wlan0 list scan` works)
- [x] Set wsec/wpa_auth from VAP flags in brcmf_newstate(AUTH)
- [x] Fix WME crash (NULL `ic_wme.wme_update` callback)
- [x] Fix BSSID bug (`sc->join_bssid` not set in MLME association path)
- [x] Work around net80211 deferred state transition race (restart_task)
- [x] Fix scan_curchan_task crash (drain scan tasks in VAP teardown)
- [x] Skip direct-join when iv_roaming == IEEE80211_ROAMING_MANUAL
- [x] Fix scan race: don't clear scan_active in scan_end
- [x] BSSID dedup in scan results (don't overwrite entries with IEs)
- [x] Flowring delete/recreate on each association
- [x] Set sup_wpa=0 for host-managed WPA
- [x] wpa_supplicant associates, EAPOL frames flow bidirectionally
- [x] Frame 2/4 verified cryptographically correct (PMK, PTK, MIC)
- [x] Frame 2/4 confirmed reaching AP (hostapd log shows it)
- [x] RSN IE mismatch resolved (WMM IE injection — see below)
- [x] 4-way handshake completes (all 4 frames exchanged)
- [x] Pairwise key (AES-CCM) installs successfully
- [x] Group key EA fix (zeros, not broadcast)
- [ ] Group key installation (BCME_UNSUPPORTED — needs struct investigation)
- [ ] Test encrypted data path

#### RSN IE mismatch (RESOLVED)

The firmware's RSN IE in the association request had capabilities `0x000c`
(16 PTKSA replay counters) while wpa_supplicant sent `0x0000`. The two
bytes differ because the firmware always uses WMM-style replay counters.

wpa_supplicant sets the replay counter bits only when `sm->wmm_enabled`
is true (`rsn_supp_capab()` in `wpa_ie.c`). This flag is set when the
BSS has a WMM vendor IE (OUI 00:50:f2 type 2).

**Fix**: Inject a synthetic WMM IE into scan results when the AP has RSN
but doesn't advertise WMM. This makes wpa_supplicant set `wmm_enabled=1`
and produce RSN capabilities `0x000c`, matching the firmware.

**Approaches that did NOT work**:
- `wpaie` iovar (any format) — causes `SET_SSID failed, status=1`
- `vndr_ie` iovar with RSN IE — firmware ignores it, still uses `0x000c`
- `bsscfg:wpaie` — same failure as `wpaie`

### Milestone 11: Latency optimization (TODO)
### Milestone 12: Robustness (TODO)

### Milestone 13: ifconfig scan support (COMPLETE)

- [x] Populate ieee80211_scan_entry from brcmf_scan_result
- [x] Feed results into net80211 scan cache via ieee80211_add_scan
- [x] Support `ifconfig wlan0 list scan`
- [x] Fix sp->tstamp NULL crash in sta_add
- [x] IE offset (128-byte fallback when ie_offset=0 and ie_length=0)
- [x] RSN/WPA IEs correctly parsed and visible in scan output

## Code structure

| Module | Purpose | Lines |
|--------|---------|-------|
| pcie.c | PCIe bus: BAR mapping, DMA, ring alloc, interrupts, firmware load | ~1160 |
| msgbuf.c | msgbuf protocol: ring ops, D2H processing, IOCTL, TX/RX | ~1360 |
| cfg.c | net80211: VAP lifecycle, attach/detach, link events, transmit | ~660 |
| cfg.h | Shared definitions for cfg/scan/security modules | ~220 |
| scan.c | Scan: escan requests, result processing, chanspec conversion | ~410 |
| security.c | Security: wsec/wpa_auth, key installation, vndr_ie | ~240 |
| core.c | Chip core management: enumeration, reset, firmware download | ~310 |
| fwil.c | Firmware interface: IOVAR get/set | ~140 |
| brcmfmac.zig | EROM parser (pure Zig) | ~220 |

## Active debug prints

These should be removed once WPA2 works:

- `cfg.c`: EAPOL TX hex dump, LINK event flags, assoc_req_ies dump
- `msgbuf.c`: EAPOL RX hex dump, TX completion non-zero status
