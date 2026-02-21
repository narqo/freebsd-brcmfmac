# Progress Tracker

## Current status

**Milestone 12: Robustness** - IN PROGRESS. Link loss recovery works.
Interface cycling (down/up) works with security state cleanup. Remaining
issue: rapid cycling (<2s) has ~40% failure rate due to firmware/AP
handshake timing race.

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

### Milestone 10: WPA2 support (COMPLETE)

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
- [x] Set infra mode and open system auth before join
- [x] wpa_supplicant associates, EAPOL frames flow bidirectionally
- [x] RSN IE mismatch resolved (WMM IE injection — see below)
- [x] 4-way handshake completes (all 4 frames exchanged)
- [x] Pairwise and group keys install (AES-CCM)
- [x] WPA2-PSK-SHA256 works (firmware auto-negotiates AKM type 6)
- [x] End-to-end ping over WPA2 (~7ms steady-state RTT)
- [x] DHCP works (dhclient obtains lease from AP)
- [x] DEAUTH on disconnect (prevents AP auth timeout on reconnect)
- [x] Dead code removed (vndr_ie, bsscfg, enable_supplicant)

#### Lifecycle tests (all passing)

| Test | Result |
|------|--------|
| WPA2-PSK association + ping | ✓ |
| WPA2-PSK-SHA256 association + ping | ✓ |
| DHCP lease acquisition | ✓ |
| `ifconfig wlan0 down` / `up` | ✓ reconnects |
| VAP destroy / recreate | ✓ clean reconnect |
| kldunload while associated | ✓ clean unload |
| Reconnect without AP restart | ✓ deauth clears AP state |

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

### Milestone 12: Robustness (IN PROGRESS)

- [x] Link loss recovery (AP restart while connected)
  - LINK event with link=0 triggers SCAN transition
  - Driver re-scans, re-associates automatically
- [x] DISASSOC on interface down (synchronous in `brcmf_parent`)
  - Sends DEAUTH_LEAVING before `ifconfig down` returns
  - Prevents stale AP session from blocking next association
- [x] Security state cleanup on interface down
  - Clear `wsec=0` and `wpa_auth=0` so stale encryption keys
    don't corrupt the next EAPOL handshake
- [x] Skip direct-join for WPA networks
  - `brcmf_join_bss_direct` returns EINVAL when `wpa_auth != 0`
  - Prevents supplicant-less WPA association from scan-complete path
- [ ] Rapid cycling reliability (<2s gap)
  - ~60% success rate; firmware occasionally re-associates before
    security clear takes effect, causing EAPOL timeout
  - With realistic intervals (>5s), cycling is reliable

#### Interface cycling test results

| Scenario | Result |
|----------|--------|
| AP restart while connected | ✓ auto-recovers |
| Single down/up cycle | ✓ reliable |
| 5x rapid cycling (2s gap) | ~3/5 pass |
| Reconnect after >5s gap | ✓ reliable |

### Milestone 11: Latency optimization (TODO)

### Milestone 13: ifconfig scan support (COMPLETE)

- [x] Populate ieee80211_scan_entry from brcmf_scan_result
- [x] Feed results into net80211 scan cache via ieee80211_add_scan
- [x] Support `ifconfig wlan0 list scan`
- [x] Fix sp->tstamp NULL crash in sta_add
- [x] IE offset (128-byte fallback when ie_offset=0 and ie_length=0)
- [x] RSN/WPA IEs correctly parsed and visible in scan output

## Known issues

- wpa_supplicant prints `ioctl[SIOCS80211, op=20]: Invalid argument`
  at startup. This is the DELKEY ioctl during key flush — benign, does
  not affect functionality.
- Rapid interface cycling (<2s between down and up) fails ~40% of the
  time. The firmware occasionally re-associates with stale encryption
  keys before the `wsec=0` clear takes effect, causing the AP to
  deauth after EAPOL timeout. Realistic reconnect intervals (>5s) are
  reliable.

## Code structure

| Module | Purpose | Lines |
|--------|---------|-------|
| pcie.c | PCIe bus: BAR mapping, DMA, ring alloc, interrupts, firmware load | ~1160 |
| msgbuf.c | msgbuf protocol: ring ops, D2H processing, IOCTL, TX/RX | ~1300 |
| cfg.c | net80211: VAP lifecycle, attach/detach, link events, transmit | ~600 |
| cfg.h | Shared definitions for cfg/scan/security modules | ~210 |
| scan.c | Scan: escan requests, result processing, chanspec conversion | ~410 |
| security.c | Security: wsec/wpa_auth, key installation, PSK | ~180 |
| core.c | Chip core management: enumeration, reset, firmware download | ~310 |
| fwil.c | Firmware interface: IOVAR get/set | ~120 |
| brcmfmac.zig | EROM parser (pure Zig) | ~220 |
