# Progress Tracker

## Current status

**Milestones 1-14 complete. M15 blocked on hardware, M16 in progress.**
Driver connects to WPA2 APs on 2.4GHz and 5GHz, handles link loss
recovery, interface cycling. Throughput testing (M15) revealed crashes
under heavy RX load — root-caused to concurrent D2H ring processing
and hard-IRQ packet delivery. Fixed via ISR taskqueue (M16), awaiting
hardware power cycle to verify.

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

### Milestone 11: Latency optimization (COMPLETE)

- [x] PM=0 (power management off) — already set in brcmf_parent
- [x] mpc=0 (minimum power consumption off) — keeps radio on during idle
- [x] roam_off=1 (disable firmware roaming) — eliminates background scans
- [x] HT rates: ic_htcaps, 11ng/11na modes, HT20 channel selection
- [x] BSS node HT flags and MCS rate set (MCS 0-7, nominal MCS 7 = 72 Mbps)
- [x] Fixed ieee80211_find_channel to use frequency (was passing channel number)

#### Latency results

| Metric | Before | After |
|--------|--------|-------|
| Steady-state ping | ~7ms | ~4.6ms |
| After 30s idle | ~7ms (sleep) | ~4.6ms (no penalty) |
| Flood ping (100x, 10ms interval) | — | avg 1.8ms, min 1.3ms |
| Jitter (stddev) | — | 1.4ms |

#### Rate negotiation

| Metric | Before | After |
|--------|--------|-------|
| ifconfig mode | 11b / DS / 1Mbps | 11ng / MCS / 72M |
| HT caps | none | SGI20, SGI40, DSSSCCK40, SMPS_OFF |
| Channel | 2412 MHz 11b | 2412 MHz 11g ht/20 |

### Milestone 12: Robustness (COMPLETE)

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

#### Interface cycling test results

| Scenario | Result |
|----------|--------|
| AP restart while connected | ✓ auto-recovers |
| Single down/up cycle | ✓ reliable |
| Reconnect after >5s gap | ✓ reliable |
| 5x rapid cycling (2s gap) | ~3/5 pass (known issue) |

### Milestone 13: ifconfig scan support (COMPLETE)

- [x] Populate ieee80211_scan_entry from brcmf_scan_result
- [x] Feed results into net80211 scan cache via ieee80211_add_scan
- [x] Support `ifconfig wlan0 list scan`
- [x] Fix sp->tstamp NULL crash in sta_add
- [x] IE offset (128-byte fallback when ie_offset=0 and ie_length=0)
- [x] RSN/WPA IEs correctly parsed and visible in scan output

### Milestone 14: 5GHz and HT40 (COMPLETE)

- [x] Fixed brcmf_bss_info_le struct alignment (removed __packed, sizeof=128)
- [x] Fixed scan result channel→frequency conversion in brcmf_add_scan_result
- [x] HT40 channel support (CHWIDTH40 htcap, HT40U/HT40D channels)
- [x] VHT capability advertisement (2SS MCS 0-9, SGI80, RXLDPC)
- [x] D11AC chanspec decoding for 5GHz/HT40/VHT80 in scan results
- [x] 5GHz default rates IE for scan results
- [x] Firmware country code (DE) via "country" iovar
- [x] SKU_DEBUG regdomain to bypass channel filtering
- [x] All 5GHz channels including DFS (36-165)
- [x] RSSI display fixed (dBm relative to noise floor)
- [x] link_task selects VHT/HT40/HT20 channel based on firmware chanspec
- [x] VHT node flags on 5GHz association
- [x] 5GHz WPA2 association + ping (Kolabox, channel 60, HT40+)
- [x] 2.4GHz regression passes (TestAP, channel 1)
- [x] DEAUTH/DISASSOC event handling (E_DEAUTH, E_DEAUTH_IND, E_DISASSOC, E_DISASSOC_IND)
- [x] Fixed brcmf_assoc_params_le (removed spurious bssid_cnt field)
- [x] Guard link_task state transition (skip SCAN if VAP already in INIT)
- [x] 5GHz→2.4GHz→5GHz cycling passes without crash

#### 5GHz test results (Kolabox, channel 60 VHT80)

| Metric | Value |
|--------|-------|
| Association | ✓ channel 60, 5300 MHz, 11a ht/40+ |
| WPA2 handshake | ✓ AES-CCM keys installed |
| DHCP | ✓ lease from 192.168.188.1 |
| Gateway ping (100x, 10ms interval) | avg 1.8ms, 0% loss |
| Jitter (stddev) | 0.5ms |

### Milestone 15: Throughput and real-world testing (IN PROGRESS)

- [x] Ping flood: 1000 packets 0% loss, avg 1.15ms (5GHz gateway)
- [x] Internet download via fetch: 13 Mbps (ISP-limited, not WiFi)
- [x] 5GHz→2.4GHz→5GHz cycling: passes
- [x] Large fetch: 3×10MB over WiFi, no crash (ISP-limited ~19 Mbps)
- [x] Throughput: ~14 Mbps download (ISP-limited), 10MB transfers stable
- [ ] Open network association (no WPA)
- [ ] WPA2-PSK (non-SHA256) with different APs

#### Findings

- **Firmware bw_cap(5G)=0x1 (20MHz only)**: firmware negotiates HT40
  despite advertising VHT in scan. The `bw_cap` iovar requires interface
  down, but the firmware auto-ups at boot; `BRCMF_C_DOWN` returns
  NOTDOWN. Root cause unclear — may be NVRAM/firmware default or
  DFS channel limitation. Net80211 reports `11a ht/40+`.
- **Kernel crash under heavy RX traffic (core.txt.3, FIXED)**: iperf3
  download caused page fault in `sbcut_internal` at `fault_addr=0x8`
  (NULL mbuf deref). Socket buffer accounting (`sb_ccc`) was corrupt.
  Root cause: concurrent D2H ring processing from two contexts — the
  hard-IRQ filter handler and the ioctl polling loop — with no locking.
  Same RX completion could be processed twice, corrupting mbuf chains.
  Fixed by moving all D2H processing to a dedicated ISR taskqueue and
  removing D2H polling from wait loops. Verified: sustained downloads
  no longer crash.
- **Crash in detach on failed attach (core.txt.5/6, FIXED)**: When
  `brcmf_cfg_attach` fails early (firmware ioctl timeout),
  `brcmf_cfg_detach` called `sysctl_ctx_free` on uninitialized context
  and `ieee80211_ifdetach` on unattached ic. Fixed with `cfg_attached`
  guard.
- **COM/node lock panic (core.txt.1/2/7, FIXED)**: Thread held COM +
  node lock in `sta_newstate` → `ieee80211_sta_leave` →
  `brcmf_key_delete` → `brcmf_msgbuf_ioctl` (`tsleep`). Fixed:
  `brcmf_key_set`/`brcmf_key_delete` drop both COM and node locks
  around firmware ioctl. Verified: interface cycling no longer panics.
- **Chip stuck after crash**: After kernel panic, PCI device returns
  0xffffffff on BAR0 MMIO reads. D3→D0 power cycle doesn't help.
  Physical host power cycle required (QEMU PCI passthrough limitation).
- **`brcmf_fil_bss_down` was passing val=1 (FIXED)**: Linux driver
  passes 0 for `BRCMF_C_DOWN`.

### Milestone 16: Production hardening (IN PROGRESS)

- [x] Move D2H processing from filter handler to ISR taskqueue
- [x] Remove concurrent D2H polling from ioctl/flowring wait loops
- [x] Guard `brcmf_cfg_detach` against partial attach (`cfg_attached`)
- [x] Fix `brcmf_fil_bss_down` to pass val=0
- [x] Fix COM lock deadlock (drop COM in `brcmf_key_set`/`brcmf_key_delete`)
- [x] Watchdog: `fw_dead` flag, BAR0 liveness callout, fast ioctl bail-out
- [ ] Firmware crash recovery (core dump, reload)
- [x] Memory leak fix (flowring struct freed in cleanup path)
- [x] Error path review (TX DMA tag/map cleanup, callout_init ordering)
- [x] Locking audit (ioctl_mtx serialization, removed unused scan_mtx)
- [x] sysctl tuning interface (dev.brcmfmac.0.pm, debug, psk)

### Milestone 17: Integration (TODO)

- [ ] FreeBSD port or package
- [ ] rc.conf integration (auto-load, auto-configure)
- [ ] man page
- [ ] devd rules for device attach/detach
- [ ] Multiple VAP support (if needed)

## Known issues

- ~~RX in hard interrupt context~~: Fixed. Split into filter + ISR
  taskqueue. Tested: 3×10MB downloads, 1000-pkt flood, no crash.
- ~~COM/node lock held across sleep~~: Fixed. `brcmf_key_set`/
  `brcmf_key_delete` drop COM and node locks around firmware ioctl.
  Tested: 3 interface cycles + band switch, no crash.
- **5GHz limited to HT40**: Firmware reports `bw_cap(5G)=0x1` (20MHz).
  Setting `bw_cap` requires `BRCMF_C_DOWN` but the firmware auto-ups
  at boot and rejects DOWN with NOTDOWN. Actual negotiated mode on
  5GHz ch60 is HT40+ (chanspec 0xd83e, bw=3). VHT80 channel lookup
  code is correct but never triggered.
- wpa_supplicant prints `ioctl[SIOCS80211, op=20]: Invalid argument`
  at startup. This is the DELKEY ioctl during key flush — benign.
- Rapid interface cycling (<2s between down and up) fails ~40% of the
  time. Firmware re-associates with stale keys before `wsec=0` clears.
  Intervals >5s are reliable.
- Memory leak on unload: 1 allocation, 64 bytes.

## Code structure

| Module | Purpose |
|--------|---------|
| pcie.c | PCIe bus: BAR mapping, DMA, ISR taskqueue, firmware load |
| msgbuf.c | msgbuf protocol: ring ops, D2H processing, IOCTL, TX/RX |
| cfg.c | net80211: VAP lifecycle, attach/detach, link events, transmit |
| cfg.h | Shared definitions for cfg/scan/security modules |
| scan.c | Scan: escan requests, result processing, chanspec conversion |
| security.c | Security: wsec/wpa_auth, key installation, PSK |
| core.c | Chip core management: enumeration, reset, firmware download |
| fwil.c | Firmware interface: IOVAR get/set |
| brcmfmac.h | Main driver header: softc, firmware structs, constants |
| brcmfmac.zig | EROM parser (pure Zig) |
