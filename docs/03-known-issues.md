# Known Issues

## Open

### 5GHz limited to HT40

Firmware reports `bw_cap(5G)=0x1` (20MHz cap). `BRCMF_C_DOWN` returns NOTDOWN,
so the cap cannot be changed at runtime. The firmware still negotiates HT40+
in practice. Net80211 reports `11a ht/40+`.

Root cause unclear — may be NVRAM/firmware default or DFS channel limitation.

### Rapid interface cycling unreliable on DFS channels

Down/up cycles with <5s gaps do not complete WPA2 association in time on DFS
channels (ch60). The firmware takes longer to teardown and rejoin on DFS channels
due to radar detection and CAC requirements.

5s gaps: reliable (5/5 in testing on ch60). 2s gaps: not enough — wpa_state
stays ASSOCIATING after 10s wait. No IOCTL timeouts or fw_dead with current fix.

2s-gap cycling with wpa_supplicant running additionally hits a deadlock in the
net80211 state machine (suspected lock ordering between `IEEE80211_LOCK` and
wpa_supplicant's ioctl dispatch). Requires VM reset. Not yet diagnosed.

### wpa_supplicant DELKEY warning at startup

```
ioctl[SIOCS80211, op=20]: Invalid argument
```

Benign — wpa_supplicant flushes keys on an empty keyring at startup. No functional
impact.

### Long downloads stall on DFS channels

100MB downloads stall after ~24s on ch116 (DFS). 10MB transfers complete reliably.
Likely AP/ISP issue rather than driver — no driver-side fix identified.

---

## Resolved

### IOCTL timeouts cascading into fw_dead during DFS cycling (FIXED)

On DFS channels the firmware is busy with radar detection/CAC and doesn't
respond to host ioctls for several seconds after DISASSOC. Three consecutive
2s timeouts set `fw_dead`, making the driver permanently unusable until
kldunload/kldload. Happened on every rapid down/up cycle on ch60.

Two fixes:
1. `brcmf_key_delete`: skip `wsec_key` ioctl when `!sc->running`. Net80211
   calls `iv_key_delete` on every down; on DFS the firmware timed out here
   first. `brcmf_parent` already clears `wsec`/`wpa_auth`, so key delete
   is redundant.
2. Removed `ioctl_timeouts → fw_dead` escalation from `brcmf_msgbuf_ioctl`.
   Individual ioctl timeouts during teardown are expected on DFS channels and
   should not permanently kill the driver. `fw_dead` is now set only by the
   watchdog (BAR0 returns 0xffffffff), which detects true chip death.

### kldunload/cycling deadlock with fw_dead (PARTIALLY FIXED)

With `fw_dead=1`, `kldunload` hung because `ieee80211_ifdetach` internally
spins on `ieee80211_com_vdetach` waiting for COM refs to drop, while ioctl
threads holding those refs were sleeping waiting for firmware responses.

Fixed by:
- Setting `sc->detaching=1` and `sc->fw_dead=1` at the top of
  `brcmf_pcie_detach` with `wakeup` on all blocked waiters, before
  `ieee80211_ifdetach`.
- Draining `link_task` and `restart_task` before `ieee80211_ifdetach`.
- Gating `brcmf_link_task`, `brcmf_newstate`, and `brcmf_parent` on
  `!sc->detaching` to prevent new firmware ioctls during detach.

Verified: kldunload after 5s-gap cycling with wpa_supplicant running is clean.



### High latency and D2H ring processing in interrupt context (FIXED, M16)

Was caused by D2H ring processing running in the hard-IRQ filter handler, and
concurrently in ioctl/flowring polling loops. Fixed by moving all D2H processing
to a dedicated `brcmfmac_isr` taskqueue. Steady-state ping: ~4.6ms.

### Memory leak on unload (FIXED, M16)

64-byte leak (flowring struct) in the cleanup path. Fixed by freeing the struct
in the error/cleanup path of flowring delete.

### Rapid kldload/kldunload cycle crashes (FIXED, M15/M16)

Was caused by COM+node lock held across firmware ioctls (tsleep). Fixed by
dropping both locks in `brcmf_key_set`/`brcmf_key_delete` before the ioctl.
Interface cycling (including VAP destroy/recreate) now passes reliably.

### BSSID incorrectly retrieved (WORKED AROUND)

`BRCMF_C_GET_BSSID` returns garbage. BSSID is saved at join time in
`sc->join_bssid` and used wherever the BSSID is needed.

### ifconfig scan not supported (FIXED, M13)

`ifconfig wlan0 list scan` now works. Scan results from firmware escan are fed
into net80211's scan cache via `ieee80211_add_scan`.

### ieee80211_add_scan crashes (FIXED, M10/M13)

Was caused by a NULL `sp->tstamp` pointer in `sta_add`. Fixed. All scan results
are now delivered to net80211 correctly.

### BSS info structure alignment (FIXED, M14)

`brcmf_bss_info_le` was declared `__packed` (117 bytes), misaligning chanspec,
RSSI, and subsequent fields. Removed `__packed`; natural alignment (128 bytes)
matches firmware layout.

### WPA/WPA2 not implemented (FIXED, M10)

WPA2-PSK and WPA2-PSK-SHA256 both work. Host supplicant (wpa_supplicant) manages
the 4-way handshake. Pairwise and group AES-CCM keys install correctly.

### RX completions missing (FIXED, M8)

Was caused by net80211's `ieee80211_vap_transmit` encapsulating frames into 802.11
before the `ic_transmit` callback. FullMAC firmware expects raw ethernet. Fixed by
overriding VAP's `if_transmit` to bypass net80211 encapsulation.

### scan_curchan_task crash during teardown (FIXED, M8/M10)

swscan's `scan_curchan_task` accesses `ss->ss_vap->iv_debug` before checking abort
flags. Fixed by pre-setting `ss_vap` in vap_create and draining swscan tasks in
vap_delete.

### Re-join storm disrupting RX (FIXED, M8)

`brcmf_scan_complete_task` issued SET_SSID on every scan finding the target BSS,
even when already associated. Fixed with `link_up` guard.

### Socket buffer corruption under heavy RX (FIXED, M16)

`sbcut_internal` page fault (fault_addr=0x8) under iperf3 download. Concurrent
D2H ring processing from filter handler and ioctl polling loop allowed the same
RX completion to be processed twice. Fixed by ISR taskqueue refactor.

### Crash in detach on failed attach (FIXED, M16)

`brcmf_cfg_detach` called `sysctl_ctx_free` on uninitialized context and
`ieee80211_ifdetach` on unattached ic when `brcmf_cfg_attach` failed early.
Fixed with `cfg_attached` guard.

### Firmware stale encryption keys on reassociation (FIXED, M12)

Firmware retains keys across DISASSOC; encrypted EAPOL frame 2/4 on next join
caused AP deauth. Fixed by clearing `wsec=0` and `wpa_auth=0` synchronously in
`brcmf_parent` on interface down.

### RSN IE mismatch (FIXED, M10)

Firmware RSN IE capabilities `0x000c` (16 PTKSA replay counters) did not match
wpa_supplicant's `0x0000`. Fixed by injecting a synthetic WMM IE into scan results,
causing wpa_supplicant to set `wmm_enabled=1` and produce matching capabilities.

### D2H ring wraparound (FIXED, M16)

Available-entry calculation missed the wrapped portion of the ring (`w_ptr < r_ptr`
case). TX completions in the wrapped region were never processed under heavy traffic,
stalling TX permanently. Fixed in all three D2H rings.
