# Known Issues

## Data path

### High latency

**Status:** Open
**Severity:** Low (functional but suboptimal)

Ping latency averages 35-40ms with spikes to 80-115ms. Likely causes:
- D2H ring processing in interrupt filter context
- Power management (SET_PM=0 may not be fully effective)
- Interrupt coalescing in firmware

## Module lifecycle

### Memory leak on unload

**Status:** Open
**Severity:** Low

```
Warning: memory type brcmfmac leaked memory on destroy (1 allocations, 64 bytes leaked).
```

One 64-byte allocation not freed. Likely a ring structure or control buffer.

### Rapid kldload/kldunload cycle crashes

**Status:** Open
**Severity:** Medium (normal load/unload works)

Rapid cycling of kldload/kldunload (3 cycles with 3s gaps) causes VM crash.
Normal load/unload with proper teardown works reliably.

Likely cause: firmware not fully reset between cycles, or DMA memory
accessed by firmware after unload completes.

## Association

### BSSID incorrectly retrieved

**Status:** Worked around

`BRCMF_C_GET_BSSID` returns garbage. Workaround: save BSSID at join time
in `sc->join_bssid`.

## Scan support

### ifconfig scan not supported

**Status:** Open
**Severity:** Low (association works)

`ifconfig wlan0 list scan` doesn't work. Scan results are cached internally
and used for direct join, but not fed into net80211's scan cache.

### ieee80211_add_scan crashes

**Status:** Open

Calling `ieee80211_add_scan()` crashes. Avoided by using internal scan
result cache.

## BSS info structure

### Structure alignment issues

**Status:** Worked around

`brcmf_bss_info_le` doesn't match firmware layout. Using raw byte offsets
for chanspec (offset 72) and RSSI (offset 78).

## Security

### WPA/WPA2 not implemented

**Status:** Open
**Severity:** High (blocks real-world use)

Only open authentication works. WPA/WPA2 requires setting wsec, wpa_auth,
and PMK via firmware ioctls.

---

## Resolved issues

### RX completions missing (FIXED)

Was caused by net80211's `ieee80211_vap_transmit` encapsulating frames
into 802.11 before our `ic_transmit` callback. FullMAC firmware expects
raw ethernet. Fixed by overriding VAP's `if_transmit` to bypass net80211
encapsulation.

### scan_curchan_task crash during teardown (FIXED)

Root cause: swscan's `scan_curchan_task` accesses `ss->ss_vap->iv_debug`
before checking abort flags. Fixed by pre-setting `ss_vap` in vap_create
and draining swscan tasks in vap_delete.

### Re-join storm disrupting RX (FIXED)

`brcmf_scan_complete_task` issued SET_SSID on every scan finding target
BSS, even when already associated. Fixed with `if (sc->link_up) return`
guard.
