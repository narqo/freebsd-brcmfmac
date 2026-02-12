# Known Issues

## Scan support

### ieee80211_add_scan crashes

**Status:** Open  
**Severity:** Medium (scan results not visible in ifconfig wlan0 scan)

Calling `ieee80211_add_scan()` from taskqueue context crashes the kernel.
The crash happens even with valid parameters (non-NULL channel, valid rates IE).

**Symptoms:**
- Kernel panic when scan results are reported to net80211
- VM reboots immediately

**Investigation notes:**
- Channel pointer is valid (verified with debug prints)
- Default rates IE provided (required by sta_add KASSERT)
- Crash happens inside ieee80211_add_scan, not in our code
- May be related to scan state machine expectations
- Possibly needs IEEE80211_LOCK held or specific vap state

**Workaround:**
- Scan results are cached and printed to dmesg
- ieee80211_add_scan call is disabled

**Next steps:**
1. Check if IEEE80211_LOCK is required around ieee80211_add_scan
2. Verify scan state machine is in correct state (ISCAN_DISCARD flag?)
3. Compare with other drivers (iwm, rtwn) for proper usage pattern

### Subsequent escan timeouts

**Status:** Open  
**Severity:** Medium

After the first successful escan, subsequent escans timeout with ETIMEDOUT (60).

**Symptoms:**
- First escan works correctly
- Second and subsequent escans fail with "IOCTL timeout cmd=0x107"
- Error 60 (ETIMEDOUT) returned

**Investigation notes:**
- May be IOCTL queue state issue
- Possibly need to clear/reset some firmware state between scans
- Event buffer re-posting might be needed

**Workaround:**
- First scan works; module reload needed for subsequent scans

**Next steps:**
1. Check if event buffers need re-posting after consumption
2. Investigate IOCTL completion state machine
3. Check if firmware needs explicit scan abort before new scan

## BSS info structure alignment

**Status:** Worked around  
**Severity:** Low

The `brcmf_bss_info_le` structure definition doesn't match firmware data layout.
Chanspec is at offset 72 (not 71), RSSI at offset 78.

**Workaround:**
- Using raw byte offsets instead of structure fields for critical data
- BSSID, SSID_len, SSID work correctly via structure

**Next steps:**
- Compare structure with Linux driver definition
- May need padding bytes or different field ordering
