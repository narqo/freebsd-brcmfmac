# Known Issues

## Data path

### RX not working

**Status:** Open  
**Severity:** Critical (no data connectivity)

After successful flowring creation and TX submission, no RX completions are received
from firmware. TX packets are submitted but responses not received.

**Symptoms:**
- Flowring creates successfully (status 0)
- TX function called, packets submitted
- No RX completions in D2H RX complete ring
- DHCP/ping fails with 100% packet loss

**Suspected causes:**
1. RX buffers not properly associated with interface
2. May need iovar to enable data path
3. Ring index address calculation may be wrong

**Next steps:**
1. Verify RX buffer posting format
2. Check if "wsec" or "wlfc_mode" iovars needed
3. Compare ring setup with Linux driver
4. Add debug to interrupt handler to verify RX ring activity

## Association

### BSSID incorrectly retrieved

**Status:** Worked around  
**Severity:** Low (cosmetic)

`BRCMF_C_GET_BSSID` ioctl returns garbage data instead of actual associated BSSID.

**Workaround:**
- Save BSSID during join (`sc->join_bssid`) and use that instead

## Scan support

### ieee80211_add_scan crashes

**Status:** Open  
**Severity:** Medium (scan results not visible in ifconfig wlan0 scan)

Calling `ieee80211_add_scan()` crashes the kernel.

**Workaround:**
- Scan results cached internally; direct join works
- `ieee80211_add_scan` call disabled

### net80211 scan state machine causes crashes

**Status:** Worked around  
**Severity:** High (was causing crashes)

net80211's `scan_curchan_task` crashes when trying to send probe requests because
it expects SoftMAC behavior (node management, channel iteration).

**Workaround:**
- Override `ic_scan_curchan` with no-op function
- Removed `IEEE80211_C_BGSCAN` and `IEEE80211_C_MONITOR` capabilities

## BSS info structure

### Structure alignment issues

**Status:** Worked around  
**Severity:** Low

The `brcmf_bss_info_le` structure definition doesn't match firmware data layout.
Chanspec is at offset 72 (not 71), RSSI at offset 78.

**Workaround:**
- Using raw byte offsets instead of structure fields for critical data
