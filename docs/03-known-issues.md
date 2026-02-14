# Known Issues

## Association

### BSSID not correctly retrieved after association

**Status:** Open  
**Severity:** Low (cosmetic)

After link up, `BRCMF_C_GET_BSSID` returns incorrect/garbage BSSID values.
The association itself works correctly.

**Symptoms:**
- dmesg shows random BSSID like `82:e6:fc:66:1c:ce` instead of actual AP BSSID
- ifconfig shows this incorrect BSSID

**Workaround:**
- Association still works; this is cosmetic

**Next steps:**
1. Check if BSSID ioctl needs different buffer handling
2. Verify endianness of returned data

## Scan support

### ieee80211_add_scan crashes

**Status:** Open  
**Severity:** Medium (scan results not visible in ifconfig wlan0 scan)

Calling `ieee80211_add_scan()` from taskqueue context crashes the kernel.

**Workaround:**
- Scan results are cached internally; direct join works
- ieee80211_add_scan call is disabled

**Next steps:**
1. Check if IEEE80211_LOCK is required
2. Verify scan state machine expectations
3. Compare with other drivers (iwm, rtwn)

## BSS info structure alignment

**Status:** Worked around  
**Severity:** Low

The `brcmf_bss_info_le` structure definition doesn't match firmware data layout.
Chanspec is at offset 72 (not 71), RSSI at offset 78.

**Workaround:**
- Using raw byte offsets instead of structure fields for critical data
