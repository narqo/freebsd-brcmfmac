# Known Issues

## Data path

### RX completions missing

**Status:** Open
**Severity:** Critical (no data connectivity)

Firmware consumes all 255 RXPOST buffers (RXPOST_r=255) but never writes
RX completions (RX_w=0). TX works (TX_STATUS status=0, OTA delivery confirmed).

**Suspected causes:**
1. RX complete ring w_idx address mismatch
2. Firmware may use DMA index buffer instead of TCM for write pointers
3. Missing iovar to enable RX data delivery
4. RX buffer DMA format issue

**Next steps:**
1. Dump TCM around expected RX_w address to find where firmware writes
2. Check shared flags 0x20000 meaning
3. Try additional iovars (wsec, arpoe, etc.)

## Module lifecycle

### Rapid kldload/kldunload cycle crashes

**Status:** Open
**Severity:** Medium (normal load/unload works)

Rapid cycling of kldload/kldunload (3 cycles with 3s gaps) causes VM crash.
Normal load/unload with proper teardown works reliably.

Likely cause: firmware not fully reset between cycles, or DMA memory
accessed by firmware after unload completes.

### scan_curchan_task crash during teardown

**Status:** Fixed
**Severity:** Was High (prevented kldunload)

Root cause: swscan's `scan_curchan_task` accesses `ss->ss_vap->iv_debug`
(offset 0x6a) via `IEEE80211_DPRINTF` before checking abort flags. If
`ss_vap` is NULL (never set by `ieee80211_swscan_start_scan_locked`),
the kernel faults at address 0x6a.

Fix (two parts):
1. Pre-set `ic->ic_scan->ss_vap = vap` in `brcmf_vap_create` so it's
   never NULL when scan tasks fire
2. Drain swscan tasks (`scan_start`, `scan_curchan`) in `brcmf_vap_delete`
   after `ieee80211_vap_detach` but before freeing VAP memory. Uses
   knowledge of swscan private struct layout (`struct brcmf_scan_priv`).

## Association

### BSSID incorrectly retrieved

**Status:** Worked around

`BRCMF_C_GET_BSSID` returns garbage. Workaround: save BSSID during join.

## Scan support

### ieee80211_add_scan crashes

**Status:** Open

Calling `ieee80211_add_scan()` crashes. Scan results cached internally;
direct join works.

## BSS info structure

### Structure alignment issues

**Status:** Worked around

`brcmf_bss_info_le` doesn't match firmware layout. Using raw byte offsets
for chanspec (offset 72) and RSSI (offset 78).
