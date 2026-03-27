# Investigations

## 27 Mar 2026: register fixes applied, bsscfg encoding bug, firmware console

### Register fixes applied and tested

All three register bugs from 26 Mar fixed and consolidated into
`brcmfmac.h`. Boot mailbox now reads FWREADY + protocol version 4.
Runtime ACK sends correct value (0x02). FC bits correct.

AUTH timeout persists — register bugs were real but not sufficient.

### Firmware console reader

Added sysctl `dev.brcmfmac.0.fwcon` — reads CYW43455 internal log
via F1 backplane byte reads. Console structure at `shared.console_addr`
(stored during firmware boot from sdpcm_shared offset 20).

Console revealed `join BCME -14 (Buffer too short)`, not BCME_NOTREADY
as previously assumed. Error was masked because ioctl layer returns
generic EIO for all firmware errors.

### bsscfg encoding bug (FIXED)

`brcmf_fil_bsscfg_data_set` always prepended a 4-byte bsscfg index.
Linux's `brcmf_create_bsscfg` sends a plain iovar (no prefix, no
index) when `bsscfgidx == 0`. Our code sent `"join\0" + le32(0) +
ext_join_params`, which made the firmware parse the 4-byte index as
the start of ssid_le, corrupting the entire join command.

Fix: `bsscfg_idx == 0` now routes to `brcmf_fil_iovar_data_set`.
Non-zero indices use the `"bsscfg:" + name + idx + data` encoding.
Also matched Linux's `join_params_size` calculation.

Result: `join` iovar now succeeds (firmware console confirms error
gone). But AUTH still times out.

### btc_mode=0 — no change

Firmware logs `FIXME bt_coex` during radio init. `btc_mode=0` iovar
did not resolve AUTH timeout.

### Current status

All known protocol/encoding bugs fixed. `join` iovar works. Firmware
accepts join command. AP never sees auth frames — firmware is not
transmitting. Root cause still unknown.

### fwcon sysctl panic (FIXED)

Reading the fwcon sysctl while the DPC thread was running caused
`camq_remove: out-of-bounds index -3` — concurrent SDIO bus access
from two threads corrupts CAM queue state. Fixed: both diag and
fwcon sysctls now pause the DPC thread during bus access.

### Firmware console reveals: "authentication failure, no ack"

With msglevel enabled (8-byte GET+OR+SET), the firmware console
shows during the join attempt:

```
JOIN: authentication failure, no ack
JOIN: authentication failure, no ack
JOIN: authentication failure, no ack
```

The firmware IS transmitting 802.11 auth frames. But the AP does
not ACK them at the MAC layer. This is a PHY/radio-level issue,
not a protocol/iovar issue.

### join iovar vs SET_SSID: different failure modes

With `join` iovar (now working): firmware scans, finds the AP,
attempts auth → "authentication failure, no ack". Firmware IS
transmitting on the correct channel (post-join chanspec=0x1001
confirmed). TX power = 127 qdBm (31.75 dBm, max).

With `SET_SSID` fallback (join skipped): firmware reports
status=3 (NO_NETWORKS) — AP not in scan cache because escan
was aborted before join.

The `join` path is correct — it includes scan params so firmware
finds the AP. The "no ack" means the AP's radio doesn't receive
or acknowledge the auth frame. AP debug log confirms no frames
received from our MAC.

### msglevel behavior

`msglevel` GET returns 0x00000001 (WL_ERROR only). SET to
0xFFFFFFFF returns 0. But firmware doesn't produce verbose
console output during join/auth — only error-level messages
("no ack"). Production firmware (CYW 7.45.265) likely has most
debug prints compiled out. The "JOIN: authentication failure,
no ack" message is at WL_ERROR level and appears without
msglevel changes.

### wl_open count reduced from 3 to 1 — no change

Removed redundant `bss_up` + `set_infra` from `brcmf_parent`.
Now only one `wl_open` occurs (during `brcmf_cfg_attach` `bss_up`).
AUTH timeout unchanged.

### C_UP/C_DOWN payload fixed to match Linux

Linux sends `C_UP` with 4-byte LE int payload (value 0), and `C_DOWN`
with value 1. We were sending no payload at all. Fixed
`brcmf_fil_bss_up`/`brcmf_fil_bss_down` to use
`brcmf_fil_cmd_data_set` with the correct int payload. AUTH timeout
unchanged, but the fix is correct per Linux behavior.

### Country code removed — no change

Without `country` iovar, firmware defaults to `US/US rev=0`.
Same AUTH timeout. Country is not the cause.

### msglevel persistence issue

`msglevel` SET (8-byte, to 0xFFFFFFFF) succeeds (returns 0) but
firmware console output only grows during some loads and not others.
Likely the `wl_open` (triggered by `C_UP`) resets msglevel after
we set it, OR the firmware join/auth path in this production build
(CYW 7.45.265) has most debug prints compiled out. The "no ack"
message was confirmed on one earlier run but is not consistently
reproducible in the console.

### Confirmed: firmware transmits auth frames

The firmware console confirmed `JOIN: authentication failure, no ack`
on an earlier run. The firmware IS transmitting auth frames on the
correct channel (chanspec 0x1001 = ch1/2GHz confirmed post-join).
But the AP doesn't ACK them. The AP's debug log confirms no frames
received from our MAC.

TX power is 127 qdBm (31.75 dBm, max). AP is at -60 dBm RSSI.
Same firmware + NVRAM works on Linux RPi4.

### btc_mode=0 — FALSE POSITIVE, not the fix (27 Mar 2026)

**Initial test (kldunload/kldload without reboot):** Changed NVRAM
`btc_mode=1` → `btc_mode=0`. Association succeeded once. Firmware
showed `link up`. Concluded this was the fix.

**After reboot:** Association **fails again** with AUTH timeout.
Same `FIXME bt_coex` message, same E_AUTH status=2 pattern.

**Conclusion:** The mid-session success was a **false positive**.
The firmware wasn't fully reset between kldunload/kldload — residual
state from the first load allowed the second load to work. After a
clean reboot, `btc_mode=0` has no effect.

The AUTH timeout root cause is **still unknown**.

### Current status

- AUTH timeout persists after reboot
- `FIXME bt_coex` appears during every `wl_open`
- Firmware console shows no "no ack" messages (widx unchanged)
- `btc_mode=0` in NVRAM does NOT fix the problem

### NVRAM modification (not effective)

Changed `/boot/firmware/brcmfmac43455-sdio.txt`:
```
btc_mode=1  →  btc_mode=0  (two occurrences)
```

Backup at `/boot/firmware/brcmfmac43455-sdio.txt.bak`

---

## 26 Mar 2026: ROOT CAUSE FOUND — three SDIO core register bugs

**Priority: fix before any other work.**

Traced the full SDIO init and runtime path against the canonical Linux
source (`freebsdsrc/sys/contrib/dev/broadcom/brcm80211/brcmfmac/sdio.c`
and `sdio.h`). Found three bugs that break the SDIO mailbox protocol.
The firmware never receives a proper host acknowledgment after boot.

### Bug 1: wrong register offset for tohostmailboxdata

Files: `src/sdio.c`, `src/sdpcm.c`

```c
#define SD_REG_TOHOSTMAILBOXDATA 0x044   // WRONG
```

The SDIO core register layout (from Linux `struct sdpcmd_regs`):

| Offset | Register            | Direction        |
|--------|---------------------|------------------|
| 0x040  | tosbmailbox         | host → firmware  |
| 0x044  | tohostmailbox       | firmware → host (control) |
| 0x048  | tosbmailboxdata     | host → firmware  |
| 0x04C  | tohostmailboxdata   | firmware → host (data)    |

We read 0x044 (the control register) when we should read 0x04C (the
data register). The firmware puts `HMB_DATA_FWREADY`, `HMB_DATA_DEVREADY`,
`HMB_DATA_FWHALT` etc. in the data register at 0x04C. We never see them.

Affected code:
- `sdpcm.c` `brcmf_sdpcm_hostmail()` — DPC runtime mailbox read
- `sdio.c` `brcmf_sdio_download_fw()` — boot-time mailbox read

Fix: `#define SD_REG_TOHOSTMAILBOXDATA 0x04C`

### Bug 2: wrong value for tosbmailbox INT_ACK

Files: `src/sdio.c`, `src/sdpcm.c`

```c
#define I_SMB_INT_ACK 0x020000   // WRONG — this is an intstatus bit position
```

The `tosbmailbox` register has its own bit layout, distinct from
`intstatus`. From Linux:

```c
#define SMB_NAK       (1 << 0)   /* 0x01 — Frame NAK */
#define SMB_INT_ACK   (1 << 1)   /* 0x02 — Host Interrupt ACK */
#define SMB_USE_OOB   (1 << 2)   /* 0x04 — Use OOB Wakeup */
#define SMB_DEV_INT   (1 << 3)   /* 0x08 — Miscellaneous Interrupt */
```

We write 0x020000 (bit 17 — reserved/undefined) to `tosbmailbox`.
The firmware expects bit 1 (0x02) for `SMB_INT_ACK`. The firmware
never sees our acknowledgment.

Affected code:
- `sdpcm.c` `brcmf_sdpcm_hostmail()` — runtime mailbox ACK
- `sdio.c` `brcmf_sdio_download_fw()` — boot-time mailbox ACK

Fix: define a separate `SMB_INT_ACK = 0x02` for the tosbmailbox
register and use it in both locations. Remove or rename the
intstatus-domain `I_SMB_INT_ACK` to avoid confusion.

### Bug 3: wrong intstatus bit definitions for FC_STATE and FC_CHANGE

File: `src/sdpcm.c` only (sdio.c has correct values)

```c
#define I_HMB_FC_STATE    0x000008   // WRONG — bit 3 is I_SMB_SW3 (to-SB)
#define I_HMB_FC_CHANGE   0x000010   // WRONG — bit 4 is I_HMB_SW0 (FC_STATE)
```

Correct values from Linux:

| Constant        | Ours (wrong) | Correct | Linux alias  |
|-----------------|-------------|---------|--------------|
| I_HMB_FC_STATE  | 0x08 (bit 3)| 0x10 (bit 4) | I_HMB_SW0 |
| I_HMB_FC_CHANGE | 0x10 (bit 4)| 0x20 (bit 5) | I_HMB_SW1 |
| I_HMB_FRAME_IND | 0x40 (bit 6)| 0x40 (bit 6) | I_HMB_SW2 ✓ |
| I_HMB_HOST_INT  | 0x80 (bit 7)| 0x80 (bit 7) | I_HMB_SW3 ✓ |

Bits 0-3 of `intstatus` are **to-SB** (host→firmware) mailbox bits.
Bits 4-7 are **to-host** (firmware→host) bits. Our FC_STATE at 0x08
is actually `I_SMB_SW3` — a to-SB bit the host must not acknowledge.

Effects of the wrong definitions:
- `brcmf_sdpcm_intr_rstatus` masks with 0xD8 instead of 0xF0
- Bit 3 (to-SB mailbox) is included in the acknowledge write-back,
  clearing a firmware-side interrupt bit
- Bit 5 (real FC_CHANGE) is never seen, so FC change processing
  never triggers
- Flow-control state from intstatus is read from the wrong bit

Fix: change definitions in sdpcm.c to match sdio.c / Linux:
```c
#define I_HMB_FC_STATE    0x000010
#define I_HMB_FC_CHANGE   0x000020
```

### Why these bugs cause AUTH timeout

Bugs 1+2 together mean the mailbox protocol is completely broken:

1. Firmware boots, sends `HMB_DATA_FWREADY | HMB_DATA_DEVREADY` in
   `tohostmailboxdata` (offset 0x04C)
2. We read the wrong register (0x044) — never see FWREADY
3. We write 0x020000 (reserved bit) to `tosbmailbox` — firmware
   never sees our ACK
4. Firmware's connection state machine stays in degraded/unready state

This explains the entire symptom pattern:

- **Scans work**: escan doesn't require full mailbox handshake
- **Ioctls work**: BCDC control exchange operates at SDPCM level
- **`join` returns BCME_NOTREADY (-14)**: firmware is literally
  not ready — connection state machine never fully enabled
- **`C_SET_SSID` accepted but AUTH times out**: firmware tries to
  auth but can't complete the exchange in degraded state
- **Same firmware works on Linux**: Linux writes correct ACK (0x02)
  to correct register, firmware fully initializes

The investigation notes say association worked once before the DPC
thread was added (M-S6). Before M-S6, there was no mailbox processing
— no reads, no acks. After M-S6, we added mailbox processing with
wrong register and wrong value. Writing 0x020000 to a reserved
tosbmailbox bit is actively worse than doing nothing — it may
confuse the firmware into an unrecoverable state.

Bug 3 is a secondary issue. It corrupts flow-control tracking and
acknowledges to-SB mailbox bits, but doesn't directly block the
auth exchange. Fix it together with bugs 1+2.

### Verification reference

Canonical Linux source in the tree:
- `freebsdsrc/sys/contrib/dev/broadcom/brcm80211/brcmfmac/sdio.h`
  lines 199-250 (`struct sdpcmd_regs` with register offsets)
- `freebsdsrc/sys/contrib/dev/broadcom/brcm80211/brcmfmac/sdio.c`
  lines 201-270 (I_SMB/I_HMB bit definitions, SMB_INT_ACK, HMB_DATA)

---

## 26 Mar 2026: DPC thread, struct alignment, SR init

DPC thread implemented (T1-T4). Single kernel thread owns all SDIO I/O.
Tested with interrupt processing at DPC top and without. No change to
AUTH timeout.

**Struct alignment fix**: `brcmf_join_params`, `brcmf_assoc_params_le`,
`brcmf_join_scan_params`, `brcmf_ext_join_params` were `__packed`.
Firmware expects natural alignment — 2 bytes padding after bssid[6]
before chanspec_num. Without it, SET_SSID with chanspec returned EIO.
Fixed: removed `__packed`, added explicit padding. SET_SSID with BSSID
+ chanspec now accepted (returns 0). AUTH still times out.

Also added: SR init (WAKEUPCTRL, CARDCAP, CHIPCLKCSR), CCCR IENx
interrupt enable. Neither changed AUTH behavior.

Bus noise test: reduced DPC polling to 50ms, removed intstatus reads
from recv path. No change — AUTH timeout is not caused by bus
activity during join.

AUTH timeout is intermittent — screenshot from 25 Mar shows TestAP
connected once (`ssid TestAP channel 1, 2412 MHz`). Current code
never succeeds. The working session was before the DPC thread was
added.

## 25 Mar 2026: AUTH timeout investigation — ruled-out causes

After the sdio-auth-ref audit fixes (proptxstatus removed, TX credits
enforced, attach ordering fixed, mailbox/FC processing added,
iv_mgtsend cancelled), the AUTH timeout persists on TestAP (open,
2.4GHz, channel 1). Every attempt: `C_SET_SSID` accepted, firmware
reports AUTH timeout (code=3 status=2) ~3s later.

Tested and ruled out:
- BSSID/chanspec variants in SET_SSID fallback params
- Escan abort timing (100ms, 500ms)
- Shared RAM structure validity (flags=1, no trap)
- wpaie iovar on CYW43455 (UNSUPPORTED, no state change)
- C_SET_INFRA removal from per-connect path
- Redundant bss_up in brcmf_parent

The DPC loop is the only remaining major structural gap.

## 25 Mar 2026: sdio-auth-ref audit — root cause of AUTH timeout

Systematic audit of `docs/sdio-auth-ref/` (authoritative Linux brcmfmac
SDIO reference) against the FreeBSD source code. Found 12 deviations,
3 critical. Full findings in `docs/00-progress.md` M-S6.

### Critical findings

1. **`proptxstatus_mode=1` actively harmful.** `cfg.c` sends this iovar
   on SDIO attach. The ref doc is explicit: Linux does NOT enable
   proptxstatus on the default SDIO path (`fcmode=NONE`,
   `always_use_fws_queue` not set). Sending it tells the firmware to
   expect TLV signaling metadata that the host never processes.

2. **TX credits not enforced.** `sdpcm_max_seq` is recorded from byte 9
   of every RX SDPCM header but `brcmf_sdpcm_send` never checks it.
   The ref doc states the check is mandatory: `((uint8_t)(tx_max -
   tx_seq)) & 0x80` must be zero before any transmission.

3. **No integrated DPC loop.** Linux runs all SDIO bus I/O (interrupt
   status, mailbox, RX, control TX, data TX) in one thread. The
   FreeBSD code splits these across a 50ms callout, a taskqueue task,
   inline ioctl polling, and direct TX calls.

### Other findings

- No BCDC `init_done` / fws_attach (Linux always creates fws object,
  even in reduced `avoid_queueing` mode on default SDIO)
- Attach ordering wrong (poll starts after cfg_attach, no bus-state-UP)
- `tlv=0` and `ampdu_hostreorder=1` sent unnecessarily
- Flow-control bitmap (SDPCM byte 8) never read
- Mailbox data content not interpreted (only read + acked)
- No error recovery (frame abort, NAK, rxskip)
- F2 block size 64 vs Linux's 512

### Method

Read both ref docs completely, then checked every claim against
`src/sdio.c`, `src/sdpcm.c`, `src/main.c`, `src/cfg.c`, and
`src/brcmfmac.h`. Documented each deviation with the exact code
location and the ref doc section that contradicts it.

### Conclusion

The AUTH timeout is caused by SDIO transport/runtime incompleteness,
not by net80211, WPA, or channel selection issues. The `proptxstatus_mode=1`
iovar is the most likely single-change fix candidate — it actively
changes firmware behavior in a way the host can't support.

---

## 22 Mar 2026: RPi4 net80211 attach success, escan BCME_UNSUPPORTED

### What works

- `brcmf_cfg_attach` completes on BCM43455 SDIO
- MAC address: `dc:a6:32:29:7b:1b`
- io_type: D11AC (not D11N as expected from spec)
- `bss_down`, `bss_up` succeed
- `event_msgs`, `mpc`, `roam_off` iovars succeed
- `cap` iovar returns: `ap sta wme 802.11d 802.11h rm cqa cac
  dualband ampdu ampdu_tx ampdu_rx amsdurx radio_pwrsave btamp
  p2p proptxstatus mchan p2po anqpo vht-prop-rates dfrts
  txpwrcache stbc-tx stbc-rx-1ss epno pfnx wnm bsstrans mfp
  sae_ext fbt`
- `ifconfig wlan0 create wlandev brcmfmac0` works
- `ifconfig wlan0 up` works (brcmf_parent runs, no crash)
- RX poll callout (20ms) running without panics

### What fails

| Iovar/cmd | fwerr | Meaning |
|-----------|-------|---------|
| `escan` (C_SET_VAR) | -4 | BCME_UNSUPPORTED |
| `C_SCAN` (cmd=50) | -4 | BCME_UNSUPPORTED |
| `country` (C_SET_VAR) | -2 | BCME_NOTFOUND |
| `C_SET_ROAM_TRIGGER` (cmd=55) | -10 | BCME_RANGE |
| `C_SET_ROAM_DELTA` (cmd=57) | -10 | BCME_RANGE |
| `sup_wpa` (C_GET_VAR) | -23 | BCME_BADARG |

### Firmware details

Firmware: `wl0: Aug 29 2023 01:47:08 version 7.45.265 (28bca26 CY)
FWID 01-b677b91b`

NVRAM: `txchain=1 rxchain=1` (1T1R, 1SS)

### BCME_UNSUPPORTED for C_SCAN is highly unusual

C_SCAN (cmd=50) is a fundamental firmware command. Returning
BCME_UNSUPPORTED means the firmware is either:
1. Not fully initialized (missing init step)
2. In a mode that doesn't support scanning (AP-only? monitor?)
3. Needs a specific sequence before scan is allowed

The Linux driver's SDIO init path includes steps we skip:
- `C_SET_GLOM` (cmd=89) with val=0
- `bus:txglomalign` and `bus:txglomsize` iovars
- `assoc_listen` iovar
- `ampdu_ba_wsize` iovar

None of these should gate scanning, but the firmware may have
internal state machine requirements.

### RX poll concurrency

Previous panic: `sleeping thread holds brcmfmac_ioctl` — caused
by RX poll task holding ioctl_mtx while SDIO I/O sleeps in CAM.

Fixed with `sdpcm_rx_busy` atomic flag: ioctl path sets it before
send+recv, RX task skips if set. Removed ioctl_mtx from RX task
entirely. Also removed intstatus backplane check from recv (avoids
window register race between RX task and ioctl path).

### CLM blob download (RESOLVED)

The CYW 7.45.265 firmware requires a CLM (Country Locale Matrix)
blob for channel/regulatory data. Without it, both `escan` and
`C_SCAN` return `BCME_UNSUPPORTED (-4)`. After downloading the
4733-byte CLM blob via `clmload` iovar (chunked, 1400 bytes/chunk),
the firmware accepts scan commands.

CLM blob: `brcmfmac43455-sdio.clm_blob` from linux-firmware
(cypress directory), placed at `/boot/firmware/`.

### BCDC header on SDIO events (RESOLVED)

SDIO event frames (SDPCM channel 1) include a 4-byte BCDC data
header before the Broadcom event frame. The PCIe path strips
this at a different layer. `brcmf_sdpcm_process_event` must
strip the BCDC header before parsing the event. Without this,
the OUI check fails and all events are silently dropped.

### Scan working (22 Mar 2026)

After CLM download + BCDC header fix, escan produces results:
```
SSID/MESH ID                      BSSID              CHAN RATE  S:N   INT CAPS
Kolabox                           1c:ed:6f:1f:bc:3b    1  18M -70:-95 100 EPS
FRITZ!Box 7530 RU                 1c:ed:6f:1f:bc:42    1  18M -80:-95 100 EPS
```

Scan takes ~40-60s end-to-end (firmware scans all channels,
50ms RX poll rate). IE data is mostly empty (`ie=1`), so no
HT caps or RSN flags displayed. Needs investigation — the BSS
info parsing might have an offset issue specific to this firmware.

### Open issues

1. **Scan IE data nearly empty** — `ie_len=1` for all BSS entries.
   The IE extraction code uses the same logic as PCIe (128-byte
   header offset). May need adjustment for firmware 7.45.265.

2. **kldunload hangs** — detach path doesn't drain sdpcm callout
   and rx_task before ieee80211_ifdetach. Need to call
   `brcmf_sdpcm_stop_poll` early in detach.

3. **Scan latency** — 40-60s for a full scan at 50ms poll. The
   firmware sends events slowly (one per channel dwell, ~1-2s each).
   Poll rate may not be the bottleneck.

4. **RX poll SDIO bus saturation** — 20ms poll rate caused hangs.
   50ms works. The Arasan SDHCI controller can't handle rapid
   repeated F2 reads when the FIFO is empty.

### kldunload fix (22 Mar 2026)

`brcmf_sdpcm_stop_poll` now called at top of
`brcmf_sdio_bus_detach`, before `brcmf_cfg_detach`. Added
`sdpcm_poll_started` guard to avoid draining uninitialized
callout. Unload takes ~35-45s (ioctl timeouts during teardown
with fw_dead=0 at `ifconfig destroy` time) but completes
without hanging.

Reload after unload fails — chip F2 port is in bad state after
detach. Reboot required between unload and reload.

### IE offset (22 Mar 2026, RESOLVED)

Firmware 7.45.265 BSS info struct is 512 bytes (not 128). Our
`brcmf_bss_info_le` definition (128 bytes) only covers the first
portion. The `ie_offset` and `ie_length` fields at byte 116/120
of our struct read garbage from the firmware's extended fields.

SSID IE found at offset 512 by searching for `tag=0x00, len=SSID_len`
matching the SSID from the fixed header. IEs are at 512..bi_len.

Fix: search for SSID IE in the raw BSS data to find the actual
IE boundary. Falls back to `ie_offset` if valid, then to 128
for older firmware.

### Scan cache empty despite ieee80211_add_scan (22 Mar 2026, RESOLVED)

Escan takes 40-60s on SDIO. By the time `brcmf_scan_complete_task`
ran and called `ieee80211_add_scan`, swscan had already finished
its channel iteration and detached the scan module (`ss_ops=NULL`).
All entries were silently dropped.

Fix: call `brcmf_add_scan_result` immediately from
`brcmf_escan_result` as each BSS arrives, while swscan is still
active. The deferred delivery via `scan_complete_task` is kept
for the final `ieee80211_scan_done` call and direct-join logic.

## 20 Mar 2026: SDIO F2 writes, kernel #25

Kernel #25 — claimed to have SDHCI fixes. Tested with updated
driver code that includes an IORdy poll loop (50 iter × 50ms).

### Test results from /var/log/messages

Three runs across kernel iterations:

| Time | Kernel | IORdy result | Outcome |
|------|--------|-------------|---------|
| Mar 19 20:08 | #22 | 0x02 (not ready) | F2 write → EIO, ver ioctl failed. Module loaded OK. |
| Mar 20 03:21 | #23 | 0x06 (ready) iter=1 | F2 blksize set. Hung on first F2 CMD53 write (ver ioctl). Watchdog reboot after 36s. |
| Mar 20 04:15 | #25 | never printed | Hung inside IORdy CMD52 poll loop. Watchdog reboot after 36s. |

### Kernel #26 test (with IORdy poll loop restored)

Kernel #26 claimed SDHCI fixes. Restored the 50-iteration IORdy
poll loop and tested. Same result — hung after `firmware booted`,
IORdy line never printed, watchdog reboot after 31s.

```
Mar 20 04:40:30  brcmfmac0: firmware booted, sharedram=0x00201cc0
Mar 20 04:41:01  ---<<BOOT>>---
```

### Analysis

**Bug 1 (CMD52 poll hang) still present through kernel #26.** The
IORdy poll loop hangs the Arasan SDHCI controller. The
`device_printf` after the loop never executes; syslog shows
`firmware booted, sharedram=...` as the last driver message
before the watchdog reboot.

**Bug 2 (CMD53 PIO write hang) still present on kernel #23.**
The kernel #23 run shows F2 ready on iter=1 (no repeated CMD52
polling needed), block size set successfully, then hang. The
hang occurs in `brcmf_sdpcm_send` → `SDIO_WRITE_EXTENDED` for
the "ver" ioctl — the first F2 CMD53 write after F2 is ready.

### Conclusion

Both SDHCI bugs from the 19 Mar investigation remain through
kernel #26. The driver code is correct — the SDHCI controller
cannot handle repeated CMD52 reads to CCCR 0x03, and cannot
complete F2 CMD53 PIO writes when F2 is ready.

## 20 Mar 2026: SDHCI bugs fixed (kernel SDIOF2FIX1), F2 write EIO

Kernel `SDIOF2FIX1` (kernel #0, 20 Mar 05:30) fixes both SDHCI
hangs. Confirmed:

- IORdy poll loop (50×50ms) completes without hanging
- F2 CMD53 byte-mode write fails cleanly with EIO (no hang)

### Complete run timeline on SDIOF2FIX1

All runs from /var/log/messages:

| Time | Boot | Load# | IORdy | Outcome |
|------|------|-------|-------|---------|
| 05:34 | 05:32 | 1st | 0x02 | F2 not ready, abort (old single-check code) |
| 05:57 | 05:32 | 2nd | 0x06 iter=1 | F2 write EIO, module loaded OK |
| 09:21 | 05:32 | 3rd | 0x06 iter=0 | F2 write EIO, module loaded OK |
| 09:24 | 05:32 | 4th | 0x06 iter=0 | F2 diag write EIO, hung at sdio_set_block_size |
| 11:41 | 11:13 | 1st | not reached | hung after "ARM released" (IORdy poll or sharedram poll) |
| 13:40 | 13:35 | 1st | not reached | hung after "firmware booted" (IORdy poll) |
| 14:37 | 14:37 | 1st | not reached | hung after "firmware booted" (IORdy poll) |
| 18:24 | 14:37 | 1st | 0x02 | F2 not ready, abort (new single-check code) |
| 18:24 | 14:37 | 2nd | 0x02 | F2 not ready, abort |
| 18:24 | 14:37 | 3rd | 0x02 | F2 not ready, abort (10s delay between loads) |

Key observations:

1. **IORdy poll loop hangs on first load after fresh boot.** The
   50×50ms loop with `pause_sbt` hangs when F2 is not immediately
   ready (runs 11:41, 13:40, 14:37). Watchdog fires after 14-31s.

2. **Single IORdy check is safe.** Runs 05:34 and 18:24 abort
   cleanly with ENXIO. No hang, no crash.

3. **F2 becomes ready only on the 05:32 boot.** On that boot,
   the 2nd load (05:57, 23min gap) found F2 ready. All subsequent
   loads on that boot also found F2 ready. No other boot achieved
   F2 ready — the 14:37 boot had three loads over 10+ seconds,
   all IORdy=0x02.

4. **F2 writes fail with EIO even when F2 is ready.** Every run
   that got IORdy=0x06 still failed the F2 CMD53 write.

5. **`pause_sbt` in poll loops is the hang trigger.** The HT
   clock poll uses `DELAY(1000)` and always works. The IORdy and
   sharedram polls use `pause_sbt` and hang. Yielding likely
   allows an SDHCI interrupt to deadlock with the next CMD52.

### 0-byte .ko filesystem corruption

Unclean reboots (watchdog) corrupt UFS inodes. `make` reports
success and correct sizes but the on-disk .ko is 0 bytes. The
11:41, 13:40, 14:37 runs loaded valid .ko files built in /tmp
(confirmed 80KB ELF with `file` + `wc -c`). Earlier confusion
about "loading stale .ko" was partly wrong — the 05:57 and
09:21 runs also loaded valid .ko files from that same boot's
build. The corruption happened after the 09:24 hang.

### F2 write EIO details

```
sdiob_rw_extended_cam: Failed to write to address 0 buffer ...
  size 160 incr b_count 0 blksz 160 error=5
```

Also tested 4-byte F2 write — same EIO. Not size-dependent.
F2 reads succeed (returns zeros when no data pending).

The CAM/sdiob layer reports `CAM_REQ_CMP_ERR` with `Error 5,
Retries exhausted`. No `Controller timeout` line from sdhci.
The actual SDHCI error code (timeout, CRC, etc.) is not visible
through the CAM abstraction.

### sdio_set_block_size(func2) hangs

`sdio_set_block_size(func2, 512)` goes through CAM and hangs
after a failed F2 write. Removed — CCCR FBR writes + direct
`cur_blksize` update in download_fw are sufficient.

### Code state

Single IORdy check (no poll loop). `sdio_set_block_size(func2)`
removed. Diagnostic printf on F2 write failure in sdpcm.c.

### Linux driver behavior (from maintainer, 20 Mar 2026)

**F2 write address:** Linux writes to `0x8000` (SDIO core base
windowed: `(cc_core->base & 0x7fff) | 0x8000`). Same address for
reads and writes. Our code was writing to address 0 — wrong.

**F2 write mode:** First control frame uses `sdio_memcpy_toio`
(incrementing). SG/data path uses fixed-address block-mode CMD53.
Incrementing is correct for control frames.

**F2 readiness:** Linux calls `sdio_enable_func(func2)` which
polls IORdy with a 3000ms timeout. No separate readiness check.
Our single IORdy read was too early — Linux waits up to 3s.

**Init sequence after F2 enable:**
1. hostintmask = I_HMB_SW_MASK | I_CHIPACTIVE
2. watermark = 0x60
3. devctl |= 0x10
4. mesbusyctrl = 0xD0
5. sdio_claim_irq(func1, handler)
6. sdio_claim_irq(func2, dummy_handler)
7. Common attach, then first iovar → sdio_memcpy_toio(func2, 0x8000, ...)

No delay between F2 enable and first write. No explicit intstatus
ack or tohost mailbox read before first write.

**intstatus 0xa0000000:** Decodes to I_IOE2 (0x80000000) +
I_CHIPACTIVE (0x20000000). This is F2-enable-changed + chip-active.
NOT firmware protocol readiness (that comes via tohost mailbox
HMB_DATA_FWREADY, which Linux doesn't wait for before first TX).

### Fixes applied

1. F2 write address: changed from 0 to `(sdiocore.base & 0x7FFF) | 0x8000`
   with backplane window set (same as recv path)
2. IORdy: needs DELAY-based poll up to 3s (matching Linux's
   sdio_enable_func timeout)

### F2 write address fix did NOT resolve EIO

After fixing address from 0 to 0x8000, the write still fails.
Post-fail intstatus=0x008000c0 shows I_HMB_FRAME_IND set,
suggesting firmware received the frame. But the SDHCI/CAM layer
reports the CMD53 as failed.

### Linux maintainer guidance (20 Mar 2026, second response)

**Do not ignore SDHCI errors.** A clean R5 only confirms command
acceptance, not data-phase success. Linux treats any command or
data error as a real failure.

**The error is likely command-level.** "Immediate R5 error on F2
writes points to command acceptance failing" — not a transient
data-phase issue.

**Need to distinguish three cases:**
1. R5 error flags set → command rejected (wrong fn/addr/not ready)
2. R5 clean, host reports data-phase error → data transfer failed
3. CAM collapses useful information → fix plumbing first

**Instrument the write path to log:**
- function number, raw CMD53 argument
- block mode vs byte mode, fixed vs incrementing
- block count / byte count
- raw R5 response bytes
- CAM completion status
- SDHCI interrupt/status bits

**On F2 write failure, Linux runs:**
- function 2 abort (CCCR ASx)
- write SFC_WF_TERM to SDIO core
- poll WFRAMEBC{HI,LO} down to zero

### sdiob limitation

FreeBSD's `sdiob_rw_extended_cam` does not expose the raw R5
response or MMC error code to callers. `SDIO_WRITE_EXTENDED`
returns only EIO. The `cam_periph_runccb` error path returns
before the R5 response check (`resp[0] & 0xff`). Also, the
R5 check only looks at bits 7:0 (stuff byte), not the actual
R5 error flags in bits 8-16.

To get the raw CMD53 argument, R5 response, and MMC error code,
a printf must be added to `sdiob_rw_extended_cam` in the kernel.

## 21 Mar 2026: SDIOF2FIX1 #1, sdiob instrumentation deployed

Kernel rebuilt with sdiob printf in `sdiob_rw_extended_cam` to
log raw CMD53 arg, mmc_err, resp[0], ccb_status on failure.

### DELAY-based IORdy poll also hangs

Tested 3000-iteration DELAY(1000) poll (no pause_sbt). Still
hangs — watchdog fires after ~60s. The issue is repeated CMD52
reads to CCCR 0x03, not the yield mechanism. Both DELAY and
pause_sbt trigger the same Arasan SDHCI hang.

Reverted to single IORdy check + abort.

### F2 not becoming ready (persistent)

On SDIOF2FIX1 #1 boot, F2 never becomes ready:

| Load | Delay | IORdy | Outcome |
|------|-------|-------|---------|
| 1st | 0 | 0x02 | abort |
| 2nd | 0 | 0x02 | abort |
| 3rd | 30s | 0x02 | abort |

All loads show `sdio core intstatus=0xa0000000` (I_IOE2 +
I_CHIPACTIVE). The I_IOE2 bit (0x80000000) indicates "F2 enable
state changed" but doesn't mean F2 is ready.

The two-load pattern that worked on 20 Mar (05:32 boot) has
not reproduced on any subsequent boot. On that boot, the
second load (23min later) saw IORdy=0x06 and
`intstatus=0x20000000` (I_CHIPACTIVE only, I_IOE2 cleared).

Cannot exercise the sdiob instrumentation because F2 writes
are never attempted (F2 not ready → abort before write).

### Open blockers

1. **IORdy poll hang** — repeated CMD52 reads to CCCR 0x03
   hang the Arasan SDHCI regardless of DELAY vs pause_sbt.
   Single reads work. This prevents Linux-equivalent
   `sdio_enable_func` polling. Needs SDHCI-layer fix.

2. **F2 not becoming ready** — IORdy bit 2 stays 0x02 after
   firmware boot on most boots. Root cause unknown. May need
   additional init steps or SDHCI fix for the IORdy poll so
   the driver can wait long enough.

3. **F2 CMD53 write EIO** — sdiob instrumentation deployed
   but untestable until blocker 2 is resolved.

## 21 Mar 2026: F2 readiness deep investigation

### F2 disable before firmware download

Linux disables F2 during probe before firmware download to clear
stale frame state. Added `IOEx &= ~0x04` + `sdio_disable_func`
before ARM halt in `brcmf_sdio_download_fw`. Did not help —
IORdy still 0x02 on first and second loads.

### Why F2 is not ready

The firmware needs time after F2 enable to initialize the F2
data port. The sharedram marker indicates the firmware core is
running, but F2 SDIO port init is separate and takes additional
time. Linux polls IORdy for up to 3000ms via `sdio_enable_func`.

On the 20 Mar 05:32 boot, the second load (23 minutes after the
first) found F2 ready. The firmware from the first load was still
running — detach only disables clocks, doesn't halt ARM. Each
subsequent load re-downloads firmware and re-boots, so the
23-minute head start was lost. With the F2 disable fix, each load
now starts F2 from a clean state, but still needs to wait.

### IORdy poll hang vs CHIPCLKCSR poll

Both are CMD52 reads through the same sdiob/CAM path. The
CHIPCLKCSR poll (`sdio_read_1(func1, 0x1000E)`) works — 100
iterations × 10ms with `pause_sbt`. The IORdy poll
(`sdio_f0_read_1(func1, 0x03)`) hangs with any loop mechanism.

| Poll | Function | Address | Mechanism | Result |
|------|----------|---------|-----------|--------|
| CHIPCLKCSR | F1 | 0x1000E | pause_sbt × 100 | works |
| IORdy | F0 | 0x03 | pause_sbt × 50 | hangs |
| IORdy | F0 | 0x03 | DELAY × 3000 | hangs |
| IORdy | F0 | 0x03 | single read | works |

The difference: F1 register reads vs F0 CCCR reads. Both use
CMD52 (no data phase). The hang mechanism is unknown — it could
be the card, the SDHCI controller, or the CAM/sdiob stack.

### ROOT CAUSE FOUND: sdiob timeout=0 for function 0

`sdiob_rw_direct_sc` uses `sc->cardinfo.f[fn].timeout` for the
CAM CCB timeout. The function info is initialized in a loop
starting at fn=1. **Function 0 is never initialized** — its
timeout field is 0 (from M_ZERO malloc).

When our driver calls `sdio_f0_read_1(func1, 0x03)`, it goes
through `SDIO_READ_DIRECT(parent, 0, 0x03)` → sdiob uses
`sc->cardinfo.f[0].timeout = 0`. A zero timeout means the
CAM/SDHCI layer waits forever if the command doesn't complete
immediately.

The CHIPCLKCSR poll uses fn=1 → `sc->cardinfo.f[1].timeout =
5000`. That's why it works.

Evidence in `freebsdsrc/sys/dev/sdio/sdiob.c`:
- Line 855: `for (fn = 1; fn < fn_max; fn++)` — starts at 1
- Line 891: `sc->cardinfo.f[fn].timeout = 5000` — only for fn≥1
- Line 171: `cam_fill_mmcio(..., timeout=sc->cardinfo.f[fn].timeout)`

Fix: initialize `sc->cardinfo.f[0].timeout = 5000` in sdiob,
or use fn=1 timeout as fallback when fn=0.

## 21 Mar 2026: Skip IORdy, attempt F2 write — sdiob instrumentation result

### Experiment: removed IORdy gate

Removed the IORdy abort — proceed to F2 write regardless of
IORdy state. On second kldload (after kldunload), IORdy=0x06
and the F2 write was attempted with the corrected address.

### sdiob instrumentation output

```
sdiob_rw_extended_cam: arg=0xa50000a0 mmc_err=2 resp[0]=0x00001000 ccb_status=0x404
```

Decoded:
- **arg=0xa50000a0**: write, fn=2, byte mode, incrementing,
  addr=0x8000 (correct), count=160
- **mmc_err=2**: MMC_ERR_BADCRC (SDHCI reports CRC error)
- **resp[0]=0x00001000**: R5 response, bit 12 set =
  **FUNCTION_NUMBER error**
- **ccb_status=0x404**: CAM_REQ_CMP_ERR (0x04) with some flags

### Interpretation

The card rejects the CMD53 with R5 FUNCTION_NUMBER error. Per
SDIO spec, this means "invalid function number in I/O command."
Function 2 is in the CMD53 arg and IORdy=0x06 confirms F2 ready,
so the function number itself is correct. The error likely means
the F2 data port is not accepting writes despite IORdy being set.

The MMC_ERR_BADCRC from SDHCI may be a secondary effect — the
card rejected the command, the data phase was aborted, and the
SDHCI saw a CRC error on the incomplete transfer.

### F2 address was wrong, now fixed

Previous runs used addr=0xC000 (derived from sdiocore.base
0x18004000). Linux uses addr=0x8000 (derived from cc_core->base
0x18000000 = SI_ENUM_BASE). Fixed in both send and recv paths.

The 0xC000 address also produced FUNCTION_NUMBER error in R5.
The correct 0x8000 address produces the same error, so the
address was not the root cause of the EIO. The R5 error is
consistent regardless of address.

### SDHCI code trace: arg reaches hardware unchanged

Traced through kernel source. `sdhci_start_command` writes
`cmd->arg` directly to `SDHCI_ARGUMENT` register with
`WR4(slot, SDHCI_ARGUMENT, cmd->arg)`. No rewriting. The
opcode (53) and arg (0xa50000a0) reach the card as constructed.

### Error phase analysis

`mmc_err=2` (MMC_ERR_BADCRC) can be set by either `sdhci_cmd_irq`
(SDHCI_INT_CRC) or `sdhci_data_irq` (SDHCI_INT_DATA_CRC). Since
we got a valid R5 response (`resp[0]=0x00001000`), the command
phase completed. The BADCRC is from the data phase — the card
rejected the data transfer after accepting the command.

The interrupt dispatch in `sdhci_generic_intr` skips `data_irq`
when `CMD_ERROR_MASK` is set. Since data_irq DID run (it set
the BADCRC), there was no command-phase error. The command
succeeded, the R5 response was captured, then the data phase
failed.

### R5 FUNCTION_NUMBER error (bit 12) with IORdy=0x06

The card accepts the CMD53 (valid R5 response) but flags
FUNCTION_NUMBER error. IORdy shows F2 is ready. IOEx shows F2
is enabled. The CMD53 arg has fn=2. The SDHCI sends the arg
unchanged.

The card's firmware decides whether to accept F2 data. Despite
IORdy=0x06, the firmware's F2 data port may not be ready to
accept SDPCM frames. This is the same root problem as the F2
readiness issue — the firmware hasn't completed its internal
initialization of the F2 data path.

### R5 bit decoding CORRECTED

Initial decoding used raw 48-bit R5 bit positions. The SDHCI
`resp[0]` register uses shifted positions (per `mmcreg.h`):

| Bit | Field |
|-----|-------|
| 15 | COM_CRC_ERROR |
| 14 | ILLEGAL_COMMAND |
| 13:12 | IO_CURRENT_STATE |
| 11 | ERROR |
| 9 | FUNCTION_NUMBER |
| 8 | OUT_OF_RANGE |

`resp[0]=0x00001000`: bit 12 set = IO_CURRENT_STATE=1 (CMD
state). **No error flags set.** The R5 response is clean.

### Revised diagnosis

This is case 2 from the Linux maintainer: R5 clean, host
reports data-phase error. The card accepted the CMD53 command.
The data transfer failed with SDHCI_INT_DATA_CRC (mmc_err=2).

The problem is in the data phase — PIO write of 160 bytes to
F2. The SDHCI controller reports a CRC error during or after
the data transfer. This is an SDHCI/bus-level issue, not a
card-level rejection.

## 21 Mar 2026: kernel panic — stack overflow in brcmf_sdpcm_ioctl

### Panic

```
vm_fault_lookup: fault on nofault entry, addr: 0xffff0000914d3000
```

Crash dump: `/var/crash/vmcore.8`

### Root cause: stack overflow in brcmf_sdpcm_ioctl

`brcmf_sdpcm_ioctl` had two 8220-byte stack arrays:

```c
uint8_t txbuf[BRCMF_SDPCM_CTL_BUFSZ];  /* 8220 bytes */
uint8_t rxbuf[BRCMF_SDPCM_CTL_BUFSZ];  /* 8220 bytes */
```

Total: 16440 bytes. arm64 kernel stack is 16384 bytes
(`KSTACK_PAGES=4` × 4096). The arrays overflow into the guard
page. The F2 read (`SDIO_READ_EXTENDED` into `rxbuf`) crosses
the guard page boundary, causing the page fault.

### Fix

Moved all large buffers from stack to softc:
- `sdpcm_ioctl_tx[8220]` — ioctl TX buffer
- `sdpcm_ioctl_rx[8220]` — ioctl RX buffer
- `sdpcm_data_tx[2048]` — TX data frame buffer

All are serialized by `ioctl_mtx` (ioctl buffers) or single-
threaded TX path (data buffer).

Also fixed `sizeof(txbuf)` / `sizeof(rxbuf)` references that
would compute pointer size instead of buffer size.

## 22 Mar 2026: F2 transfer configuration — RESOLVED

### F2 block size, address mode, and frame padding

The Arasan SDHCI cannot sustain large PIO bursts to the
BCM43455 F2 port. The driver-side fix:

- **F2 block size = 64 bytes**: sdiob uses block-mode CMD53
  with 16-word PIO bursts per block (same as working F1 path)
- **Fixed address mode** (incaddr=false): F2 is a FIFO,
  incrementing addresses cause the chip to die
- **Frame padding to 64-byte boundary**: ensures all data goes
  as block-mode transfers with no byte-mode remainder
- **Tolerant recv**: accepts data when valid SDPCM header
  present despite sdiob error return (partial FIFO reads)

### First successful ioctl

```
brcmfmac0: firmware: wl0: Aug 29 2023 01:47:08 version 7.45.265
```

No kernel changes needed beyond the sdiob F0 timeout fix.

## 19 Mar 2026: SDIO F2 writes, kernel #21

### Confirmed: F2 not ready (IORdy)

On two clean-boot runs (kernel #21, no hot-path instrumentation),
the diagnostic shows:

```
CCCR IORdy=0x02 (F2_ready=0)
```

IOEx=0x06 (F1+F2 enabled), but IORdy bit 2 is never set. The
firmware boots (sharedram=0x00201cc0), the SDIO core shows frame
indication (intst=0x208000c0), but the card's F2 data port is
not marked ready.

The F2 CMD53 byte-mode write (160 bytes to address 0) returns
EIO. This is non-fatal — kldload completes, module loads.

### Hang caused by extended IORdy poll loop

Adding a poll loop (500 iterations, 10ms each, ~5s total) that
repeatedly reads CCCR 0x03 via `sdio_f0_read_1` causes the SDHCI
controller to lock up. The system becomes completely unresponsive
and requires a watchdog reboot.

The same F0 CMD52 read works fine when done once. The issue is
specific to rapid repeated reads over several seconds. Reverting
to the original flow (wait for sharedram only, single IORdy check)
restores stability.

### Kernel #20 regression (resolved)

Kernel #20 had CMD53 tracing in `sdhci_start_data` that logged
every CMD53 data transfer. The ~10000 F1 writes during firmware
download produced enough trace output to consume 99% CPU for
minutes, starving the watchdog and making the system appear hung.
Kernel #21 removed the hot-path instrumentation, fixing this.

### SDIO core state after firmware boot

```
intst=0x208000c0  hostmask=0x000000f0  tohost=0x00000004
clk=0xc2  devctl=0x10  IOEx=0x06  IORdy=0x02
```

Firmware is alive (frame indication set, HT clock available).
tohost=0x04 suggests mailbox data pending.

### F2 ready eventually asserts

The sysctl diagnostic (read manually after kldload completes) shows
IORdy=0x06 — F2 IS ready after some delay. The init-time check
(immediately after sharedram valid) sees IORdy=0x02 because F2
hasn't finished initializing yet.

### The Arasan SDHCI hang pattern

Any SDIO transaction added between the working baseline flow and
the F2 CMD53 write causes the system to hang:

| Change | Result |
|--------|--------|
| Baseline (no changes) | works, F2 write returns EIO |
| + IORdy poll (50×50ms, pause_sbt) | hang |
| + HT clock request (pause_sbt poll) | hang |
| + 500ms pause_sbt + single IORdy read | hang |
| + early sdio_set_block_size(F2) | hang |
| + early CCCR FBR writes (0x210/0x211) | hang |

The hang occurs even with just 2 additional CMD52 reads/writes.
It is NOT caused by a tight loop — `pause_sbt` yields between
iterations. The hang correlates with the total time between
F2 enable (IOEx write) and the first F2 CMD53 data write.

**Key insight**: with extra delay, F2 becomes ready (IORdy=0x06),
and the subsequent F2 CMD53 byte-mode write hangs the Arasan SDHCI.

When F2 is NOT ready (baseline — no delay), the card NAKs the
CMD53 immediately (EIO) and the controller doesn't hang.

### Multi-block theory disproved

F2's `cur_blksize` defaults to 512 (from CIS CISTPL_FUNCE). A
160-byte frame uses byte mode (`b_count=0, blksz=160`). The hang
is NOT caused by multi-block transfers.

The extra SDIO transactions (CCCR FBR writes, IORdy reads, HT
clock poll) don't directly cause the hang — they just add enough
delay (~50-200ms) for F2 to become ready. Once F2 is ready, the
card accepts the CMD53 write data phase instead of NAKing it,
and the Arasan SDHCI controller hangs during PIO data transfer.

### Root cause: Arasan SDHCI cannot complete F2 CMD53 write

This is a host controller bug. The card is correctly ready (IORdy
set, firmware running), but the BCM2835 Arasan SDHCI controller
fails to complete the PIO data transfer phase of a CMD53 write
to function 2. The same controller handles F1 CMD53 writes and
F2 CMD53 reads without issue.

This needs to be fixed in `sdhci.c` or `bcm2835_sdhci.c`. The
driver cannot work around it — any functional SDIO WiFi driver
must write data to F2.

### /var/log/messages evidence

syslog captures kernel messages that survive reboots. From the
07:53:59 run (HT clock enabled, IORdy=0x02, F2 not ready):

```
sdhci_bcm0-slot0: CMD53 error: intmask=0x200000 err=2 arg=0xa58000a0
```

Arg 0xa58000a0 decodes: write, fn=2, byte mode, incr, addr=0xC000,
len=160. err=2 is likely an R5 CRC/response error. This error only
appears in runs where F2 is NOT ready — the controller returns the
error normally and kldload completes.

In runs where F2 IS ready (with delay), NO CMD53 error log appears.
The controller hangs before reaching the error handler.

### Two separate SDHCI bugs identified

**Bug 1 (CMD52 poll hang):** Repeated CMD52 reads to CCCR 0x03
(IORdy) hang the Arasan SDHCI. Single reads work. The IORdy poll
loop with `pause_sbt(50ms)` between iterations freezes the
controller after a few iterations. This is NOT the PIO write bug.

Evidence from /var/log/messages (kernel #22, 20:04:50 run):
log stops at "firmware booted" — no IORdy poll result printed.
The subsequent run without the poll (20:08:47) completes fine.

**Bug 2 (CMD53 PIO write hang):** F2 CMD53 byte-mode writes hang
when F2 is ready. Kernel #22 patch 05 addresses this by masking
SPACE_AVAIL after PIO completion. Not yet testable because Bug 1
prevents reaching the F2 write with F2 in the ready state.

### Path forward

Bug 1 must be fixed first. Once CMD52 polling works, the IORdy
poll will wait for F2 ready, and then we can test whether patch 05
fixes the CMD53 write.

## 18 Mar 2026: SDIO F2 writes, kernel #16 and #19

### Kernel #16 (patches 01-02: WR4 flush, pwrseq)

F1 works. Firmware boots. F2 CMD53 writes hang the SDHCI controller
completely (no timeout, no error return). Firmware download takes
~2-3 minutes at 64 bytes/write (1-bit bus, low clock).

### Kernel #19 (patches 01-04: + 25 MHz clock, 4-bit bus)

F1 works. Firmware download completes in seconds (4-bit, 25 MHz).
F2 CMD53 writes no longer hang — they return error=5 (EIO) for
most sizes. Exception: F2 block-mode writes at 64 bytes with
multi-block (`b_count > 1`) still cause a hard hang.

Test results on kernel #19:

| What | Mode | Size | b_count | blksz | Result |
|------|------|------|---------|-------|--------|
| F1 block write | block | 64 | 1 | 64 | works |
| F2 block write | block | 512 | 1 | 512 | err=5 |
| F2 block write | block | 192 | 3 | 64 | hang |
| F2 byte write | byte | 160 | 0 | 160 | err=5 |
| F2 byte write | byte | 4 | 0 | 4 | worked (pre-fix kernel) |
| F2 read | any | any | any | any | works |

The error=5 comes from `cam_periph_runccb` in `sdiob_rw_extended_cam`.
The sdiob layer retries and exhausts retries, then returns EIO.

### Chip state after failed F2 write

After a failed kldload + kldunload cycle, chip backplane reads
return 0xFFFF (chip=ffff rev=15). A reboot is required to reset
the SDIO card via power sequencing.

### Open question

Why do F2 writes fail while F1 writes and F2 reads work? The CMD53
argument differs only in the function number field (`SD_IOE_RW_FUNC`)
and the write flag (`SD_IOE_RW_WR`). Both are set correctly by sdiob.
The BCM43455 firmware reports F2 as enabled (IOEx=0x06). The SDIO
core intstatus shows frame indication (0x80000000 or 0x008000c0),
suggesting the firmware is ready to communicate.

### IE false positive fix + dedup (22 Mar 2026)

SSID search without validation produced false matches at offset
128 for `bi_len=460` entries — the SSID bytes appeared by
coincidence in the extended header fields. Added
`brcmf_check_ie_chain` that validates SSID IE + Rates IE (tag 1)
sequence. Changed search to start from `bi_len / 2` to skip the
extended header entirely.

Also changed dedup to prefer entries with more IE data (`>=`
instead of `> 0` check).

Result: `bi_len=536` entries correctly find IEs at offset 512
(24 bytes IE). `bi_len=460` entries find IEs at offset 328 (132
bytes IE, includes RSN). But some entries still fall back to
offset 128 — these are the short BSS info responses where the
SSID+Rates pattern doesn't appear at the expected position.

Association blocked: wpa_supplicant sees APs in the scan cache
but the RSN IE is missing from some/all entries at the time
wpa_supplicant checks. The dedup "prefer more IEs" change helps
but doesn't fully solve it because the timing of which escan
event arrives first is non-deterministic.

Next: may need to check if the 128-byte fallback can be disabled
entirely for CYW firmwares, or use a different strategy (e.g.,
`bi_len - some_constant` based on observed patterns).

## 23 Mar 2026: BCM43455 association diagnosis after spec review

### Summary

The SDIO path can boot firmware, load CLM, scan, and exchange firmware
ioctls/events, but association is still broken even on an open 2.4GHz
AP (`TestAP`). The working Linux RPi4 uses the same firmware and connects
normally. That shifts the focus away from WPA, the AP, and net80211, and
back to the SDIO transport/runtime implementation.

### What the tests established

- Open network (`TestAP`, ch1, 2.4GHz) fails the same way as WPA2:
  `AUTH` timeout (`code=3 status=2`), then `SET_SSID` fail (`code=0 status=1`)
- `join` iovar returns `BCME_NOTREADY (-14)` on CYW43455, including the
  bsscfg-scoped form Linux uses
- `C_SET_SSID` is accepted by firmware, but auth still times out
- `C_GET_UP` returns `isup=1` after `bss_up`
- Earlier 5GHz runs that reached LINK/SET_SSID success were not stable
  and do not change the diagnosis

This eliminates several earlier theories:
- not WPA-specific
- not DFS-specific
- not explained by deferred RUN transition timing
- not explained by EAPOL TX filtering alone

### Spec vs implementation gap

Re-reading `spec/02-bus-sdio.md`, `spec/04-protocol-bcdc.md`, and
`spec/08-initialization.md` against the current code shows that the SDIO
path does not yet implement the runtime model the docs describe.

Missing or incomplete SDIO-specific pieces:

1. **Common attach / bus-started ordering**
   - Spec: bus preinit and protocol init_done happen before cfg attach
   - Code: `src/main.c` calls `ver`, `cap`, CLM load, and `brcmf_cfg_attach`
     directly, then only starts SDIO polling afterward

2. **BCDC protocol init_done**
   - Spec: BCDC attach has an `init_done` phase
   - Code: SDIO bypasses any protocol-layer attach object and uses
     `src/sdpcm.c` directly via `bus_ops`

3. **Firmware signaling (`fwsignal`)**
   - Spec: SDIO/USB BCDC uses `fwsignal` for credit-based flow control
   - Code: no `fwsignal` implementation is present for SDIO

4. **Real SDIO DPC/runtime loop**
   - Spec: DPC processes intstatus, mailbox, FC changes, RX, TX
   - Code: current SDIO path is a polled RX loop plus synchronous ioctls

5. **SDPCM TX credit enforcement**
   - Spec: host must stop TX when sequence exceeds firmware max sequence
   - Code: `sdpcm_max_seq` is recorded from RX headers but never enforced

### Why PCIe works and SDIO does not

PCIe uses the substantially complete msgbuf transport: IRQ-driven D2H,
control/event buffers, completion handling, and flowring management.

SDIO uses a simplified transport that is sufficient for:
- firmware boot
- `ver` / `cap` / CLM ioctls
- escan
- event delivery

But it is still missing SDIO-specific runtime pieces that Linux brcmfmac
has during connect. The strongest symptom is `join` returning
`BCME_NOTREADY` on SDIO while the same firmware works on Linux.

### Current conclusion

The primary blocker is an **SDIO transport/runtime completeness issue**.
This is below cfg80211/net80211 and below WPA logic.

Useful fixes from this session that should stay:
- log firmware `reason` on disconnect events
- skip unsupported `wpaie` / `sup_wpa` on CYW43455
- allow EAPOL TX before RUN
- use saved `join_chan` in `link_task`
- `brcmf_fil_bsscfg_data_set()` helper for bsscfg-scoped iovars

But those do not address the root cause.

### Next steps

1. Rework SDIO attach to follow the spec's common attach / bus-started order
2. Add the missing BCDC `init_done` step for SDIO
3. Implement the SDIO DPC/runtime pieces:
   - interrupt status processing
   - mailbox handling
   - flow-control updates
   - RX/TX progression in one runtime path
4. Enforce SDPCM TX credits from `sdpcm_max_seq`
5. Only then revisit association behavior

### 24 Mar 2026: worker-mode reboot root cause

The reboot introduced by the new SDIO worker-mode path was not random.
It was a transport serialization bug.

Observed panic from `savecore`:

```
camq_remove: Attempt to remove out-of-bounds index -3 from queue ... size 1
```

What changed:
- worker-mode moved control-response delivery into `rx_task`
- but the ioctl caller still sent the control frame directly from its own
  thread
- unlike the old path, the new path no longer held `sdpcm_rx_busy` across
  the direct F2 write

That allowed concurrent SDIO activity from two contexts:
- ioctl thread doing F2 CMD53 write (`brcmf_sdpcm_send`)
- `rx_task` doing F2 reads / SDIO traffic at the same time

On this Arasan + sdiob + CAM stack, that corrupts lower-level queue state
and panics in CAM (`camq_remove ... out-of-bounds index -3`).

Fix applied:
- restore F2 serialization for worker-mode sends by taking `sdpcm_rx_busy`
  around the direct control-frame send
- keep the worker responsible for draining F2 and delivering the response
  after the send completes

Result after fix:
- no reboot on `kldload`
- no reboot on `ifconfig wlan0 create` / `ifconfig wlan0 up`
- no reboot from direct control/data F2 send races

This removed the regression introduced while refactoring the SDIO runtime
and confirmed that strict F2 serialization is required even with a central
RX worker.

### 24 Mar 2026: multi-block F2 reads were another SDIO runtime bug

After the F2-serialization fix, the board still panicked later during scan /
association loops. The new logs showed a different failure sequence before the
same eventual CAM panic:

- `sdhci_bcm0-slot0: Controller timeout`
- `sdiob_rw_extended_cam: Failed to read ... size 576 ... error=5`
- later another timeout on `size 1152`
- then `camq_remove ... out-of-bounds index -3`

Those sizes came from `brcmf_sdpcm_recv()` reading the remainder of a frame in
one large follow-up CMD53 after the first 64-byte block. The code comment said
"read one block at a time", but the implementation still issued large multiblock
reads for the remainder.

Fix applied:
- change SDPCM remainder reads to use 64-byte F2 reads throughout
- keep reading until the exact frame length is collected

Observed result after the fix:
- repeated escan traffic stays alive
- no SDHCI controller timeouts seen in the observed scan window
- no `rx_task: ch=3` glom frames seen in the observed stable run
- no reboot during the long scan/join retry loop

Association behavior is still unchanged:
- `join` returns `BCME_NOTREADY (-14)`
- `SET_SSID` is accepted
- firmware then reports AUTH timeout / SET_SSID failure

This is still not the association fix, but it is a real SDIO runtime
correction: the RX path now matches the earlier design intent of avoiding
large F2 CMD53 reads on BCM2711.

## 24 Mar 2026: SDIO worker-mode concurrent access panic

### Panic: camq_remove out-of-bounds index -3

System panic during SDIO association attempts with call stack through
CAM queue management. Dump file: `/var/crash/vmcore.5`.

```
Panic String: camq_remove: Attempt to remove out-of-bounds index -3
              from queue 0xffffa00001443038 of size 1
```

### Root cause

The SDIO worker-mode ioctl path had a race condition with `rx_task`.
When an ioctl timed out, the ioctl thread called `brcmf_sdio_bp_read32`
to read interrupt status for diagnostics while `rx_task` was still
running SDIO I/O. This caused concurrent F1 (backplane) and F2 (data)
SDIO commands, corrupting CAM's internal queue state.

The ioctl thread holds `ioctl_mtx` during timeout handling, and
`rx_task` acquires `sdpcm_rx_busy`. These are independent locks, so
neither prevents the other from issuing SDIO commands.

### Fix

Removed the diagnostic backplane read in the worker-mode timeout path.
The `brcmf_sdio_bp_read32` call was only used for logging interrupt
status and is not essential. In worker mode, we cannot safely access
the SDIO bus from the ioctl thread context.

### Additional finding: firmware channel mismatch

Debug output showed that when AUTH state tries to join:
- Pre-join: `cur_chan=36 cur_chanspec=0xd024` (firmware on 5GHz ch36)
- Target: `chan=1 chanspec=0x1001` (AP on 2.4GHz ch1)

The firmware's radio is tuned to a different band than the target AP.
Even when the channel naturally aligns after scan, AUTH still times
out (code=3 status=2). Explicit `C_SET_CHANNEL` before join did not
resolve the AUTH timeout.

The AUTH timeout suggests the firmware is not actually transmitting
802.11 authentication frames despite being told to join. This remains
an open investigation.

## 24 Mar 2026: Taskqueue contention fix

### Problem
AUTH state ioctls (C_SET_INFRA, C_SET_AUTH, wsec) were timing out
on the first AUTH attempt after scan completion. Second attempt worked.

### Root cause
`scan_task` and `sdpcm_rx_task` both used `taskqueue_thread`. When
escan completed, `rx_task` enqueued `scan_task`. `scan_task` called
`ieee80211_scan_done` which triggered AUTH state transition. The AUTH
handler called ioctls which needed `rx_task` to run, but `rx_task`
couldn't run because `scan_task` was still executing on the same
single-threaded taskqueue.

### Fix
Created dedicated `sdpcm_tq` taskqueue for `sdpcm_rx_task`. Now ioctls
can complete even when triggered from `scan_task` context.

### Result
Security ioctls (`set_security`) now complete successfully on first
AUTH attempt.

### Remaining issue
AUTH still times out (E_AUTH status=2). Firmware accepts SET_SSID
but 802.11 authentication doesn't complete. This is not an ioctl
timeout — it's the firmware reporting that the auth handshake
with the AP timed out. The firmware might not be transmitting
auth frames, or there's a missing init step.

### Firmware known-good

The firmware files on the test host (brcmfmac43455-sdio.bin,
brcmfmac43455-sdio.txt, brcmfmac43455-sdio.clm_blob) were copied
from a working Raspberry Pi 4 running Linux. The same firmware
successfully associates with APs on Linux, so the AUTH timeout
is not a firmware bug — it's a driver initialization or transport
issue specific to the FreeBSD port.

## 24 Mar 2026: Channel set commands ignored

### Observation
Both `C_SET_CHANNEL` and `chanspec` iovar return success (0) but
firmware stays on previous channel:

```
set_channel(1): 0
verify_channel: 6      <- still on channel 6, not 1

set_chanspec(0x1001): 0
verify_chanspec: 0xd02c   <- still on 5GHz channel 44
```

### Implications
The firmware ignores channel changes in its current state. This might be:
1. Normal behavior when not associated (firmware picks channel at join)
2. Indication that firmware needs different state to accept channel changes
3. Related to ongoing scan or other firmware activity

The channel in SET_SSID params should tell firmware which channel to
use for the join attempt, but AUTH still times out regardless.

### Tested variations
- `C_SET_CHANNEL` with channel number — ignored
- `chanspec` iovar with full chanspec — ignored  
- Including chanspec in SET_SSID join params — AUTH still times out
- Broadcast BSSID + no chanspec (let firmware pick) — AUTH still times out

The channel handling appears to be a red herring. The firmware receives
correct channel info in the join params but doesn't complete auth.

## WPA Handshake Issue (2026-03-27 session)

**Symptoms:**
- 5GHz WPA2 AP (Kolabox): Association succeeds, EAPOL exchange starts, but VAP leaves RUN state before completion
- 2.4GHz open AP (TestAP): AUTH timeout, "no ack" from firmware

**Key findings:**

1. **TestAP (open, 2.4GHz):** Firmware logs "JOIN: authentication failure, no ack" — TX of AUTH frames not getting ACKs. Probe requests during scan work, but AUTH doesn't. Possibly channel/FEM issue on 2.4GHz.

2. **Kolabox (WPA2, 5GHz):** Association works, but:
   - EAPOL 1/4, 2/4, 3/4, 4/4 all exchanged
   - wpa_supplicant sees `portEnabled=0` during handshake
   - VAP transitions `RUN -> INIT` before PTK is installed
   - wpa_supplicant thinks handshake failed, issues MLME_DEAUTH

3. **E_LINK event issue:** Firmware sends E_LINK with link=0 shortly after E_SET_SSID success. Added code to ignore E_LINK down while in RUN state, but something else still triggers RUN->INIT.

4. **Inline vs deferred link_task:** Changed E_SET_SSID handler to call `brcmf_link_task` inline instead of deferring to taskqueue. This fixed the initial "Not associated - Delay processing EAPOL" issue.

**Current state:**
- Association reaches RUN
- EAPOL 4-way handshake proceeds but doesn't complete
- VAP leaves RUN (arg=1 = reason from MLME_DEAUTH ioctl from wpa_supplicant)
- wpa_supplicant is disconnecting due to perceived handshake failure

**Final test after reboot (fresh chip state):**
- Same behavior: association succeeds, EAPOL 1-4 exchanged, but RUN->INIT before key install
- Firmware logs `link up (wl0)` — considers connection established
- `key_set` callback is never called — VAP leaves RUN before net80211 installs keys
- wpa_supplicant issues MLME_DEAUTH (arg=1) due to handshake failure perception

**Root cause FOUND:**
The wlan_ccmp kernel module cannot load due to version mismatch:
```
KLD wlan_ccmp.ko: depends on kernel - not available or version mismatch
```

When wpa_supplicant tries to set the PTK via `SIOCS80211` ioctl:
1. `ieee80211_crypto_newkey()` tries to auto-load wlan_ccmp module
2. Module load fails due to version mismatch
3. `ieee80211_crypto_newkey()` returns 0 (failure)
4. Ioctl returns `ENXIO` ("Device not configured")
5. wpa_supplicant sees key install failure
6. wpa_supplicant aborts handshake, sends MLME_DEAUTH with reason=1
7. net80211 transitions VAP to INIT

**Evidence:**
```
bsd_set_key: alg=3 addr=... key_idx=0 set_tx=1 seq_len=6 key_len=16
ioctl[SIOCS80211, op=19, val=0, arg_len=64]: Device not configured
WPA: Failed to set PTK to the driver (alg=3 keylen=16...)
```

**Fix required:**
Rebuild wlan_ccmp.ko from matching kernel sources or rebuild kernel with CCMP built-in.
This is a test host configuration issue, not a driver bug.

**The SDIO driver code is correct** — the WPA handshake completes all EAPOL exchanges successfully. The failure is in the net80211/crypto layer due to missing cipher module.
