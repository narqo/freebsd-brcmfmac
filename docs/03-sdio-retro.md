# SDIO Bring-up Retrospective (20-21 Mar 2026)

## Problems and resolutions

### 1. IORdy poll hang (days of investigation)

**Symptom:** Repeated CMD52 reads to CCCR 0x03 hung the system.
Single reads worked. Attributed to Arasan SDHCI hardware bug.

**Actual cause:** `sdiob.c` never initialized `cardinfo.f[0].timeout`.
F0 CMD52 operations had CAM timeout=0 (infinite wait). F1 operations
had timeout=5000 and worked fine. One-line fix in sdiob.

**What led us astray:** We assumed the hang was in the SDHCI PIO
path because SDHCI bugs had been the pattern. We never checked the
CAM timeout value. The difference (F0 vs F1) was visible in the
code but we focused on SDHCI register behavior instead of tracing
the full sdiob→CAM→SDHCI call chain.

**Lesson:** When two code paths use the same SDHCI hardware but
behave differently, check the software parameters (timeouts, flags)
first, not the hardware.

### 2. Kernel panic misdiagnosed as SDHCI hang

**Symptom:** kldload hung, system went down, watchdog rebooted.
Attributed to SDHCI regression in SDIOF2PACE2 kernel.

**Actual cause:** Stack overflow in `brcmf_sdpcm_ioctl` — two
8220-byte arrays (16440 total) on a 16KB arm64 kernel stack.
The F2 read buffer crossed the guard page, causing
`vm_fault_lookup: fault on nofault entry`.

**What led us astray:** We didn't check /var/crash for panic
dumps. The savecore message was in /var/log/messages but buried
in boot output. We assumed "system went down" = "SDHCI hang"
because that was the prior pattern.

**Lesson:** After any unresponsive kldload, ALWAYS check
`/var/crash/` and `grep panic /var/log/messages` on the next
boot. Distinguish panics from hangs — they have different causes.

### 3. F2 write address wrong

**Symptom:** F2 CMD53 writes returned EIO (DATA_CRC in SDHCI).

**Actual cause (partial):** F2 frame port address was 0xC000
(from `sdiocore.base` 0x18004000) instead of 0x8000 (from
`SI_ENUM_BASE` 0x18000000). Linux uses `cc_core->base`.

**Lesson:** The F2 frame port is at ChipCommon base, not the
SDIO device core base. Both recv and send paths must use
`SI_ENUM_BASE` for the backplane window.

### 4. R5 response bit misinterpretation

**Symptom:** resp[0]=0x00001000 decoded as "FUNCTION_NUMBER
error (bit 12)" — concluded the card was rejecting F2.

**Actual cause:** Used raw SDIO spec R5 bit positions instead
of FreeBSD `mmcreg.h` positions. Bit 12 in resp[0] is
`IO_CURRENT_STATE`, not `FUNCTION_NUMBER`. The R5 had no error
flags — the card accepted the CMD53.

**Lesson:** SDHCI strips CRC/start/end bits from the response.
Always use `mmcreg.h` definitions for bit positions in resp[0].

### 5. 0-byte .ko from filesystem corruption

**Symptom:** kldload failed silently or loaded stale code.
Build appeared to succeed (make reported correct sizes).

**Actual cause:** Unclean reboots (watchdog, panic) corrupted
UFS inodes. New files written to the same inode appeared as
0 bytes on disk despite successful writes.

**Lesson:** Always verify with `file` + `wc -c` after build.
If 0 bytes, `rm -f` and rebuild. Build in `/tmp` as fallback.

### 6. F2 readiness was never a card/firmware problem

**Symptom:** IORdy bit 2 stayed 0x02 on most boots. Attributed
to firmware needing more initialization time.

**Actual cause:** The driver couldn't poll because of the F0
timeout bug (#1). Once fixed, F2 becomes ready in ~40ms (4
poll iterations × 10ms). The firmware was ready all along.

## Required kernel changes

All three are needed for the current working state:

1. **sdiob: F0 timeout init** — `cardinfo.f[0].timeout = 5000`
2. **sdhci: PIO pacing for F2 byte-mode writes** — one word
   per SPACE_AVAIL, DELAY(1) between words
3. **sdhci: SDIOF2FIX1 base** — prevents hard SDHCI hangs on
   F2 CMD53 PIO writes

The sdiob diagnostic printf can be removed for production.

## Driver code changes

- F2 frame port: `SI_ENUM_BASE` windowed (0x8000) for both
  send and recv paths
- Stack overflow fix: ioctl and TX buffers moved to softc
- IORdy poll: 300 iterations × 10ms with pause_sbt
- F2 disable before firmware download (matches Linux)
- F2 block size via CCCR FBR writes (not sdio_set_block_size)
