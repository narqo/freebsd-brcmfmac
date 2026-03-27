# SDIO Bring-up Retrospective

Historical bring-up notes for the BCM43455 SDIO work.
This file is not the current status tracker; see docs/00-progress.md.

---

## Retrospective 2: AUTH Timeout (26-27 Mar 2026)

### The problem

After SDIO F2 transfers worked and the firmware booted, association
failed with AUTH timeout. The firmware accepted `join` and `SET_SSID`
commands but 802.11 authentication never completed. The AP (1 meter
away, -60 dBm RSSI) never received any frames from the RPi4.

Timeline: ~2 days of investigation across multiple sessions.

### Root cause

**STILL UNKNOWN** as of end of 27 Mar session.

### What we thought was the fix (FALSE POSITIVE)

Mid-session, changed NVRAM `btc_mode=1` → `btc_mode=0`. On the next
kldunload/kldload cycle (without reboot), association succeeded once.
Firmware showed `link up`. We concluded this was the fix and documented
it as such.

**After reboot:** AUTH timeout returned. The `btc_mode=0` change had
no effect. The mid-session success was due to residual firmware state
from the previous load — the firmware wasn't fully reset between
kldunload/kldload.

**Lesson: Always verify fixes across a full reboot before concluding
root cause is found.**

### What helped during investigation

1. **Firmware console reader.** Added sysctl `dev.brcmfmac.0.fwcon`
   to read the firmware's internal log buffer. Revealed
   `JOIN: authentication failure, no ack` on one run — confirmed
   firmware was attempting TX but AP didn't ACK.

2. **AP-side monitoring.** Running wpa_supplicant with `-dd` on the
   AP showed no auth frames received. Confirmed zero frames reaching
   AP — physical layer issue.

3. **The `FIXME bt_coex` message.** Appears during every `wl_open`.
   Still the prime suspect but `btc_mode=0` doesn't fix it.

### What went wrong

1. **Declared victory too early.** One successful association during
   a kldunload/kldload cycle was treated as confirmation. Should have
   rebooted and re-tested before updating docs.

2. **Didn't understand kldunload/kldload vs reboot difference.** The
   firmware isn't fully reset on kldunload — some state persists in
   the chip. A reboot power-cycles the chip via the power sequencer
   and gives a clean slate.

3. **Updated docs with "ROOT CAUSE FOUND" prematurely.** Created
   confusion when the fix didn't survive reboot. Progress docs,
   investigation notes, and retro all had to be corrected.

4. **Spent time on fixes that were correct but irrelevant:**
   - SDIO register offset bugs (real bugs, didn't cause AUTH timeout)
   - C_UP/C_DOWN payload format (matches Linux now, didn't help)
   - bsscfg encoding fix (correct, didn't help AUTH)
   - Removing redundant bss_up (correct, didn't help AUTH)

### Lessons for future agents

1. **Verify fixes survive reboot.** A kldunload/kldload cycle is not
   a clean test. The chip retains state. Always reboot before
   declaring a hardware/firmware issue fixed.

2. **Be skeptical of single successes.** One working test after many
   failures could be a fluke, residual state, or timing luck. Repeat
   the test, ideally with reboot.

3. **Firmware console is valuable but not conclusive.** The "no ack"
   message appeared on one run but not others. The console buffer is
   small (1024 bytes) and wraps. Absence of a message doesn't mean
   the condition didn't occur.

4. **Don't update "ROOT CAUSE FOUND" until verified.** Use tentative
   language ("appears to fix", "testing") until reboot confirms.

### Current status (end of 27 Mar)

- AUTH timeout persists after reboot
- `FIXME bt_coex` appears during every `wl_open`
- `btc_mode=0` in NVRAM does NOT fix it
- Root cause unknown
- Firmware console shows no activity after boot (widx unchanged)
- Investigation continues

---

## Retrospective 1: F2 Transfers (20-21 Mar 2026)

### Problems and resolutions

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
Attributed to a kernel regression.

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

### 3. F2 transfer configuration (multiple issues)

**Symptom:** F2 CMD53 writes returned EIO.

**Actual causes (all driver-side):**
- Wrong F2 address: 0xC000 (from sdiocore.base) instead of
  0x8000 (constant for the F2 frame port)
- Wrong block size: 512 bytes caused large PIO bursts that
  the Arasan SDHCI can't sustain for the BCM43455 F2 port
- Wrong address mode: incrementing instead of fixed (FIFO)
- Stack overflow: 16KB of stack arrays on 16KB kernel stack

**Fix:** F2 block size = 64, fixed address, frame padding to
64-byte boundary. This makes sdiob use block-mode CMD53 with
16-word PIO bursts per block — same as the working F1 path.
Recv tolerates read errors when valid SDPCM header is present.

**Lesson:** No kernel changes needed for F2 transfers. The
driver controls block size, address mode, and frame padding.

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

None. The driver works on an unmodified FreeBSD 15-STABLE
kernel with SDIO support. The sdiob F0 timeout=0 issue does
not affect the driver because the SDHCI uses its own 10-second
timeout callout independent of the CAM CCB timeout.

## Driver code changes for F2

- F2 frame port address: 0x8000 (constant), fixed address mode
- F2 block size: 64 bytes (small PIO bursts via block-mode CMD53)
- Frame padding: rounded to 64-byte boundary
- Recv: tolerant read — accepts data when valid SDPCM header
  present despite sdiob error return
- Stack overflow fix: ioctl and TX buffers moved to softc
- IORdy poll: 300 iterations × 10ms with pause_sbt
- F2 disable before firmware download (matches Linux)
- F2 block size via CCCR FBR writes (not sdio_set_block_size)
