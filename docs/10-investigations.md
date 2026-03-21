# Investigations

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
