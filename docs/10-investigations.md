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

### F2 write EIO

```
F2 write failed: err=5 ch=0 flen=160 blksz=512
sdiob_rw_extended_cam: Failed to write to address 0 buffer ... size 160 incr b_count 0 blksz 160 error=5
```

Also tested 4-byte F2 write — same EIO. Not size-dependent.
F2 reads succeed (returns zeros when no data pending).

The CAM/sdiob layer reports `CAM_REQ_CMP_ERR` with `Error 5,
Retries exhausted`. No `Controller timeout` line from sdhci.

### sdio_set_block_size hangs

`sdio_set_block_size(func2, 512)` (goes through CAM) hangs
after a failed F2 write attempt. Removed the call — CCCR FBR
writes + direct `cur_blksize` update are sufficient.

### Chip state after failed F2 write

After an unclean reboot (watchdog or power loss), the chip may
be in a bad state. The HT clock request loop hangs on the next
kldload. A power cycle is required to reset the SDIO card.

### Second test: fresh power cycle, still hangs

After power cycle, clean boot on SDIOF2FIX1, kldload hangs hard.
Board completely unresponsive — no watchdog reboot after >6 min.

**Root cause: 0-byte .ko from filesystem corruption.** The earlier
"working" runs (05:57, 09:21) loaded a stale .ko cached from a
previous build — the actual build output was 0 bytes due to
unclean reboot corrupting the filesystem. Those runs used code
from a different build.

After a proper `make clean && make` producing a real 80KB .ko,
kldload hangs hard on SDIOF2FIX1. The hang is during firmware
download (`brcmf_sdio_bp_write_block` — F1 CMD53 block writes).
Last syslog message: `writing firmware (609309 bytes) to
0x198000...`.

The SDHCI fix may have introduced a regression in F1 CMD53
handling. The watchdog does not fire, suggesting the CPU is
stuck in a spinlock or infinite loop inside the SDHCI PIO
transfer path.

### Code state

IORdy poll loop restored (CMD52 polling is safe now).
`sdio_set_block_size(func2)` removed (hangs).
F2 writes fail with clean EIO — next step is to debug why.

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
