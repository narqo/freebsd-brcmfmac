# Investigations

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
