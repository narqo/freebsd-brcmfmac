# SDIO Support Plan (BCM43455, Raspberry Pi 4)

## Hardware

- Chip: BCM4345 (CYW43455), chip ID `0x4345`, SDIO interface
- SDIO vendor: `0x02D0` (Broadcom), device: `0xA9A6`
- Host: BCM2835 Arasan SDHCI controller at `0x7e300000`
- Firmware: `/boot/firmware/brcmfmac43455-sdio.bin` (609 KB)
- NVRAM: `/boot/firmware/brcmfmac43455-sdio.txt` (2 KB)

### Chip specifics (BCM43455)

- Chip ID: `0x4345`, revision 6
- ARM core: CR4 (core ID 0x83E)
- RAM base: `0x198000`
- RAM size: `0xc8000` (800KB)
- SDIO device core: `0x829` (base discovered via EROM)
- Firmware: `brcmfmac43455-sdio.bin` (609309 bytes)
- NVRAM: `brcmfmac43455-sdio.txt` (1748 bytes after parsing)
- HT caps: 1SS, MCS 0-7, 20/40 MHz, no VHT
- io_type: D11N (to be confirmed via `C_GET_VERSION`)

## Build notes

Hardware watchdog configured in `/etc/rc.conf`:

```
watchdogd_enable="YES"
watchdogd_flags="-s 4 -t 8"
```

Pats every 4s, reboots after 8s of kernel hang. The watchdog
does NOT recover from SDIO I/O hangs where the blocking thread
yields via `pause_sbt` — `watchdogd` can still pat in that case.
Only truly spinning or deadlocked code triggers the watchdog.

Read docs/02-build-test.md for general approach to build and test
the project.

Important RPi4 test host specifics:

- Address: `freebsd@192.168.20.106`
- OS: FreeBSD 15.0-STABLE kernel #16 (SDIO + SDHCI fix)
- Build dir: `~/src/`; `/tmp` is cleared on reboot.

The driver requires the net80211 wlan module (`MODULE_DEPEND` on
`wlan`). The RPi4 kernel includes `device wlan`.

After a hung `kldload`, the module name stays registered in the kernel.
`kldunload` fails because the module is in an inconsistent state. A reboot
is required to clear it.

## Boot prerequisites (DONE)

1. **config.txt**: Remove `dtoverlay=mmc` to enable `mmcnr@7e300000`.
2. **SDIO module**: `sdio_load="YES"` in `/boot/loader.conf`.
3. **mmc-pwrseq**: Kernel rebuilt with `mmc-pwrseq-simple` driver.
   DT overlay `wlan-pwrseq.dtbo` handles WL_REG_ON via firmware GPIO.
4. **SDHCI fix**: `bcm2835_sdhci.c` patched for correct register
   write ordering (WR4 flush). Kernel #16 rebuilt 18 Mar 2026.

## Architecture: bus abstraction (DONE)

`struct brcmf_bus_ops` decouples upper layers from bus-specific
protocol. PCIe uses `brcmf_pcie_bus_ops` (msgbuf); SDIO uses
`brcmf_sdio_bus_ops` (SDPCM+BCDC). `fwil.c` and `cfg.c` call
through `sc->bus_ops->ioctl()` / `sc->bus_ops->tx()`.

### Reusable files (unchanged)

`cfg.c`, `cfg.h`, `scan.c`, `security.c`, `debug.c`, `debug.h`,
`fwil.c`, `core.c`

### SDIO-specific files

| File | Role |
|------|------|
| `sdio.c` | Backplane access, clock, core enumeration, firmware download |
| `sdpcm.c` | SDPCM framing, BCDC ioctl/data, event dispatch, bus_ops |
| `main.c` | Both PCI and SDIO `DRIVER_MODULE` registrations |

## Build system (DONE)

Build on RPi4: `cd ~/brcmfmac_build && sudo make -j2`

## Milestones

### M-S1: Bus ops abstraction (DONE)

- [x] `struct brcmf_bus_ops` in `brcmfmac.h`
- [x] `fwil.c`, `cfg.c` use `sc->bus_ops->ioctl/tx`
- [x] PCIe path verified (BCM4350, WPA2, ping)

### M-S2: SDIO bus layer (DONE)

- [x] Backplane window management (CMD52 to `0x1000A/B/C`)
- [x] `brcmf_sdio_bp_read32` / `brcmf_sdio_bp_write32`
- [x] Clock enable (ALP for init, HT for runtime)
- [x] EROM enumeration: chip=4345 rev=6
- [x] RAM info: base=0x198000, size=0xc8000 (800KB)
- [x] Firmware download via 64-byte F1 CMD53 block writes
- [x] NVRAM write (1748 bytes, token verified)
- [x] Firmware boots: `sharedram=0x00201cc0`
- [x] F2 enabled (IOEx=0x06), block size set
- [x] SDIO core hostintmask and watermark configured
- [x] `pause_sbt` yield in write loop (avoids watchdog starvation)

Firmware download takes ~2-3 minutes at 64 bytes/write through
the FreeBSD sdiob CAM stack (~100 CMD53/sec). Functional but slow.

### M-S3: SDPCM + BCDC protocol (IN PROGRESS)

- [x] SDPCM frame encode/decode (12-byte header)
- [x] BCDC command header (16 bytes)
- [x] `brcmf_sdpcm_ioctl()` implements `bus_ops->ioctl`
- [x] `brcmf_sdpcm_tx()` implements `bus_ops->tx`
- [x] `brcmf_sdpcm_recv()` reads F2 frames
- [x] `brcmf_sdpcm_process_event()` dispatches firmware events
- [x] `brcmf_sdpcm_process_rx()` delivers data frames
- [x] `brcmf_sdio_bus_ops` wired into `main.c`
- [ ] **BLOCKED**: F2 CMD53 writes hang the Arasan SDHCI controller.
  See "Current blocker" below.

### M-S4: SDIO probe/attach (DONE)

- [x] `main.c`: `brcmf_sdio_probe`, `brcmf_sdio_bus_attach`,
  `brcmf_sdio_bus_detach`
- [x] `DRIVER_MODULE(if_brcmfmac, sdiob, ...)`
- [x] Probe: vendor `0x02D0`, device `0xA9A6`, funcnum 1
- [x] F2 sibling lookup via parent's children
- [x] Attach: F1 enable, clock, chip ID, fw download, F2 setup
- [x] Detach: cleanup, clock disable
- [x] Makefile includes SDIO sources and `sdio_if.h`
- [x] `kldload` creates `brcmfmac0` on `sdiob0`

### M-S5: net80211 for BCM43455

Blocked on M-S3 (F2 writes).

- [ ] Firmware version and MAC query
- [ ] `brcmf_cfg_attach` (net80211 integration)
- [ ] Channel/mode setup (1SS HT, no VHT)
- [ ] Scan, association, WPA2

### M-S6: Upstream SDHCI fix

- [ ] Submit `bcm2835_sdhci.c` patch to FreeBSD

## Current blocker: F2 CMD53 writes

**Status (18 Mar 2026):** The kernel SDHCI fix (WR4 register write
ordering) resolved F1 CMD53 writes. Firmware download completes.
F2 CMD53 writes still cause a hard SDHCI controller hang.

**Evidence:**
- F1 CMD53 writes at 64 bytes: work (firmware download completes)
- F2 CMD53 writes at any block size: hang (controller stops responding)
- F2 reads work (SDIO core intstatus readable, frame indication present)
- Hang is not a timeout — the SDHCI controller freezes completely

**Diagnosis from earlier testing (pre-kernel-fix):**
- F2 byte-mode writes (4, 8, 16, 32 bytes) succeeded
- F2 block-mode writes (64+ bytes) failed with controller timeout
- All four CMD53 addressing modes tested (windowed/FIFO × inc/fixed)

**Hypothesis:** The SDHCI fix corrected a register write ordering
issue that affected F1 block writes. F2 block writes may require
an additional fix — possibly related to how the Arasan controller
handles data transfers on SDIO function 2 specifically, or to
the CMD53 argument construction for F2 in the sdiob CAM path.

**Next steps:**
1. Test F2 writes with block size reduced to match F1 (64 bytes)
2. Instrument sdiob CMD53 argument for F2 vs F1 writes
3. Check if the SDHCI fix needs to apply to the F2 data path too
4. Consider bypassing sdiob block-mode for F2 writes (byte-mode only)
