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
4. **Kernel patches** (kernel #19, 18 Mar 2026):
   - `bcm2835_sdhci.c`: pass correct OFW node for mmc-pwrseq
   - `bcm2835_sdhci.c`, `sdhci.c`, `sdhci_if.m`: platform_update_ios
     for pwrseq/regulator
   - `mmc_xpt.c`: SDIO bus clock to 25 MHz
   - `mmc_xpt.c`: 4-bit SDIO bus width via CCCR 0x07

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

Firmware download was ~2-3 minutes on kernel #16 (1-bit bus).
On kernel #19 (4-bit bus, 25 MHz) it completes in seconds.

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

## Current blocker: F2 CMD53 writes

**Status (18 Mar 2026, kernel #19 — 4 patches applied):**

Kernel patches fixed F1 CMD53 writes and the hard-hang behavior.
F2 CMD53 writes now return error=5 (EIO) instead of freezing the
controller, but they still do not succeed.

**Test matrix (kernel #19, 4-bit bus, 25 MHz):**

| What | Mode | Size | Result |
|------|------|------|--------|
| F1 CMD53 write | block | 64 B | works (fw download) |
| F2 CMD53 write | block | 512 B (`b_count=1`) | error=5, no hang |
| F2 CMD53 write | block | 64 B (`b_count=N`) | hard hang, watchdog reboot |
| F2 CMD53 write | byte | 160 B (`b_count=0`) | error=5, no hang |
| F2 CMD53 read | any | any | works |

**Key observations:**
- F2 writes fail regardless of byte vs block mode for sizes >32 bytes
- F2 reads work at all sizes
- F1 writes work at all tested sizes
- The error is specific to F2 (function number 2) write direction
- sdiob constructs CMD53 with `SD_IOE_RW_WR` flag and `fn=2`

**Hypothesis:** The sdiob/SDHCI stack has a remaining issue specific
to CMD53 writes on function 2. Possible causes:
- The F2 function is not fully enabled at the SDIO protocol level
  (CCCR IOEx shows 0x06 = F1+F2 enabled, but the card may require
  additional setup before accepting F2 data writes)
- The Arasan SDHCI controller may need function-specific configuration
  for write transfers that the current patches don't cover
- The CMD53 argument encoding for F2 writes may differ from F1 in a
  way the sdiob CAM path doesn't handle

**Next steps:**
1. Verify F2 is truly ready: check CCCR IORdy (reg 0x03) bit for F2
2. Check if F2 requires explicit interrupt enable (CCCR 0x04) before
   accepting writes
3. Compare CMD53 argument word between working F1 writes and failing
   F2 writes — the function number field and RW bit
4. Try small F2 writes (4/8/16/32 bytes) on kernel #19 to confirm
   the size threshold still holds
