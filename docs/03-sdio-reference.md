# SDIO Reference

Reference details for BCM43455 on Raspberry Pi 4.
This file is static context, not milestone tracking.
See docs/00-progress.md for current status, docs/12-sdio-retro.md for
historical bring-up lessons, and docs/10-investigations.md for session notes.

## RPi4 host

- Host: `freebsd@192.168.20.106`
- Build dir: `~/src/brcmfmac2`
- `/tmp` is cleared on reboot

## Hardware

- Chip: BCM4345 / CYW43455, chip ID `0x4345`, revision 6
- Bus: SDIO
- SDIO vendor/device: `0x02d0` / `0xa9a6`
- Host controller: BCM2835 Arasan SDHCI at `0x7e300000`
- ARM core: CR4 (core ID `0x83e`)
- RAM base: `0x198000`
- RAM size: `0x0c8000` (800 KB)
- SDIO device core: `0x829`

## Firmware files

- Firmware: `/boot/firmware/brcmfmac43455-sdio.bin`
- NVRAM: `/boot/firmware/brcmfmac43455-sdio.txt`
- CLM blob: `/boot/firmware/brcmfmac43455-sdio.clm_blob`

The firmware files came from a working RPi4 running Linux where WiFi association succeeds.

## Radio capabilities

- 1SS HT
- MCS 0-7
- 20/40 MHz
- No VHT support in the current net80211 exposure for BCM43455

## Boot prerequisites

1. Remove `dtoverlay=mmc` from `config.txt` so `mmcnr@7e300000` is enabled
2. Load `sdio` in `/boot/loader.conf`
3. Use `mmc-pwrseq-simple` with `wlan-pwrseq.dtbo` for WL_REG_ON
4. Keep the SDIO-related kernel support needed by the RPi4 host

## Bring-up lessons

- arm64 kernel stack is 16 KB — avoid large on-stack buffers
- F2 frame port is fixed-address FIFO at `0x8000`, not `sdiocore.base`
- F2 works with 64-byte blocks and fixed address mode
- round SDPCM frames to a 64-byte boundary
- verify every built `.ko` with `file` and `wc -c`
- after failed loads, check `/var/crash` and `/var/log/messages`
- R5 response bits in `resp[0]` must be decoded with `mmcreg.h` bit positions
- repeated failed SDIO states can leave the chip needing a reboot

Retrospective (only for historical context): `docs/12-sdio-retro.md`.
