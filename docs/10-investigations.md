# Investigations

## 18 Mar 2026: SDIO F2 write on fixed kernel #16

### What works
- F1 byte access (sdio_read_1/write_1): works
- F1 block access at 64 bytes via CMD53: works (firmware download completes)
- ALP/HT clock enable: works
- EROM/chip enumeration: chip=4345 rev=6
- RAM discovery: 0x198000, 800KB
- Firmware download: ~609KB via 64-byte F1 CMD53 writes (takes ~2-3 minutes)
- Firmware boot: sharedram=0x00201cc0
- F2 enable: IOEx=0x06
- SDIO core intstatus: 0x008000c0 (frame indication present)

### What still fails
- F2 writes (SDPCM TX via `SDIO_WRITE_EXTENDED` on F2): causes hard SDHCI hang
- `brcmf_sdpcm_send` → F2 CMD53 write at 512-byte block size → controller hangs
- Host becomes unreachable; only hardware watchdog or power cycle recovers

### Root cause hypothesis
The kernel SDHCI fix addressed F1 CMD53 writes but F2 CMD53 writes
still hang. F2 uses a different SDIO function number (fn=2) and the
sdiob CAM path may construct the CMD53 differently for F2 vs F1.

Or: the F2 block size (512) exceeds what the Arasan controller can handle
in the fixed mode. F1 uses 64-byte blocks which work.

### Next step
- Try F2 writes with smaller block size (64 instead of 512)
- If that works, the issue is block-size-specific in the SDHCI path
- If not, the issue is F2-specific regardless of size
