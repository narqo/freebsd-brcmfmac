# M-S3/M-S5 Implementation Plan: SDPCM data path and net80211

Read docs/02-build-test.md for general guidance.
Read docs/05-sdio-plan.md for hardware details.
Read docs/10-investigations.md for previous investigations.

## Current state (20 Mar 2026)

M-S1, M-S2, M-S4 done. Firmware boots, F2 becomes ready
(IORdy=0x06). SDPCM/BCDC protocol code exists in `sdpcm.c`.
SDHCI bugs fixed (kernel SDIOF2FIX1).

**Blocker:** F2 CMD53 writes fail with EIO. The CAM/sdiob layer
returns `CAM_REQ_CMP_ERR` (error 5, retries exhausted). F2 reads
work. The "ver" ioctl fails because `brcmf_sdpcm_send` cannot
write the SDPCM frame to F2.

**IORdy poll hazard:** The 50×50ms IORdy poll loop hangs the
system on first load after fresh boot (F2 not ready, loop runs
all iterations). Replaced with a single check + abort. On second
load, F2 is ready immediately. See docs/10-investigations.md.

## Step 1: Make kldload safe — single IORdy check

Replace the IORdy poll loop with a single CCCR 0x03 read. If F2
is not ready, abort with ENXIO. The module can be loaded again.

On first load after fresh boot: F2 not ready, clean abort.
On second load: F2 ready (iter=0), proceeds to ver ioctl.

This avoids the `pause_sbt` hang without losing functionality —
the F2 write fails with EIO regardless of F2 readiness.

**Status:** DONE

## Step 2: Debug F2 write EIO

The real blocker. Every F2 CMD53 write returns EIO, even when
F2 is ready (IORdy=0x06). Both 4-byte and 160-byte writes fail.
F2 reads succeed.

### 2a. Identify the SDHCI-level error

Add diagnostic after the failed F2 write:
- Read SDIO core intstatus
- Check if sdhci reports timeout, CRC, or data error
- Log the R5 response if available

### 2b. Check F2 write address

Our `brcmf_sdpcm_send` writes to F2 address 0 (FIFO, incr).
Our `brcmf_sdpcm_recv` reads from the SDIO core backplane
address. Linux may use a different write address. Compare
against `brcmf_sdiod_send_buf` / `brcmf_sdiod_send_pkt` in
the Linux driver.

### 2c. Check for missing init steps

Compare our init sequence in `brcmf_sdio_download_fw` against
Linux `brcmf_sdio_bus_init()`. Possible missing steps:
- Ack pending intstatus before first F2 write
- Clear tohost mailbox
- Configure CCCR interrupt enables (reg 0x04) for F2
- Set SDIO core sleep/wake state

### 2d. Escalation path

If the EIO persists after 2a-2c, ask the kernel developer for
sdhci-level tracing of the failed CMD53. The CAM layer hides
the actual SDHCI error code. A printf in `sdhci_cmd_irq` or
`sdhci_data_irq` showing `intmask` for the failing CMD53 would
identify the root cause.

## Step 3: First successful ioctl

Once F2 writes work:

Goal: `brcmf_fil_iovar_data_get(sc, "ver", ...)` returns the
firmware version string.

The ioctl sends an SDPCM control frame (F2 write), then polls
for a response (F2 reads in `brcmf_sdpcm_recv`). The recv path
reads 512 bytes from F2. If writes work but reads don't return
data, check:

- SDIO core intstatus for I_HMB_FRAME_IND (bit 6)
- The recv address: currently uses backplane-windowed SDIO core
  address. Linux reads from address 0. May need to unify.

## Step 4: Wire up `brcmf_cfg_attach`

After the "ver" ioctl succeeds, call `brcmf_cfg_attach(sc)` from
`brcmf_sdio_bus_attach` in `main.c`. The existing `cfg.c` is
bus-agnostic. BCM43455: 1SS HT, no VHT, MCS 0-7, 20/40 MHz.
`cfg.c` auto-adapts from firmware responses.

## Step 5: RX data path — polling callout

Add a 10-20ms callout in `sdpcm.c`:
1. Check SDIO core intstatus for frame indication
2. `brcmf_sdpcm_recv` to read the frame
3. Dispatch: control → ioctl, event → link/scan, data → if_input

Race with ioctl poll: protect with `ioctl_mtx` or suppress
callout during ioctl.

## Step 6: Test scan and association

1. `ifconfig wlan0 create wlandev brcmfmac0`
2. `ifconfig wlan0 up`
3. `ifconfig wlan0 list scan`
4. `wpa_supplicant` (need AP reachable from RPi4)

## Step 7: TX data path

`brcmf_sdpcm_tx` already implements `bus_ops->tx`. Verify
bidirectional data flow with ping after association.

## Key differences from PCIe path

| Aspect | PCIe (msgbuf) | SDIO (SDPCM+BCDC) |
|--------|---------------|-------------------|
| Ioctl | DMA ring + completion | SDPCM control channel |
| TX | Flow ring + DMA | SDPCM data channel |
| RX | Pre-posted buffers + completion ring | F2 read on poll |
| Events | Embedded in RX completions | SDPCM event channel |
| Flow control | Flow ring create/delete | SDPCM max_seq |

`cfg.c` NULL-checks `flowring_create`/`flowring_delete` (both
NULL for SDIO bus_ops).

## Testing protocol

1. Always verify .ko before loading: `file` + `wc -c`
2. First load after fresh boot: expect F2 not ready, clean abort
3. Second load: expect F2 ready, F2 write EIO (until step 2 resolved)
4. If hang detected, wait ≤5min for SSH, then stop and wait for user
5. After unclean reboot, re-verify .ko (fs corruption zeros files)
