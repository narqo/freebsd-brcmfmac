# M-S3/M-S5 Implementation Plan: SDPCM data path and net80211

Read docs/02-build-test.md for general guidance.
Read docs/05-sdio-plan.md for hardware details.
Read docs/10-investigations.md for investigation history.

## Current state (21 Mar 2026)

M-S1, M-S2, M-S4 done. Kernel: SDIO.

**M-S3 complete.** First successful SDPCM ioctl over SDIO F2:

```
firmware: wl0: Aug 29 2023 01:47:08 version 7.45.265 (28bca26 CY)
```

F2 transfers work with 64-byte blocks, fixed address, tolerant
recv. No kernel changes beyond sdiob F0 timeout fix.

### Key lessons (avoid repeating)

- arm64 kernel stack is 16KB — never put >1KB arrays on stack
- sdiob F0 CMD52 timeout was 0; any F0 poll hung without kernel fix
- F2 frame port address is SI_ENUM_BASE windowed (0x8000), not
  sdiocore.base (0xC000)
- Unclean reboots corrupt UFS; always verify .ko with `file` + `wc -c`
- After hang, wait ≤5min for SSH then stop and wait for user
- Check /var/crash and /var/log/messages after every failed load
- `sdio_set_block_size(func2)` via CAM hangs; use CCCR FBR writes
- R5 response bits in SDHCI resp[0] use mmcreg.h positions, not
  raw 48-bit SDIO spec positions

## Current experiment: skip IORdy, attempt F2 write anyway

### Rationale

IORdy=0x02 does not necessarily mean the card rejects CMD53.
On SDIOF2FIX1, F2 CMD53 writes return clean EIO (no hang) even
when attempted. The firmware IS running (sharedram valid). The
card may accept F2 data even without IORdy bit 2.

If the write fails, the sdiob instrumentation will show the
raw CMD53 arg, MMC error code, and R5 response — which is
exactly what we need to diagnose the F2 write problem regardless
of IORdy state.

### What to change

Remove the IORdy abort. After firmware boot, proceed directly
to hostintmask/watermark config and the ver ioctl. Log IORdy
value for diagnostics but don't gate on it.

### Expected outcomes

1. **F2 write succeeds** — firmware version string returned.
   Proceed to step 2 (wire up brcmf_cfg_attach).
2. **F2 write fails with EIO, sdiob logs details** — we learn
   the exact MMC error and R5 response. Diagnose from there.
3. **F2 write hangs** — SDHCI bug, need kernel fix. Watchdog
   will fire in ~15s. (Unlikely: SDIOF2FIX1 returned clean EIO
   for F2 CMD53 writes in prior tests.)

### Alternative if this fails

**Path A:** Ask kernel developer to investigate why F0 CMD52
polls to CCCR 0x03 hang while F1 CMD52 polls to 0x1000E work.
If fixed, we can poll IORdy for 3s like Linux, get F2 ready,
then test writes normally.

## Step 2: Wire up `brcmf_cfg_attach`

After the ver ioctl succeeds, call `brcmf_cfg_attach(sc)` from
`brcmf_sdio_bus_attach` in `main.c`. `cfg.c` is bus-agnostic.
BCM43455: 1SS HT, no VHT, MCS 0-7, 20/40 MHz.

## Step 3: RX data path — polling callout

Add a 10-20ms callout in `sdpcm.c` for RX frame processing.
Race with ioctl poll: protect with `ioctl_mtx`.

## Step 4: Scan and association

Test with AP reachable from RPi4.

## Step 5: TX data path

`brcmf_sdpcm_tx` exists. Verify with ping.

## Testing protocol

1. Verify .ko: `file` + `wc -c` (must be ELF, >10KB)
2. If hang detected, wait ≤5min then stop and wait for user
3. After unclean reboot, re-verify .ko
