# sdiob instrumentation for F2 CMD53 write debugging

Add one printf inside `sdiob_rw_extended_cam` in
`sys/dev/sdio/sdiob.c`, in the error path after
`cam_periph_runccb` (around line 332).

## Current code

```c
	error = cam_periph_runccb(sc->ccb, sdioerror, CAM_FLAG_NONE, 0, NULL);
	if (error != 0) {
		if (sc->dev != NULL)
			device_printf(sc->dev,
			    "%s: Failed to %s address %#10x buffer %p size %u "
			    "%s b_count %u blksz %u error=%d\n",
			    ...);
```

## Add after the existing device_printf

```c
		if (sc->dev != NULL) {
			device_printf(sc->dev,
			    "%s: Failed to %s address %#10x buffer %p size %u "
			    "%s b_count %u blksz %u error=%d\n",
			    __func__, (wr) ? "write to" : "read from", addr,
			    buffer, len, (incaddr) ? "incr" : "fifo",
			    b_count, blksz, error);
			device_printf(sc->dev,
			    "%s: arg=0x%08x mmc_err=%d resp[0]=0x%08x ccb_status=0x%02x\n",
			    __func__, arg,
			    sc->ccb->mmcio.cmd.error,
			    sc->ccb->mmcio.cmd.resp[0],
			    sc->ccb->ccb_h.status);
		}
```

## What this tells us

- `arg` — the raw CMD53 argument (fn, addr, mode, count)
- `mmc_err` — SDHCI error code (0=none, 1=timeout, 2=badcrc,
  3=fifo, 7=failed)
- `resp[0]` — raw R5 response (error flags in bits 8-16:
  bit 8=COM_CRC, bit 9=ILLEGAL_CMD, bit 11=ERROR,
  bit 12=FUNCTION_NUMBER, bit 16=OUT_OF_RANGE)
- `ccb_status` — CAM completion status
