# Investigations

## D2H ring missed completions (26 Feb 2026)

**Status**: Partially fixed. IOCTL timeouts resolved. TX stalls remain.

### Symptom

All IOCTLs time out (2s each) during `brcmf_download_fw` →
`brcmf_cfg_attach` init:

```
brcmfmac0: IOCTL timeout cmd=0x2    (BRCMF_C_UP)
brcmfmac0: IOCTL timeout cmd=0x14   (BRCMF_C_SET_INFRA)
brcmfmac0: IOCTL timeout cmd=0x56   (BRCMF_C_SET_PM)
brcmfmac0: IOCTL timeout cmd=0x107  (iovar wrapper, cmd 263)
```

First IOCTL already fails — firmware not processing the control submit
ring at all.

### Decoded commands

| Hex | Dec | Command | Purpose |
|-----|-----|---------|---------|
| 0x2 | 2 | BRCMF_C_UP | Bring interface up |
| 0x14 | 20 | BRCMF_C_SET_INFRA | Set infrastructure (STA) mode |
| 0x56 | 86 | BRCMF_C_SET_PM | Set power management mode |
| 0x107 | 263 | — | IOVAR wrapper (likely "mpc" set) |

### Instrumentation added

On IOCTL timeout, the driver now prints:

- **chipid** — BAR0 offset 0 read; 0xffffffff means dead chip (H5)
- **mboxint** — pending MAILBOXINT; nonzero means firmware raised IRQ
  but host didn't process it (H4)
- **isr_filter / isr_task counts** — zero means MSI never arrived (H4)
- **H2D/D2H control ring pointers** — host-side w/r and firmware-side
  r/w from TCM; shows whether firmware consumed the request (H1/H6)
- **Firmware console** — last 512 bytes from shared memory console
  buffer; shows boot progress or assert (H1)

### Findings

Diagnostic output from two IOCTL timeout events confirmed:

- **H5 ruled out**: chipid=0x396 (alive)
- **H4 ruled out**: isr_filter=128, isr_task=116 (MSI working)
- **H1 confirmed (partial)**: firmware booted and processed requests
  (fw_rptr matched host w_ptr), but D2H completions were lost
- Root cause is in `brcmf_msgbuf_process_d2h`, not firmware

Key diagnostic line:
```
d2h_ctrl w=27 r=27 fw_wptr=49
```
Firmware wrote 49 completions, host only consumed 27.

### Bugs found

1. **DMA sync only covered RX ring.** `process_d2h` called
   `bus_dmamap_sync(POSTREAD)` on `rx_ring` only. Control and TX
   complete ring DMA writes were not synced, making firmware writes
   invisible to the CPU on non-coherent DMA.

2. **Loop exit only checked RX ring.** The "more work" loop exited
   when `rx_ring->w_ptr == rx_ring->r_ptr`, even if ctrl or TX
   complete rings had pending entries.

3. **No D2H polling fallback.** M16 removed D2H polling from the
   IOCTL wait loop to fix a double-processing crash. But without
   polling, a completion written between ISR task processing and
   the next interrupt was permanently lost.

### Fixes applied

- DMA sync all three D2H rings per pass
- Exit only when all three rings drained
- Re-add D2H poll in IOCTL wait loop (safe: ISR task serialized
  by taskqueue, IOCTL waiter holds ioctl_mtx)

### Remaining issue

IOCTL timeouts resolved, but TX stalls after ~30s. `Opkts=0` at link
layer while IP layer shows packets sent. Flowring may be full with no
TX completions being processed — same missed-completion pattern but
in the TX complete ring. Under investigation.
