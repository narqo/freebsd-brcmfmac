# Investigations

## IOCTL timeout at init (26 Feb 2026)

**Status**: Not reproduced. Diagnostic instrumentation added; waiting
for next occurrence.

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

### Hypotheses

| # | Hypothesis | Check |
|---|-----------|-------|
| H1 | Firmware not booted / not processing rings | Console output, D2H ring pointers |
| H2 | Doorbell write not reaching firmware | BAR0 window, register read-back |
| H3 | IOCTL response buffer DMA addresses invalid | Print DMA addrs at post time |
| H4 | MSI not arriving / completion path broken | ISR counters, MAILBOXINT read |
| H5 | Chip stuck from prior crash | Chip ID read (0xffffffff) |
| H6 | Missing bus barrier on w_ptr TCM write | Ring pointer comparison host vs firmware |

### Investigation order

1. Chip ID after firmware boot — rules out H5
2. ISR filter counter after first timeout — rules out H4
3. MAILBOXINT register after timeout — firmware raised IRQ?
4. Firmware console buffer — rules out H1
5. DMA addresses of ioctlresp/ioctlbuf — rules out H3
6. Bus barrier before w_ptr write — rules out H6
7. Doorbell register read-back — rules out H2

### IOCTL path (reference)

1. `brcmf_msgbuf_tx_ioctl`: write `MSGBUF_TYPE_IOCTLPTR_REQ` to H2D
   control submit ring, update w_ptr in TCM, doorbell write to
   `BRCMF_PCIE_PCIE2REG_H2D_MAILBOX_0`
2. `brcmf_msgbuf_ioctl`: `msleep` on `sc->ioctl_completed`, 2s timeout
3. Firmware writes `MSGBUF_TYPE_IOCTL_CMPLT` to D2H control complete
   ring, raises MSI
4. `brcmf_pcie_isr_filter` → ack + disable → enqueue ISR task
5. `brcmf_pcie_isr_task` → `brcmf_msgbuf_process_d2h` → set
   `ioctl_completed=1` → `wakeup`
