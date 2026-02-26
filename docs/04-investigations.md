# Investigations

## D2H ring missed completions (26 Feb 2026)

**Status**: Fixed.

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

### Resolution

The three D2H ring fixes resolved all symptoms. The earlier 98% flood
loss was observed on code that only had the IOCTL poll fix but was
missing the DMA sync and loop exit fixes. After a chip power cycle
and clean test with all three fixes, flood ping passes 1000/1000 at
10ms interval with zero TX drops.

## Chip stuck after VM power cycle (26 Feb 2026)

**Status**: Blocked. Needs physical host power cycle.

### Sequence

1. Driver loaded, WPA2 associated, gateway ping working (20/20)
2. Ran 100x flood ping at 50ms interval → 98% loss (TX ring full)
3. `vm poweroff vm0; vm start vm0` to load updated .ko
4. On reboot, `kldload` → "chip ID read failed" (BAR0 reads 0xffffffff)
5. `devctl reset`, additional `vm poweroff`/`vm start` — no recovery

### Analysis

The chip was alive after the flood ping (TX drops are handled in
software — mbufs freed, no firmware crash). The `vm poweroff` is the
trigger.

bhyve sends ACPI shutdown to the guest. The guest kernel shuts down
but the BCM4350 — passed through via PCI passthrough — does not
receive a Function Level Reset (FLR) or secondary bus reset. The
firmware's ARM core is left in whatever state it was in when the VM
disappeared.

Previous `vm poweroff`/`vm start` cycles worked because the driver was
either unloaded cleanly first (kldunload drains rings and sends
BRCMF_C_DOWN) or the chip was idle. This time, the driver was active
with a flowring, TX buffers DMA-mapped, and firmware mid-operation.
The firmware's DMA engine may have been writing to host memory that
vanished, leaving the ARM core hung.

### Scope

VM-only problem. bhyve PCI passthrough doesn't issue FLR or bus reset
on passed-through devices when the VM shuts down.

On real hardware, `shutdown -p` triggers D3 transition and cold boot
resets the PCI bus via platform firmware. The only real-hardware
equivalent is a kernel panic followed by warm reboot (no bus reset).
Cold power cycle always recovers.

### Prevention (VM workflow)

Before `vm poweroff`, always:
1. `pkill wpa_supplicant` (with 2s pause)
2. `ifconfig wlan0 destroy` (with 2s pause)
3. `kldunload if_brcmfmac`
4. Then `vm poweroff`
