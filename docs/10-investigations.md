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

## Firmware hung after idle link loss (26 Feb 2026)

**Status**: Fixed (watchdog enhancement).

### Symptom

After ~12 minutes idle, `wlan0: link state changed to DOWN` appeared.
wpa_supplicant entered SCANNING but never reconnected — empty scan
results, no ISR activity. `kldunload` hung indefinitely.

### Analysis

The AP disconnected the idle client (deauth or beacon miss). The
driver correctly transitioned to SCAN state, but the firmware stopped
processing rings entirely — zero new ISR interrupts after the link
loss event. PCI MMIO still responded (not 0xffffffff), so the
watchdog didn't trigger.

The firmware's ARM core likely hit an internal error (assert, trap,
or deadlock) coincident with or caused by the link loss. The PCI
interface remained functional but the msgbuf ring processing loop
stopped.

Consequences:
- No ESCAN_RESULT events → wpa_supplicant sees no APs
- IOCTL timeouts on any new command
- Flowring create timeout when trying to reconnect
- `kldunload` hung because detach sends IOCTLs to dead firmware

### Fix

1. Enhanced watchdog to detect ring-level stalls: if an IOCTL is pending
   and the ISR task count hasn't changed across two watchdog intervals
   (~10s), firmware is declared dead.

2. Converted watchdog to a 10ms D2H poll callout. The ISR taskqueue
   thread stops executing tasks under bhyve (`taskqueue_enqueue` from
   the filter context doesn't reliably wake the thread). D2H polling
   at 10ms keeps RX alive regardless of whether the ISR task runs.
   Heavy checks (chip liveness, firmware stall) run every ~5s.

Previously the watchdog only checked for PCI bus death (MMIO returning
0xffffffff) and ran every 5s.

## scan_active stuck after link loss (26 Feb 2026)

**Status**: Fixed.

### Symptom

After AP disconnects (idle timeout, DFS channel switch), wpa_supplicant
enters SCANNING but never reconnects. `wpa_cli scan_results` and
`ifconfig wlan0 list scan` both empty.

### Root cause

`sc->scan_active` was set to 1 when the escan IOCTL was sent. It's
cleared when the firmware sends `ESCAN_RESULT` with status != partial
(scan complete). If the link drops mid-escan, the firmware stops
sending events, `scan_active` stays 1 forever, and
`brcmf_scan_start` returns early on all subsequent scan attempts.

### Fix

Clear `scan_active` and `scan_complete` in `brcmf_link_event` on
link down (both `BRCMF_E_LINK` with link=0 and
`DEAUTH`/`DISASSOC` events). This allows new scans to start after
link loss.

## ISR taskqueue thread stops executing under bhyve (26 Feb 2026)

**Status**: Worked around with D2H poll callout.

### Symptom

After ~10-15 minutes, the ISR taskqueue thread stops processing tasks.
`isr_filter_count` increments (MSI fires, filter runs) but
`isr_task_count` stays frozen. The thread is alive (sleeping in
`taskqueue_thread_loop`) but `taskqueue_enqueue` from the filter
context doesn't wake it.

Consequences: D2H rings stop draining, RX dies, link events are lost,
IOCTL completions only arrive via the ioctl poll fallback.

### Analysis

The filter handler runs at interrupt priority, disables interrupts,
and calls `taskqueue_enqueue`. The taskqueue thread sleeps in `_sleep`
waiting for work. Under bhyve, `wakeup_one` from filter context
doesn't always reach the sleeping thread.

Not reproduced on real hardware (untested). May be a bhyve-specific
issue with MSI delivery or wakeup signaling from interrupt context.

### Workaround

Converted the 5s watchdog callout to a 10ms D2H poll. Every tick:
1. `brcmf_msgbuf_process_d2h(sc)` — drain all three D2H rings
2. Check MAILBOXMASK — re-enable interrupts if stuck disabled

Every 500th tick (~5s): chip liveness check (MMIO 0xffffffff) and
firmware stall detection (ISR count frozen during pending IOCTL).

This makes the driver independent of the ISR taskqueue for D2H
processing. The ISR task still runs when it can (reducing latency
to sub-ms), but the poll provides a guaranteed 10ms fallback.
