# Code Review

Review date: 28 Feb 2026. Focus: correctness and security.

## Severity levels

- **P1** — can cause kernel panic, data corruption, or security breach
- **P2** — incorrect behavior, resource leak, or latent bug
- **P3** — style, cleanup, or hardening

---

## P1-1: Concurrent D2H ring processing from three contexts

`brcmf_msgbuf_process_d2h` is called from:

1. `brcmf_pcie_isr_task` (ISR taskqueue)
2. `brcmf_watchdog` (callout, every 10ms)
3. `brcmf_msgbuf_ioctl` (ioctl wait loop, on timeout retry)

The ring pointer fields (`r_ptr`, `w_ptr`) have no synchronization.
Two concurrent callers can read the same `w_ptr`, process the same
completion entry, and deliver the same RX mbuf twice (double-free)
or complete the same TX buffer twice. This was the root cause of the
M16 socket buffer corruption crash (core.txt.3). The M16.6 changes
re-introduced polling from the watchdog and ioctl paths, breaking
the single-owner invariant documented in `01-decisions.md`.

**Files:** `pcie.c:brcmf_watchdog`, `msgbuf.c:brcmf_msgbuf_ioctl`,
`msgbuf.c:brcmf_msgbuf_process_d2h`

**Fix:** Either (a) protect `brcmf_msgbuf_process_d2h` with an
atomic flag or mutex so only one caller processes at a time, or
(b) remove the direct calls from watchdog and ioctl paths and
instead enqueue the ISR task (`taskqueue_enqueue(sc->isr_tq,
&sc->isr_task)`).

---

## P1-2: IOCTL buffer race between preparation and submission

The shared `sc->ioctlbuf` DMA buffer is written in `brcmf_fil_*`
functions **before** `brcmf_msgbuf_ioctl` acquires `ioctl_mtx`.
Two concurrent callers (e.g., `brcmf_link_task` on `taskqueue_thread`
and `brcmf_sysctl_pm` on a sysctl thread) both write to `ioctlbuf`,
then one enters the mutex and submits the other's data.

Affected functions: `brcmf_fil_iovar_data_get`,
`brcmf_fil_iovar_data_set`, `brcmf_fil_cmd_data_set`,
`brcmf_fil_cmd_data_get`.

**Files:** `fwil.c`

**Fix:** Move the `ioctl_mtx` acquisition into the fwil layer so it
covers buffer preparation through response copy-out. Alternatively,
have `brcmf_msgbuf_ioctl` accept the data to copy into `ioctlbuf`
under the lock.

---

## P1-3: TX pktid slot overwrite when ring is full

`brcmf_msgbuf_tx` checks only the single slot at
`txbuf[pktid % BRCMF_TX_RING_SIZE]`. If all 256 slots are occupied
(completions lagging), `tx_pktid_next` advances past the ring size
and `pktid % 256` wraps back to a slot with an inflight mbuf. The
check `txbuf[...].m != NULL` catches this for the *current* `pktid`,
but only rejects and drops the new packet. The real problem: there is
no backpressure signal. Under sustained TX pressure with delayed
completions, the driver silently drops every packet once the ring
fills, with no indication to the network stack.

More concerning: if `tx_complete` processing races (see P1-1), a
slot's `m` could be NULLed while the DMA is still inflight, and the
next TX overwrites it.

**File:** `msgbuf.c:brcmf_msgbuf_tx`

**Fix:** Track in-flight count explicitly. Return `ENOBUFS` when
count equals `BRCMF_TX_RING_SIZE`. Consider `if_setdrvflagbits` to
set `IFF_DRV_OACTIVE` when the ring is full.

---

## P1-4: PSK readable by unprivileged local users

The `psk` sysctl is registered with `CTLFLAG_RW` and no privilege
restriction. Any local user can read the WiFi passphrase:

```
$ sysctl dev.brcmfmac.0.psk
```

The PSK remains in `sc->psk` in plaintext for the module lifetime.

**File:** `security.c:brcmf_security_sysctl_init`

**Fix:** Use `CTLFLAG_WR` (write-only), or add `CTLFLAG_SECURE`
to require `securelevel <= 0`. Zero the `sc->psk` buffer after
`brcmf_set_pmk` pushes it to firmware. In the read handler, return
`"********"` or empty string instead of the actual PSK.

---

## P1-5: BAR0 window register unserialized across CPUs

`brcmf_pcie_select_core` writes the BAR0 window register. It is
called from:

- `brcmf_pcie_isr_filter` (hard IRQ context, any CPU)
- `brcmf_pcie_isr_task` (ISR taskqueue thread)
- `brcmf_watchdog` (callout, potentially on a different CPU)
- `brcmf_bp_read32` / `brcmf_bp_write32` (used during attach)

If the watchdog callout runs on CPU1 while the ISR filter fires on
CPU0, both write the BAR0 window register concurrently. One reads
the wrong 4K window.

**Files:** `pcie.c`, `core.c`

**Fix:** Serialize BAR0 window access with a spinlock (MTX_SPIN,
since it's used in filter context).

---

## P2-1: Scan result buffer TOCTOU between ISR and scan task

`brcmf_escan_result` (called from ISR task context) writes to
`sc->scan_results[]` and `sc->scan_nresults`.
`brcmf_scan_complete_task` (called from `taskqueue_thread`) reads
the same fields. No lock protects them. A new escan starting between
the snapshot (`n = sc->scan_nresults`) and the result iteration can
overwrite entries being read.

**Files:** `scan.c`, `cfg.c`

**Fix:** Either copy the result buffer locally in
`brcmf_scan_complete_task`, or add a mutex around scan result access.

---

## P2-2: `brcmf_vap_delete` drains scan tasks after `vap_detach`

```c
ieee80211_vap_detach(vap);     // frees internal VAP state
brcmf_drain_scan_tasks(ic);   // tasks may still reference vap
free(bvap, M_80211_VAP);
```

If `scan_curchan_task` fires between `vap_detach` and
`drain_scan_tasks`, it accesses `ss->ss_vap` which points to freed
memory.

**File:** `cfg.c:brcmf_vap_delete`

**Fix:** Drain scan tasks before `ieee80211_vap_detach`.

---

## P2-3: `brcmf_msgbuf_init_flowring` leaks on partial failure

`sc->flowring` is set to the allocated ring **before** the create
request is submitted. If `brcmf_msgbuf_ring_reserve` fails (returns
`ENOBUFS`), the function returns with `sc->flowring` pointing to an
orphaned ring. The caller doesn't clean it up, and the next
`brcmf_msgbuf_delete_flowring` will try to send a delete request to
firmware for a ring that was never created.

Similarly, on create timeout (`flowring_create_done == 0`), the
function sets `fw_dead = 1` but doesn't free the DMA buffer or
reset `sc->flowring`.

**File:** `msgbuf.c:brcmf_msgbuf_init_flowring`

**Fix:** Move `sc->flowring = ring` to after successful completion.
On failure paths, free the ring and DMA resources.

---

## P2-4: `brcmf_link_task` accesses `vap->iv_bss` without node lock

```c
ni = vap->iv_bss;
if (ni != NULL) {
    IEEE80211_ADDR_COPY(ni->ni_bssid, bssid);
    ni->ni_chan = chan;
    ...
```

`iv_bss` can be swapped by net80211 concurrently (e.g., during
`ieee80211_sta_join`). The reference could become stale. Other
FreeBSD drivers use `ieee80211_ref_node(vap->iv_bss)` under the
COM lock.

**File:** `cfg.c:brcmf_link_task`

---

## P2-5: `brcmf_detect_security` misidentifies WEP as WPA2

```c
if (sr->capinfo & IEEE80211_CAPINFO_PRIVACY) {
    *wpa_auth = WPA2_AUTH_PSK;
    return AES_ENABLED;
}
```

Any BSS with the PRIVACY capability bit (including WEP) is tagged as
WPA2-PSK/AES. Currently harmless because the direct-join path rejects
`wpa_auth != WPA_AUTH_DISABLED`, but if that guard is removed, the
driver will attempt WPA2 association to WEP networks.

**File:** `security.c:brcmf_detect_security`

**Fix:** Parse the RSN/WPA IEs from `sr->ie` to determine the actual
security suite, or simply set `WSEC_NONE` / `WPA_AUTH_DISABLED` for
all BSS in this function (since the direct-join path already rejects
WPA, and the wpa_supplicant path sets security independently).

---

## P2-6: RX path copies every packet — unnecessary data copy

`brcmf_rx_deliver` allocates a fresh mbuf via `m_get2` and copies
the entire packet from the DMA buffer. Every received packet incurs
a full-length `memcpy`. This halves the effective memory bandwidth
for RX.

**File:** `msgbuf.c:brcmf_rx_deliver`

**Fix:** Use `m_extadd` or a custom external mbuf that references
the DMA buffer directly, deferring the free to mbuf release. This
requires a different RX buffer lifecycle (don't repost until mbuf
is freed). Lower priority than correctness issues.

---

## P2-7: No DMA sync before H2D ring writes

Ring buffers are allocated with `BUS_DMA_COHERENT`. On x86 this is
a no-op, but on non-coherent architectures (ARM), writes to the ring
buffer via `brcmf_msgbuf_ring_reserve` are not guaranteed to be
visible to the device without `bus_dmamap_sync(PREWRITE)`.

**Files:** `msgbuf.c:brcmf_msgbuf_ring_reserve`,
`msgbuf.c:brcmf_msgbuf_ring_submit`

**Fix:** Add `bus_dmamap_sync(ring->dma_tag, ring->dma_map,
BUS_DMASYNC_PREWRITE)` in `brcmf_msgbuf_ring_submit`, before
writing the write index. Low priority for x86-only target.

---

## P2-8: `brcmf_scan_complete_task` accesses VAP fields without COM lock

```c
vap->iv_roaming
vap->iv_des_nssid
vap->iv_des_ssid[0]
vap->iv_des_bssid
```

These fields can be modified concurrently by `ifconfig` or
`wpa_supplicant` via net80211 ioctls. Reading them without the COM
lock is a data race.

**File:** `scan.c:brcmf_scan_complete_task`

---

## P2-9: Event datalen bounds check is off by one direction

```c
if (datalen > 0 && datalen < BRCMF_MSGBUF_MAX_CTL_PKT_SIZE - sizeof(*event))
    brcmf_escan_result(sc, (uint8_t *)cb->buf + sizeof(*event), datalen);
```

The check prevents reading past the buffer, but the firmware is
trusted to write a well-formed event. A compromised firmware could
write `event_code = BRCMF_E_ESCAN_RESULT` with a crafted
`datalen` just under the limit, causing `brcmf_escan_result` to
parse attacker-controlled data. The escan parser validates
`buflen` and `bi_len` internally, so this is defense-in-depth
rather than exploitable today.

**File:** `msgbuf.c:brcmf_msgbuf_process_event`

---

## P3-1: Dead header file `pcie.h`

`src/pcie.h` includes `<linux/pci.h>` and declares `struct
pci_driver`. It is never included anywhere in the build and would
fail to compile. Leftover from an early LinuxKPI attempt.

**Fix:** Delete the file.

---

## P3-2: Duplicate macro definitions

`BRCMF_RING_MEM_BASE_ADDR_OFFSET`, `BRCMF_RING_MAX_ITEM_OFFSET`,
`BRCMF_RING_LEN_ITEMS_OFFSET`, and `BRCMF_RING_MEM_SZ` are defined
in both `pcie.c` and `msgbuf.c`.

Event codes `BRCMF_E_SET_SSID`, `BRCMF_E_DEAUTH`, etc., are defined
in both `cfg.h` and `msgbuf.c`.

**Fix:** Move shared definitions to a single header.

---

## P3-3: `ETHER_ADDR_LEN` redefined

```c
#define ETHER_ADDR_LEN 6
```

Already defined in `<net/ethernet.h>`, which is included via the
same header chain.

**File:** `brcmfmac.h`

---

## P3-4: `brcmf_sysctl_psk` stack buffer NUL termination

```c
char buf[65];
memset(buf, 0, sizeof(buf));
...
error = sysctl_handle_string(oidp, buf, sizeof(buf), req);
...
int len = strlen(buf);
```

If `sysctl_handle_string` writes exactly 64 characters, `buf[64]`
is the NUL terminator (initialized by `memset`), so this is safe.
But the code relies on the `memset` being done before the handler
call — fragile if the code is refactored.

**File:** `security.c:brcmf_sysctl_psk`

---

## P3-5: EROM scanner worst-case iteration count

The Zig EROM scanner uses `safety` counters of 256 in nested loops.
If the EROM is corrupt, it spins for up to 65536 backplane reads
(each going through the BAR0 window register) before returning.
This runs during attach, so it blocks the boot path.

**File:** `brcmfmac.zig:EromScanner`

---

## P3-6: `brcmf_newstate` drops and reacquires COM lock

```c
IEEE80211_UNLOCK(ic);
/* firmware work */
IEEE80211_LOCK(ic);
return (bvap->newstate(vap, nstate, arg));
```

After reacquiring the lock, the VAP state may have changed due to
a concurrent state transition. The parent `newstate` is called with
the original `nstate` unconditionally. This is a common pattern in
FreeBSD wireless drivers, but in a FullMAC driver where firmware
events drive state transitions asynchronously, it's more likely to
cause state machine confusion.

**File:** `cfg.c:brcmf_newstate`

---

## P3-7: NVRAM parser allocation margin undocumented

```c
buf = malloc(size + 8, M_BRCMFMAC, M_NOWAIT | M_ZERO);
```

The `+ 8` is the worst-case overhead: 1 byte NUL terminator for the
last line + 3 bytes padding + 4 bytes footer. The margin is exact
with no room for error. A comment explaining the budget would
prevent future regressions.

**File:** `pcie.c:brcmf_nvram_parse`
