# Code Review

Review date: 28 Feb 2026. Focus: correctness and security.

## Severity levels

- **P1** — can cause kernel panic, data corruption, or security breach
- **P2** — incorrect behavior, resource leak, or latent bug
- **P3** — style, cleanup, or hardening

---

## P3-2: Duplicate macro definitions

`BRCMF_RING_MEM_BASE_ADDR_OFFSET`, `BRCMF_RING_MAX_ITEM_OFFSET`,
`BRCMF_RING_LEN_ITEMS_OFFSET`, and `BRCMF_RING_MEM_SZ` are defined
in both `pcie.c` and `msgbuf.c`.

Event codes `BRCMF_E_SET_SSID`, `BRCMF_E_DEAUTH`, etc., are defined
in both `cfg.h` and `msgbuf.c`.

**Fix:** Move shared definitions to a single header.

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

## Addressed

### P1-1: Concurrent D2H ring processing from three contexts — FIXED

`brcmf_msgbuf_process_d2h` is called from three contexts (ISR
taskqueue, watchdog callout, ioctl wait loop). All three callers
are necessary — the ISR taskqueue stops executing under bhyve, so
the watchdog and ioctl paths provide fallback D2H processing.

**Fix:** Added `atomic_cmpset_int` try-lock (`d2h_processing` flag
in softc) at entry, `atomic_store_rel_int` at exit. If another
context is already processing, the caller returns immediately.
Updated `01-decisions.md` to document the new invariant.

**Tested:** 1000-packet flood ping 0% loss, TX counters balanced
(1111/1111), interface cycling stable, no panics.

### P1-2: IOCTL buffer race between preparation and submission — FIXED

The fwil layer wrote to the shared `sc->ioctlbuf` DMA buffer before
`brcmf_msgbuf_ioctl` acquired `ioctl_mtx`. Two concurrent callers
could corrupt each other's request data.

**Fix:** Eliminated all direct `sc->ioctlbuf` access from fwil.c.
Iovar functions assemble name+data in a stack buffer (512 bytes),
then pass it to `brcmf_msgbuf_ioctl`. Command functions pass the
caller's buffer directly. `brcmf_msgbuf_tx_ioctl` copies into
`ioctlbuf` under the lock; the response path copies out under the
lock. No code outside msgbuf.c touches `ioctlbuf` anymore.

Also fixed two callers that read `ioctlbuf` after the ioctl returned
(cfg.c `cur_etheraddr`, pcie.c `ver`) — they now pass proper output
buffers.

**Tested:** Firmware version prints correctly, MAC address read works,
WPA2 association + 1000-packet flood ping 0% loss, PM sysctl read
works.

### P1-4: PSK readable by unprivileged local users — FIXED

Read handler returned the plaintext PSK.

**Fix:** Read path now returns empty string. Removed the `memcpy`
that populated the sysctl read buffer from `sc->psk`. Write path
unchanged. Also removed dead `brcmf_set_pmk` function (firmware
supplicant approach doesn't work on this firmware; see
`01-decisions.md` WPA2 supplicant section).

**Tested:** `sysctl dev.brcmfmac.0.psk` returns empty. Write +
validation still works. WPA2 association unaffected.

### P1-3: TX pktid slot overwrite when ring is full — DECLINED

The `txbuf[pktid % 256].m != NULL` check prevents slot overwrite.
`brcmf_msgbuf_tx` returns `ENOBUFS` to the caller, which is the
standard backpressure signal. The race concern (paragraph 2) is
resolved by P1-1's atomic guard — TX submit and TX complete no
longer run concurrently. `IFF_DRV_OACTIVE` would be a minor
optimization, not a correctness fix.

### P1-5: BAR0 window register unserialized across CPUs — DECLINED

All post-attach callers of `brcmf_pcie_select_core` select the
same core (`sc->pciecore`). Two CPUs writing the same value to
the PCI config BAR0 window register is benign. The callers that
select other cores (`brcmf_bp_read32`/`brcmf_bp_write32`) run
only during attach (single-threaded).

### P2-2: `brcmf_vap_delete` drains scan tasks after `vap_detach` — FIXED

Scan tasks dereference `ss->ss_vap`, which is freed by
`ieee80211_vap_detach`. Reordered: drain scan tasks first,
then detach.

**Tested:** Two VAP create/destroy cycles with wpa_supplicant,
no crash. Reconnect after recreate works.

### P2-3: `brcmf_msgbuf_init_flowring` leaks on partial failure — FIXED

Three failure paths (ring_reserve ENOBUFS, create timeout, create
status != 0) leaked the DMA buffer and ring struct because
`sc->flowring` was set before the create request.

**Fix:** Moved `sc->flowring = ring` to after successful completion.
All failure paths goto a common `fail` label that frees DMA buffer
and ring struct. `brcmf_msgbuf_delete_flowring` sees `NULL` and
is a no-op.

**Tested:** Association + traffic (flowring create happy path),
interface cycling (flowring delete + recreate). No crash, no leak.

### P2-4: `brcmf_link_task` accesses `vap->iv_bss` without lock — FIXED

`iv_bss` can be swapped by net80211 (`ieee80211_sta_join`) on
a different thread. Reading and writing `ni->ni_*` fields without
COM lock is a use-after-free risk.

**Fix:** Wrapped the `iv_bss` access block (BSSID, channel, HT/VHT
caps, ESSID writes, plus `ic_curchan`/`ic_bsschan`) in
`IEEE80211_LOCK`/`IEEE80211_UNLOCK`. Sleeping calls
(`ieee80211_new_state`, flowring ops, allmulti iovar) remain outside
the lock.

**Tested:** Association, DHCP, ping, interface cycling — all pass.

### P2-5: `brcmf_detect_security` misidentifies WEP as WPA2 — FIXED

PRIVACY capability bit was mapped to WPA2-PSK/AES. The bit only
means "encryption required" — distinguishing WEP from WPA requires
RSN/WPA IE parsing.

**Fix:** Return `WEP_ENABLED` (not `AES_ENABLED`) for PRIVACY bit,
and `WPA_AUTH_DISABLED` always (no IE parsing). Updated caller
`brcmf_join_bss_direct` to reject `wsec != WSEC_NONE` in addition
to `wpa_auth != WPA_AUTH_DISABLED`, so encrypted networks are
skipped on the direct-join path.

**Tested:** WPA2 association via wpa_supplicant unaffected (uses
separate security setup path).

### P2-8: `brcmf_scan_complete_task` accesses VAP fields without COM lock — FIXED

`iv_roaming`, `iv_des_nssid`, `iv_des_ssid`, `iv_des_bssid` read
without COM lock in the direct-join decision block.

**Fix:** Snapshot all VAP fields under `IEEE80211_LOCK`, then use
local copies for matching. `brcmf_join_bss_direct` and
`ieee80211_scan_done` remain outside the lock (both sleep).

**Tested:** WPA2 association + DHCP + ping pass.

### P2-1: Scan result buffer TOCTOU between ISR and scan task — DECLINED

The race is real (`brcmf_escan_result` on `isr_tq`,
`brcmf_scan_complete_task` on `taskqueue_thread`), but the worst
outcome is a garbled scan result entry — no crash, no kernel memory
corruption. Entries are self-contained value types (no pointers into
shared memory). A proper fix requires a mutex around all
`scan_results` access including the hot ISR path, or a double-buffer
swap. The complexity isn't justified by the impact.

### P2-6: RX path copies every packet — DECLINED

Performance optimization. Requires redesigning the RX buffer
lifecycle (`m_extadd` with deferred repost). Not a correctness
issue.

### P2-7: No DMA sync before H2D ring writes — DECLINED

Rings are allocated with `BUS_DMA_COHERENT`. On x86 (the only
target), `bus_dmamap_sync` is a no-op. Would matter for ARM ports
but this driver targets BCM4350 on amd64 only.

### P2-9: Event datalen bounds check — DECLINED

The reviewer acknowledges "defense-in-depth rather than exploitable
today." The escan parser validates `buflen` and `bi_len` internally.
The existing bounds check prevents reading past the event buffer.

### P3-1: Dead header file `pcie.h` — FIXED

Deleted `src/pcie.h`. LinuxKPI leftover, never included, would not
compile.

### P3-3: `ETHER_ADDR_LEN` redefined — FIXED

Removed redundant `#define ETHER_ADDR_LEN 6` from `brcmfmac.h`.
Already provided by `<net/ethernet.h>`.

### P3-7: NVRAM parser `+8` undocumented — FIXED

Added comment: `/* +8: 1 trailing NUL + 3 pad-to-4 + 4 length footer */`

---

## Spec review (11 Mar 2026)

Compared new spec (`spec/`) against implementation. No critical
mismatches — driver is architecturally correct. The following are
minor gaps where the driver deviates from the Linux driver's
behavior described in the spec. All are non-blocking; the driver
works end-to-end.

### SR-1: Missing `brcmf_c_preinit_dcmds` initialization commands

The spec lists several init commands sent in `brcmf_c_preinit_dcmds()`
and `brcmf_config_dongle()` that the driver skips:

- `BRCMF_C_SET_SCAN_CHANNEL_TIME` (cmd 185, 40ms)
- `BRCMF_C_SET_SCAN_UNASSOC_TIME` (cmd 187, 40ms)
- `BRCMF_C_SET_SCAN_PASSIVE_TIME` (cmd 258, 120ms)
- `BRCMF_C_SET_FAKEFRAG` (cmd 219, val 1) — frameburst
- `bcn_timeout` iovar
- `join_pref` iovar (RSSI-based join preference)
- `txbf` iovar (TX beamforming)
- CLM blob download

Firmware defaults apply. `FAKEFRAG` and `txbf` could improve
throughput. `bcn_timeout` could improve link-loss detection speed.
CLM blob would enable proper regulatory enforcement (currently
using `country DE` + `SKU_DEBUG`).

**Severity:** P3

### SR-2: MPC polarity differs from spec

Spec: `mpc=1` during preinit. Driver: `mpc=0` in two places (after
firmware download and in `brcmf_parent`). Intentional per M11
latency optimization — keeps radio on during idle to avoid ~7ms
wake penalty. Document as deliberate deviation.

**Severity:** P3 (document only)

### SR-3: Uses `BRCMF_C_SET_SSID` instead of `"join"` bsscfg iovar

The spec's primary connect path uses the `"join"` bsscfg iovar
(`brcmf_ext_join_params_le`) with embedded scan parameters,
falling back to `BRCMF_C_SET_SSID`. The driver always uses
`BRCMF_C_SET_SSID` directly. Both achieve the same firmware
result. The `"join"` iovar would let the firmware do a targeted
scan-then-connect in one step.

**Severity:** P3

### SR-4: Single flow ring and fixed TX pool

Spec: per-TID per-peer flow rings, 2048 TX pktids, bitmap-based
TX worker. Driver: one flow ring, 256 TX slots, synchronous submit.
Adequate for single-STA single-AP. Limits throughput under heavy
TX load (TX drops when ring is full). Multi-flow support would be
needed for AP mode or multi-peer scenarios.

**Severity:** P3

### SR-5: No AMPDU RX reorder

Spec describes host-side AMPDU RX reorder via `brcmf_proto_rxreorder`.
Driver does not implement it. Firmware handles AMPDU internally for
FullMAC, so reorder events should not arrive. If they do, frames
would be delivered out of order.

**Severity:** P3

### SR-6: `brcmf_assoc_params_le` has fixed `chanspec_list[1]`

Defined with `chanspec_list[1]` instead of a flexible array. Sends
2 extra zero bytes in `BRCMF_C_SET_SSID` when `chanspec_num=0`.
Firmware ignores the extra bytes. Minor struct sizing waste.

**Severity:** P3

### SR-7: D11AC chanspec format hardcoded

Spec selects D11N vs D11AC format at runtime via `BRCMF_C_GET_VERSION`.
Driver hardcodes D11AC. Correct for BCM4350 but would break on
older chips using D11N.

**Severity:** P3

### SR-8: No power management / deep sleep handling

Spec describes D3/D0 transitions, deep sleep request/ack, and
`BRCMF_D2H_DEV_DS_ENTER_REQ` / `BRCMF_H2D_HOST_DS_ACK` mailbox
protocol. Driver only checks `BRCMF_D2H_DEV_FWHALT`. PM_OFF is
set explicitly. Not needed for a desktop/VM use case but required
for laptop power management.

**Severity:** P3
