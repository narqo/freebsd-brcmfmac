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

The EROM scanner uses `safety` counters of 256 in nested loops.
If the EROM is corrupt, it spins for up to 65536 backplane reads
(each going through the BAR0 window register) before returning.
This runs during attach, so it blocks the boot path.

**File:** `core.c:brcmf_erom_get_regaddr`

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

Deleted `src/pcie.h`. Stale leftover, never included, would not
compile.

### P3-3: `ETHER_ADDR_LEN` redefined — FIXED

Removed redundant `#define ETHER_ADDR_LEN 6` from `brcmfmac.h`.
Already provided by `<net/ethernet.h>`.

### P3-7: NVRAM parser `+8` undocumented — FIXED

Added comment: `/* +8: 1 trailing NUL + 3 pad-to-4 + 4 length footer */`

---

## Spec review (13 Mar 2026, updated 14 Mar 2026)

Compared spec (`spec/`) against implementation. No critical
mismatches — driver is architecturally correct. The following are
gaps where the driver deviates from the behavior described in the
spec. All are non-blocking; the driver works end-to-end.

### SR-1: Missing `brcmf_c_preinit_dcmds` initialization commands — PARTIAL

Added to `brcmf_cfg_attach` dongle init:
- `BRCMF_C_SET_SCAN_CHANNEL_TIME` (cmd 185, 40ms)
- `BRCMF_C_SET_SCAN_UNASSOC_TIME` (cmd 187, 40ms)
- `BRCMF_C_SET_SCAN_PASSIVE_TIME` (cmd 258, 120ms)
- `bcn_timeout` iovar (4)

Deferred (low value for current target):
- `BRCMF_C_SET_FAKEFRAG` — frameburst, throughput optimization
- `join_pref` iovar — RSSI-based join preference
- `txbf` iovar — TX beamforming
- CLM blob download — needs chunked download impl

**Severity:** P3

### SR-2: MPC polarity differs from spec

Spec: `mpc=1` during preinit. Driver: `mpc=0` in two places (after
firmware download and in `brcmf_parent`). Intentional per M11
latency optimization — keeps radio on during idle to avoid ~7ms
wake penalty. Document as deliberate deviation.

**Severity:** P3 (document only)

### SR-3: Uses `BRCMF_C_SET_SSID` instead of `"join"` bsscfg iovar — TESTED, KEPT

Tested "join" iovar on firmware v7.35.180.133: the iovar returns
success but the firmware does not perform the association (stays
in SCANNING). Same pattern as "wpaie" and "sup_wpa" — this
firmware silently ignores certain IOVARs. Keeping SET_SSID as
the sole connect path.

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

### SR-6: `brcmf_assoc_params_le` has fixed `chanspec_list[1]` — FIXED

Changed `chanspec_list[1]` to `chanspec_list[]` (flexible array).
Inlined BSSID and chanspec_num fields directly into
`brcmf_join_params` since it never passes chanspec data.

**Severity:** P3

### SR-7: D11AC chanspec format hardcoded — FIXED

Added `io_type` field to softc, queried via `C_GET_VERSION` during
init. Both D11N and D11AC encode/decode paths implemented. Callers
(`brcmf_chanspec_to_channel`, `brcmf_channel_to_chanspec`,
`brcmf_chanspec_get_bw_sb`) dispatch based on `sc->io_type`.

**Severity:** P3

### SR-8: No power management / deep sleep handling

Spec describes D3/D0 transitions, deep sleep request/ack, and
`BRCMF_D2H_DEV_DS_ENTER_REQ` / `BRCMF_H2D_HOST_DS_ACK` mailbox
protocol. Driver only checks `BRCMF_D2H_DEV_FWHALT`. PM_OFF is
set explicitly. Not needed for a desktop/VM use case but required
for laptop power management.

**Severity:** P3

### SR-9: Missing C_DOWN before dongle init configuration — FIXED

Added `C_DOWN` → `SET_INFRA=1` before country setup, then `C_UP`
after country, in `brcmf_cfg_attach`. Matches spec dongle init
sequence.

**Severity:** P3

### SR-10: IOCTL request DMA buffer oversized — FIXED

Split into two buffers:
- `ioctl_reqbuf`: 1518-byte DMA-coherent buffer for request
  payload (firmware reads from this via DMA address)
- `ioctl_respbuf`: 8192-byte `malloc` buffer for response
  staging (copied from pre-posted DMA response buffer)

Saves ~6.5 KB of DMA-coherent memory. Response staging doesn't
need DMA since it's a host-side copy from the real DMA response
buffers (`ioctlresp_buf[]`).

**Severity:** P3

### SR-11: RX data_offset fallback to rx_dataoffset missing — FIXED

Added fallback: if per-packet `data_offset` is zero, use
`sc->shared.rx_dataoffset` from shared RAM.

**Severity:** P3

### SR-12: Event data not stripped by rx_dataoffset — FIXED

Event processing now applies `sc->shared.rx_dataoffset` to the
event buffer pointer before parsing. Escan data pointer also
made relative to the event struct rather than buffer base.

**Severity:** P3

### SR-13: BAR0 window write not verified — FIXED

Added `brcmf_pcie_set_window` helper that reads back the PCI
config register after write and retries once on mismatch.
Used by `brcmf_bp_read32`, `brcmf_bp_write32`, and
`brcmf_pcie_select_core`.

**Severity:** P2

### SR-14: Core disable skips REJECT step — DEFERRED

The full reject handshake requires writing REJECT to the slave
wrapper port (`0x0c00` series registers) and polling its status
— registers not currently mapped. An attempt to use `BCMA_RESET_ST`
(0x0804) was incorrect (wrong register). Reverted to simple
reset-without-reject, which works for CR4 cores during firmware
download because the ARM is halted and no transactions are in
flight. Proper reject handshake deferred to multi-chip support.

**Severity:** P3

### SR-15: No feature detection — FIXED

Added `cap` iovar query during init. Detects `mbss`, `p2p`,
`sae` capabilities from capability string. Probes `sup_wpa`
and `mfp` IOVARs. Results stored in `feat_*` fields in softc.
Not yet used to gate behavior (hardcoded paths remain correct
for BCM4350) but available for multi-device support.

**Severity:** P3

### SR-16: No band preference in dongle init — FIXED

Added roam trigger (-75 dBm) and roam delta (20 dB) to dongle
init sequence. Band preference is implicitly handled by the
RSSI-based join_pref (SR-1).

**Severity:** P3

### SR-17: C_UP / C_DOWN send unnecessary payload — FIXED

Changed `brcmf_fil_bss_up` and `brcmf_fil_bss_down` to send
NULL/0 payload.

**Severity:** P3

### SR-18: wsec_key struct uses __packed (160 bytes vs spec's 164) — FIXED

Removed `__packed` from `brcmf_wsec_key`. Natural alignment
matches spec's 164-byte layout.

**Severity:** P3

### SR-19: Event registration timing — FIXED

Moved `brcmf_setup_events` (event_msgs push) to right after
`C_UP` in dongle init, before any init commands that might
trigger events.

**Severity:** P3

### SR-20: DISASSOC (11) event not in spec — VERIFIED

Driver registers handler for event 11 (DISASSOC) and requests
it via `event_msgs`. The spec only lists DISASSOC_IND (12).
Tested: event 11 is registered in the firmware event mask.
If firmware never sends it, the handler is a no-op. Keeping
it is more defensive than removing it.

**Severity:** P3 (spec gap, not code bug)

## Additional review (30 Mar 2026)

### P1-6: `brcmf_msgbuf_process_rx_complete` trusts `data_offset`

```c
if ((flags & BRCMF_MSGBUF_PKT_FLAGS_FRAME_MASK) ==
    BRCMF_MSGBUF_PKT_FLAGS_FRAME_802_3) {
	if (data_len > 0 && data_len <= BRCMF_MSGBUF_MAX_PKT_SIZE) {
		brcmf_rx_deliver(sc,
		    (char *)cb->buf + data_offset, data_len);
	}
}
```

Only `data_len` is bounded. `data_offset` comes from firmware and can
point past the 2048-byte RX DMA buffer. A bogus completion can make the
kernel read beyond `cb->buf` and copy unrelated memory into an mbuf.
Need to reject completions where `data_offset > BRCMF_MSGBUF_MAX_PKT_SIZE`
or `data_offset + data_len > BRCMF_MSGBUF_MAX_PKT_SIZE`.

**File:** `src/msgbuf.c:brcmf_msgbuf_process_rx_complete`

---

### P1-7: `E_SET_SSID` success path can self-deadlock on SDIO

`brcmf_link_event()` calls `brcmf_link_task(sc, 0)` directly on
`BRCMF_E_SET_SSID` success. On SDIO, events are processed from
`brcmf_sdpcm_ioctl()` and `brcmf_sdpcm_rx_task()` while `sdio_lock`
is held. `brcmf_link_task()` then sends the `allmulti` iovar, which
re-enters `brcmf_sdpcm_ioctl()` and tries to take `sdio_lock` again.

The common event order (`E_LINK` before `E_SET_SSID`) hides this, but
if firmware reports `E_SET_SSID` first the driver deadlocks itself.

**Files:** `src/cfg.c:brcmf_link_event`, `src/sdpcm.c:brcmf_sdpcm_ioctl`, `src/sdpcm.c:brcmf_sdpcm_rx_task`

---

### P2-10: `brcmf_newstate` AUTH path uses `vap->iv_bss` without lock or ref

`brcmf_newstate()` drops `IEEE80211_LOCK()` at entry, then in the AUTH
case does:

```c
struct ieee80211_node *ni = vap->iv_bss;
...
brcmf_join_bss(sc, ni);
```

`brcmf_join_bss()` reads `ni->ni_chan`, `ni->ni_bssid`, and
`ni->ni_essid`, and sleeps. net80211 may replace or free `iv_bss`
concurrently. This is the same lifetime class that was fixed earlier in
`brcmf_link_task`; the AUTH path still has it.

**File:** `src/cfg.c:brcmf_newstate`

---

### P2-11: SDIO TX-credit recovery discards arbitrary received frames

When `brcmf_sdpcm_send()` returns `ENOBUFS`, both
`brcmf_sdpcm_ioctl()` and `brcmf_sdpcm_tx_task()` call
`brcmf_sdpcm_recv()` only to "drain RX to get TX credits" and then
ignore the returned channel and payload.

Any received event, control reply, or data frame consumed there is
silently dropped. This is worst in `brcmf_sdpcm_tx_task()`: upload-side
flow control can eat inbound data and association events. In the ioctl
path it can also discard unrelated firmware events during long control
sequences.

**Files:** `src/sdpcm.c:brcmf_sdpcm_ioctl`, `src/sdpcm.c:brcmf_sdpcm_tx_task`

---

### P2-12: SDIO attach failure leaks taskqueue, mutexes, and lock objects

`brcmf_sdio_bus_attach()` initializes `ioctl_mtx` and
`brcmf_sdpcm_init()` before the risky attach steps. On failure it only
stops polling and detaches the chip:

```c
fail:
	brcmf_sdpcm_stop_poll(sc);
	brcmf_sdio_detach(sc);
	return (error);
```

It does not call `sc->bus_ops->cleanup(sc)` and does not destroy
`ioctl_mtx`. That leaks the SDPCM taskqueue, queued TX state, and
mutexes on attach failure.

Separately, normal detach never calls `sx_destroy(&sc->sdio_lock)`.
The sx is initialized in `brcmf_sdpcm_init()` and survives every
unload.

**Files:** `src/main.c:brcmf_sdio_bus_attach`, `src/sdpcm.c:brcmf_sdpcm_init`, `src/sdpcm.c:brcmf_sdpcm_cleanup`

---

### P2-13: AUTH-time `wsec` derivation still misconfigures non-WPA2 ciphers

The AUTH path derives `wsec` from `vap->iv_flags` like this:

- WPA2 -> `AES_ENABLED`
- WPA1 -> `TKIP_ENABLED`
- any `IEEE80211_F_PRIVACY` -> `|= AES_ENABLED`

`IEEE80211_F_PRIVACY` is set for WEP and WPA1 as well, so:

- WEP becomes `AES_ENABLED`
- WPA1/TKIP becomes `TKIP_ENABLED | AES_ENABLED`

The earlier fix in `brcmf_detect_security()` only corrected scan-side
classification. The association path still advertises the wrong cipher
suite to firmware for anything except WPA2-CCMP.

**File:** `src/cfg.c:brcmf_newstate`
