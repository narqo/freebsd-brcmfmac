# Design Decisions

## License

**Decision**: ISC License.

**Rationale**:

The Linux brcmfmac driver is dual-licensed ISC/GPL-2.0. The driver spec
was produced by an AI agent that read the Linux source directly, making
this implementation a derivative work. ISC is the permissive option of
the two upstream licenses, compatible with FreeBSD in-tree inclusion,
and includes a no-warranty clause that disclaims liability for damages.

Copyright notices:
- `Copyright (c) 2010-2022 Broadcom Corporation` — upstream Linux driver
- `Copyright (c) brcmfmac-freebsd contributors` — this implementation

## Native FreeBSD vs LinuxKPI

**Decision**: Use native FreeBSD APIs instead of LinuxKPI.

**Rationale**:

- Removes dependency on `linuxkpi` and `linuxkpi_wlan` modules
- Simpler build setup (no `LINUXKPI_GENSRCS`, `LINUXKPI_INCLUDES`)
- Better integration with FreeBSD kernel conventions
- Easier to debug without Linux compatibility shim
- Eventually need net80211 integration anyway (not cfg80211)

**APIs used**:

| LinuxKPI | Native FreeBSD |
|----------|----------------|
| `pci_register_driver` | `DRIVER_MODULE` |
| `pcim_iomap` | `bus_alloc_resource_any` |
| `readl`/`writel` | `bus_space_read_4`/`bus_space_write_4` |
| `memcpy_toio` | `bus_space_write_region_1` |
| `pci_write_config_dword` | `pci_write_config(..., 4)` |
| `request_firmware` | `firmware_get` |
| `release_firmware` | `firmware_put` |
| `kzalloc`/`kfree` | `malloc`/`free` with `M_BRCMFMAC` |
| `msleep` | `pause_sbt` |
| `udelay` | `DELAY` |

## C/Zig split rationale

**Decision**: Use C for kernel interactions, Zig for pure logic only.

**Rationale**:

### Why not `@cImport` with kernel headers?

Zig's `@cImport` doesn't work reliably with FreeBSD kernel headers:

1. **Generated headers not in source tree** - vnode_if.h, device_if.h generated during build
2. **Implicit function declarations** - panic, printf, vsnprintf used without prototypes
3. **Complex include order dependencies** - headers assume specific ordering
4. **Bitfield structs** - Zig demotes bitfield structs to opaque (struct pcpu)

### Current approach

- **C code** (`src/main.c`, `src/pcie.c`): Kernel API calls, PCI operations, firmware loading
- **Zig code** (`src/brcmfmac.zig`): Pure functions like chip ID parsing, EROM enumeration

Functions exported from Zig use `extern` calling convention and are called from C.

## Core enumeration approach

**Decision**: Parse EROM (Enumeration ROM) at runtime to find core addresses.

**Rationale**:

BCM chips use a backplane with multiple cores. Core addresses vary by chip and revision.
The EROM at a chip-specific address contains descriptors for each core.

For BCM4350 (AXI backplane):
- EROM base read from ChipCommon offset 0xfc
- EROM entries are 32-bit descriptors
- Component Identifier (CI) entries specify core ID
- Address entries specify base addresses for core and wrapper

**Example from BCM4350**:
```
[13] 0x4bf83e01 - CI: core 0x83e (ARM CR4)
[16] 0x18002005 - Address: 0x18002000 (core base)
[24] 0x181020c5 - Address: 0x18102000 (wrapper base)
```

Wrapper base contains control registers (IOCTL, RESET_CTL) for core reset.

## BAR0 window mechanism

**Decision**: Use BAR0 window register to access different backplane addresses.

**Rationale**:

BAR0 is only 32KB but the backplane address space is 4GB. The window register at PCI config offset 0x80 selects which 4KB of backplane is visible through BAR0.

To read address `0x18102408`:
1. Write `0x18102000` to window register (4KB aligned)
2. Read BAR0 + `0x408` (offset within window)

**Gotcha**: Must flush writes to window register before reading.

## Firmware download approach

**Decision**: Implement minimal firmware download first, skip NVRAM initially.

**Rationale**:

The firmware binary contains everything needed to boot. NVRAM (configuration) can be added later.

Steps:
1. Halt ARM CR4 core (via wrapper IOCTL/RESET_CTL)
2. Copy firmware to TCM at ram_base
3. Clear shared RAM address (last 4 bytes)
4. Release ARM core with reset vector = ram_base
5. Poll shared RAM address until firmware writes it

**Current blocker**: Firmware not executing. Needs investigation.

## Memory allocation

**Decision**: Use FreeBSD malloc() with driver-specific malloc type.

**Rationale**:

- Zig's allocators (std.heap.*) use TLS internally → linker fails
- `MALLOC_DEFINE(M_BRCMFMAC, ...)` provides tracking and debugging

## Logging approach

**Decision**: Use kernel printf, avoid Zig std.log and std.debug.

**Rationale**:

- std.log and std.debug use TLS → linker fails
- Kernel printf works but needs careful declaration (see AGENTS.md for printf optimization issue)
- `brcmf_dbg()` wrapper function in C for Zig to call

## EROM parsing results (BCM4350)

Successfully parsed EROM at `0x1810d000`:

**ARM CR4 core**:
- Core ID: `0x3e` (from CI descriptor `0x4bf83e01`)
- Revision: 8
- Base: `0x18002000`
- Wrapper: `0x18102000`

**SOCRAM core**:
- Core ID: `0x1a` (from CI descriptor `0x4bf81a01`)
- Revision: 0
- Base: `0x18004000`
- Wrapper: `0x18104000`

## Firmware download init sequence (resolved)

The firmware boot failure was caused by missing initialization steps.
The working Linux driver does the following before firmware download:

1. **Watchdog reset** - ChipCommon watchdog register write resets the whole chip
2. **ASPM disable/restore** - around the watchdog reset
3. **Mailbox interrupt clear** - after chip reset
4. **set_passive** - `resetcore(arm, val, CPUHALT, CPUHALT)` + `coredisable(d11, ...)`
5. **Firmware copy** to TCM at ram_base
6. **NVRAM copy** to end of RAM (overlapping shared RAM address location)
7. **set_active** - write reset vector (first firmware word) to TCM[0], then `resetcore(arm, CPUHALT, 0, 0)`

Key differences from our original code:
- Missing watchdog reset entirely
- Using `ram_base` as reset vector instead of first firmware word
- Only 8-bit core IDs in EROM parser (need 12-bit DMP part numbers)
- Missing D11 core disable
- Missing PCIe core enumeration

## EROM parsing

**Decision**: Use proper DMP (Dotted Map Protocol) descriptor parsing.

The initial EROM parser used ad-hoc pattern matching on descriptor bytes.
This broke when looking for cores with IDs > 0xFF (D11=0x812, PCIE2=0x83c).

DMP descriptors use:
- `DMP_COMP_PARTNUM` bits[19:8] for 12-bit core ID (not 8-bit)
- Two-word component descriptors (CI + CIB)
- Explicit address descriptor types for slave ports vs wrapper ports
- Size type field to distinguish 4K/8K/descriptor-based sizes

## Firmware file selection (resolved)

Linux uses a revision bitmask table (`BRCMF_FW_ENTRY`) for firmware selection:
- BCM4350 rev 0-7 (mask `0x000000FF`): `brcmfmac4350c2-pcie.bin`
- BCM4350 rev 8+ (mask `0xFFFFFF00`): `brcmfmac4350-pcie.bin`

The original code used `chiprev >= 6` for the C2 variant, which was wrong.
Rev 5 (our hardware) got the base firmware, which doesn't boot on this chip.

## WPA2 supplicant approach

**Decision**: Host supplicant (wpa_supplicant). Firmware supplicant was tried
first but this firmware doesn't support it.

**Background**:

The firmware supplicant approach (`sup_wpa=1` + `BRCMF_C_SET_WSEC_PMK`) was
attempted first because the scan cache wasn't working (ieee80211_add_scan
crashed). Both `sup_wpa` and `SET_WSEC_PMK` return BCME_BADARG (-23) on
firmware 7.35.180.133. This firmware expects the host to handle the 4-way
handshake.

**Sequence** (working up to step 7):

1. `wpa_supplicant -Dbsd -iwlan0 -c/tmp/wpa.conf`
2. wpa_supplicant scans via net80211 → scan cache populated
3. wpa_supplicant finds matching BSS with RSN IE
4. wpa_supplicant triggers MLME associate → net80211 AUTH state
5. Driver sets wsec/wpa_auth, sup_wpa=0, wpaie, then joins via SET_SSID
6. Firmware associates, sends LINK event → link_task → RUN state
7. AP sends EAPOL frame 1/4 → delivered to wlan0 → wpa_supplicant
8. **BLOCKED**: wpa_supplicant sends frame 2/4, AP rejects (RSN IE mismatch)

## WPA2 4-way handshake: RSN IE mismatch (RESOLVED)

### Root cause

The firmware's RSN IE in the association request uses capabilities
`0x000c` (16 PTKSA replay counters). wpa_supplicant's RSN IE in EAPOL
frame 2/4 uses `0x0000`. The AP compares both and rejects the handshake.

The firmware always sets the WMM-style replay counter bits because the
Broadcom FullMAC firmware manages WMM internally.

wpa_supplicant sets these bits only when `sm->wmm_enabled == 1`
(`rsn_supp_capab()` in `src/rsn_supp/wpa_ie.c`):

```c
if (sm->wmm_enabled) {
    capab |= RSN_NUM_REPLAY_COUNTERS_16 << 2;  /* 0x000c */
}
```

`wmm_enabled` is set when the BSS has a WMM vendor IE (OUI 00:50:f2
type 2) in its scan entry (`wpa_supplicant.c:2117`).

### Fix

Inject a synthetic WMM IE into scan results for BSSes that have RSN
but no WMM IE. This makes wpa_supplicant detect WMM capability, set
`wmm_enabled=1`, and produce RSN capabilities `0x000c` — matching the
firmware's association request.

### What did NOT work

- `wpaie` iovar (raw, bsscfg-prefixed) — accepts the IE but causes
  `SET_SSID failed, status=1`. Corrupts firmware WPA state persistently.
- `vndr_ie` iovar with RSN IE — firmware ignores it, still uses its own.
- `bsscfg:wpaie` — same failure.
- `assoc_req_ies` readback — works after association, but too late to
  feed back to wpa_supplicant (no BSD driver mechanism for this).

## Scan implementation details

### escan lifecycle

swscan calls `scan_start` per channel. The driver starts ONE firmware escan
(all channels, `channel_num=0`) on the first call and ignores subsequent
calls until the escan completes. `scan_end` is a no-op — the firmware
controls scan timing.

The escan completion (bss_count=0) sets `scan_active=0` and enqueues
`scan_complete_task`, which delivers results to net80211 via
`ieee80211_add_scan` and calls `ieee80211_scan_done`.

### IE extraction from firmware scan results

The firmware's `brcmf_bss_info_le` struct is 117 bytes (`sizeof`), but
the firmware's actual struct appears to be 128 bytes. When `ie_offset=0`
and `ie_length=0` (common case), the IEs start at offset 128 from the
BSS info start. When `ie_length > 0`, the IEs are at `bi_len - ie_len`.

The 128-byte offset was determined empirically: at offset 117, there are
11 bytes of unknown data before the SSID IE (ID=0x00). The SSID IE at
offset 128 parses correctly and is followed by valid Rates, RSN, etc.

### BSSID dedup

Multiple escan events may report the same BSSID — some with IEs
(`ie_length > 0`) and some without. Without dedup, the entry without IEs
overwrites the one with IEs, losing RSN/HTCAP flags. The scan result
buffer tracks BSSIDs and refuses to overwrite an entry that has IEs with
one that doesn't.

### ISCAN_DISCARD

swscan's internal `ISCAN_DISCARD` flag (offset `sizeof(ieee80211_scan_state)`,
bit 0x02) causes `ieee80211_add_scan` to silently drop results. This flag
is set at scan start and cleared at first channel dwell. Since firmware
escan results arrive asynchronously (not tied to swscan's channel timing),
the driver clears this flag before each `ieee80211_add_scan` call.

## Interface down: synchronous disconnect and security clear

**Decision**: Send DISASSOC and clear `wsec`/`wpa_auth` in
`brcmf_parent` (the `ic_parent` callback), not in the deferred INIT
state transition.

**Problem**: `ifconfig down` triggers `ieee80211_new_state(INIT)`,
which is deferred via taskqueue. If `ifconfig up` + wpa_supplicant
start before the deferred INIT runs, the DISASSOC races with the new
SET_SSID. The AP receives auth → assoc → deauth (stale) and drops the
session.

Even when DISASSOC arrives first, stale encryption keys in the firmware
cause it to encrypt EAPOL frame 2/4. The AP can't decrypt it and deauths
after its handshake timeout (~1s).

**Fix**: `brcmf_parent` runs synchronously in the `ifconfig down` path
(before it returns). Sending DISASSOC + clearing security state here
guarantees they complete before the next `ifconfig up`.

The INIT handler's DISASSOC is retained as a safety net for state
transitions that don't go through `brcmf_parent` (e.g., VAP destroy).

## Direct-join and WPA networks

**Decision**: `brcmf_join_bss_direct` (the scan-complete auto-join
path) skips WPA networks.

**Rationale**: The direct-join path runs when `iv_roaming != MANUAL`
(before wpa_supplicant sets roaming to manual). Without a supplicant
managing the 4-way handshake, a WPA association succeeds at L2 but the
AP deauthenticates after its EAPOL timeout. This pollutes the AP's
session state and blocks subsequent association attempts.

## Test environment

- **Build host**: 192.168.20.82 (FreeBSD 15, Zig 0.16-dev)
- **Target**: 192.168.200.10 (SSH via jump host 192.168.20.82)
- **Hardware**: BCM4350c2 (PCI 0x14e4:0x43a3), firmware v7.35.180.133
- **AP**: Raspberry Pi (dc:a6:32:5b:98:ad), channel 1, hostapd
- **AP configs tested**:
  - "TestAP1": WPA2-PSK CCMP (AKM type 2)
  - "TestAP": WPA2-PSK-SHA256 CCMP (AKM type 6)
  - Passphrase: "SuperSecret!Test1"
- **Build/deploy**: `rsync` to build host → `make` → `scp` to target →
  `kldunload/kldload`
- **wpa.conf**: `/tmp/wpa_sha256.conf` on target (current):
  ```
  ctrl_interface=/var/run/wpa_supplicant
  network={
      ssid="TestAP"
      psk="SuperSecret!Test1"
      key_mgmt=WPA-PSK-SHA256
      proto=RSN
      pairwise=CCMP
  }
  ```

## D2H ring processing: single-owner via ISR taskqueue

**Decision**: All D2H ring processing runs exclusively in a dedicated
`brcmfmac_isr` taskqueue. No other context may call
`brcmf_msgbuf_process_d2h`.

**Problem**: The original design ran D2H processing in two places
concurrently:

1. The interrupt filter (`brcmf_pcie_intr`) — hard interrupt context
2. Polling loops in `brcmf_msgbuf_ioctl` and flowring create/delete
   wait paths — thread context

This caused two classes of crashes:

- **Socket buffer corruption (core.txt.3)**: `sbcut_internal` page
  fault at address 0x8. The filter handler delivered RX packets via
  `if_input` in hard interrupt context. Under heavy RX, TCP socket
  buffer accounting (`sb_ccc`) became corrupt — claimed 8688 bytes
  but the mbuf chain was empty.
- **Concurrent ring access**: The ioctl wait loop polled D2H rings
  while the filter handler could fire and process the same rings
  simultaneously. No locking protected ring pointer updates, so
  the same RX completion could be processed twice or ring state
  could be torn.

**Solution**: Split the interrupt into filter + taskqueue:

- `brcmf_pcie_isr_filter`: acks the mailbox interrupt, disables
  further interrupts, enqueues `isr_task`. Runs in hard IRQ; does
  no ring processing.
- `brcmf_pcie_isr_task`: runs in the `brcmfmac_isr` taskqueue at
  `PI_NET` priority. Processes all D2H rings (ctrl complete, TX
  complete, RX complete), then re-enables interrupts.
- Ioctl and flowring waits use `tsleep`/`wakeup` only. The ISR task
  processes the completion ring entry and calls `wakeup`. No polling.
- `brcmf_msgbuf_repost_rxbufs` removed — it wrote to the H2D RXPOST
  ring from `brcmf_link_task` (net80211 taskqueue), racing with the
  ISR task which reposts buffers during RX completion. The ISR task
  is now the sole writer to H2D RXPOST.

**Invariant**: `brcmf_msgbuf_process_d2h` is called from exactly one
place: `brcmf_pcie_isr_task`. All ring pointer updates, RX delivery,
ioctl completion wakeups, and flowring completion wakeups happen in
this single-threaded context.

## COM/node lock and firmware ioctls

**Problem**: `sta_newstate` (INIT from RUN) calls
`ieee80211_sta_leave` → `ieee80211_node_delucastkey` →
`ieee80211_crypto_delkey` → `brcmf_key_delete`. At this point both
the COM lock and the node table lock are held. `brcmf_key_delete`
calls a firmware ioctl which does `tsleep`. WITNESS panics:
`sleeping thread holds brcmfmac0_com_l` (core.txt.1) or
`sleeping thread holds brcmfmac0_node_` (core.txt.7).

The call chain:
```
ieee80211_newstate_cb           [COM lock held]
  brcmf_newstate                [drops COM, does fw work, re-acquires]
    sta_newstate                [COM held]
      ieee80211_sta_leave
        ieee80211_node_delucastkey  [acquires node lock]
          ieee80211_crypto_delkey
            brcmf_key_delete        [COM + node held → tsleep → panic]
```

**Fix**: `brcmf_key_set` and `brcmf_key_delete` dynamically check
and drop both COM and node locks before the firmware ioctl, then
re-acquire after. Uses `IEEE80211_IS_LOCKED` / `IEEE80211_NODE_IS_LOCKED`
to handle callers that may or may not hold these locks.

Verified: interface cycling (which triggers `sta_newstate` INIT →
key delete) no longer panics.

## Firmware liveness and fw_dead flag

**Problem**: Firmware can become unresponsive (ioctl timeouts, BAR0
reads return 0xffffffff). When this happens during detach, each
ioctl waits the full 2s timeout, making kldunload hang for tens of
seconds. If the chip is physically gone (PCIe error), no amount of
retrying will recover.

**Design**: A `fw_dead` flag in softc. Once set, all firmware
communication is short-circuited:
- `brcmf_msgbuf_ioctl` returns `ENXIO` immediately
- `brcmf_msgbuf_tx` drops packets immediately
- Flowring create/delete waits bail out

The flag is set by:
1. Any ioctl timeout (first timeout marks the device dead)
2. The watchdog callout (5s interval), which reads BAR0 mailbox
   register — `0xffffffff` means PCIe link is down

The watchdog also wakes any threads sleeping on ioctl or flowring
completion, so they don't have to wait for their individual timeouts.

## IOCTL serialization mutex

**Problem**: The firmware IOCTL protocol is single-threaded
(one outstanding request, shared `ioctlbuf`). Multiple kernel
contexts can call firmware ioctls concurrently: `ic_tq` tasks
(`brcmf_parent`, `brcmf_link_task`, `brcmf_newstate`), sysctl
handler (`brcmf_set_pmk`), and `brcmf_key_set`/`brcmf_key_delete`
(which drop COM+node locks before the ioctl).

**Fix**: `ioctl_mtx` (MTX_DEF) serializes all calls to
`brcmf_msgbuf_ioctl`. The mutex is held for the entire
request-response cycle. `msleep` atomically releases it while
waiting for the firmware response, allowing other threads to
queue up without corrupting the shared ioctl buffer.

**fw_dead threshold**: A single ioctl timeout does not mark the
firmware dead — transient timeouts occur during firmware state
transitions (e.g., after DISASSOC). Three consecutive timeouts
set `fw_dead`, which permanently short-circuits all firmware
communication. The watchdog callout also sets `fw_dead` on
BAR0 read failure (PCIe link down).

## D2H ring wraparound bug

**Problem**: The available-entries calculation in D2H completion
rings only counted entries from `r_ptr` to end-of-buffer when
`w_ptr < r_ptr` (wraparound case). Entries from 0 to `w_ptr` were
missed until the next ISR invocation. Under heavy traffic, TX
completions in the wrapped region were never processed, the TX
buffer ring filled up, and all TX stalled permanently.

**Fix**: `avail = (ring->depth - ring->r_ptr) + ring->w_ptr` for
the wraparound case. Applied to all three D2H rings (ctrl, TX, RX).

Additionally, `brcmf_msgbuf_process_d2h` now loops up to 5 times,
re-checking the RX completion ring w_ptr after each pass. This
catches completions that arrive during processing, preventing stalls
when the firmware writes new entries between the initial w_ptr read
and the interrupt re-enable.
