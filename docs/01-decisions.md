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

## C implementation rationale

**Decision**: Use C for both kernel interactions and driver logic.

**Rationale**:

FreeBSD kernel headers and kbuild-style generated interfaces are a natural fit for C.

Historical context: tried building the driver in Zig, and a mix of Zig and C.
Zig's interoperability with C (Zig 0.16-dev) din't work with kernel linker.

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

**Decision**: Firmware download is driver-managed on both PCIe and SDIO.
Use the firmware binary together with NVRAM; for CYW43455 also load the
CLM blob after firmware boot.

**Rationale**:

The firmware image is copied into RAM by the driver, then started from the
chip-specific reset vector. NVRAM provides board configuration. On CYW43455,
scan also depends on a successful CLM blob download.

Steps:
1. Halt ARM CR4 core (via wrapper IOCTL/RESET_CTL)
2. Copy firmware to RAM at `ram_base`
3. Clear shared RAM address (last 4 bytes)
4. Release ARM core with reset vector = `ram_base`
5. Poll shared RAM address until firmware writes it
6. Upload NVRAM
7. Upload CLM blob where required

## Memory allocation

**Decision**: Use FreeBSD malloc() with driver-specific malloc type.

**Rationale**:

- `MALLOC_DEFINE(M_BRCMFMAC, ...)` provides tracking and debugging

## Logging approach

**Decision**: Use `device_printf` for errors and one-time boot identity
messages. Use `BRCMF_DBG(sc, ...)` macro for verbose/trace output,
gated on `sc->debug >= 2`.

**Rationale**:

- Kernel printf works but needs careful declaration (see AGENTS.md
  for printf optimization issue)
- Default boot output is minimal: chip ID, firmware version, MAC
  address. EROM enumeration, ring info, buffer posting counts, and
  firmware download trace are suppressed unless `sysctl
  dev.brcmfmac.0.debug=2`.

**Categories**:

| Category | Function | When |
|----------|----------|------|
| Errors | `device_printf` | Always |
| Boot identity (chip, firmware, MAC) | `device_printf` | Always |
| net80211 capabilities (rates, MCS) | `ieee80211_announce` | `bootverbose` |
| Verbose/trace (EROM, rings, buffers, flowrings) | `BRCMF_DBG` | `debug >= 2` or `bootverbose` |

`BRCMF_DBG` is defined in `brcmfmac.h`. It emits when either the
per-device `debug` sysctl is >= 2 or the kernel-global `bootverbose`
flag is set. The `debug` sysctl is registered in
`security.c:brcmf_security_sysctl_init`.

`bootverbose` is set at boot via `boot -v` or `boot_verbose="YES"`
in `/boot/loader.conf`. FreeBSD WiFi drivers (`ath`, `iwm`, `rtwn`)
use it to gate `ieee80211_announce`. It covers attach-time output
that the per-device sysctl can't reach (debug defaults to 0 and
can't be set before the module loads).

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

## EROM parsing

**Decision**: Use proper DMP (Dotted Map Protocol) descriptor parsing.

The initial EROM parser used ad-hoc pattern matching on descriptor bytes.
This broke when looking for cores with IDs > 0xFF (D11=0x812, PCIE2=0x83c).

DMP descriptors use:
- `DMP_COMP_PARTNUM` bits[19:8] for 12-bit core ID (not 8-bit)
- Two-word component descriptors (CI + CIB)
- Explicit address descriptor types for slave ports vs wrapper ports
- Size type field to distinguish 4K/8K/descriptor-based sizes

## Firmware file selection

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

## D2H ring processing: atomic exclusion

**Decision**: `brcmf_msgbuf_process_d2h` uses an atomic try-lock
(`d2h_processing`) to ensure at most one caller processes rings at
a time. Three contexts may call it:

1. `brcmf_pcie_isr_task` — ISR taskqueue (primary)
2. `brcmf_watchdog` — 10ms callout (catches missed interrupts)
3. `brcmf_msgbuf_ioctl` — ioctl wait loop (when completion not yet seen)

**History**: M16 moved all D2H processing to the ISR taskqueue
exclusively, fixing the concurrent-access crashes (core.txt.3).
M16.6 re-introduced polling from the watchdog and ioctl paths
because the ISR taskqueue thread stops executing under bhyve after
~10-15 minutes. The polling is necessary for reliability, but
without synchronization it re-introduced the original race.

**Solution**: `atomic_cmpset_int(&sc->d2h_processing, 0, 1)` at
entry; `atomic_store_rel_int(&sc->d2h_processing, 0)` at exit.
If another context is already processing, the caller returns
immediately — the active processor will drain all pending work.
This is safe in callout context (no sleeping) and eliminates
double-processing of ring entries.

## CLM blob requirement (CYW/Cypress firmware)

**Decision**: Download CLM blob before `brcmf_cfg_attach` on SDIO.

**Rationale**:

CYW firmware 7.45.265 (BCM43455) returns `BCME_UNSUPPORTED (-4)` for
both `escan` iovar and `C_SCAN` (cmd=50) without a CLM blob loaded.
The firmware has no built-in channel/regulatory data — CLM is mandatory
for any scan or association.

The older BCM4350 firmware (7.35.180.133) works without CLM because it
has embedded channel data. The Linux driver logs "no clm_blob available,
device may have limited channels" and continues, but on CYW firmwares
"limited" means zero channels.

CLM blob source: `cypress/cyfmac43455-sdio.clm_blob` from
linux-firmware, placed at `/boot/firmware/brcmfmac43455-sdio.clm_blob`.
Downloaded via `clmload` iovar in 1400-byte chunks.

## BSS info IE extraction across firmware versions

**Decision**: Find IEs by searching for the SSID IE in raw BSS data,
not by trusting the `ie_offset` / `ie_length` fields.

**Rationale**:

The `brcmf_bss_info_le` struct defined in the public header is 128
bytes. The firmware's internal struct varies by version:

- 7.35.180.133 (BCM4350): 128-byte header, `ie_offset=0, ie_length=0`
- 7.45.265 (CYW43455): 512-byte header, `ie_offset=1, ie_length=1`

On CYW firmware, the `ie_offset` and `ie_length` fields at bytes
116/120 of the public struct are overwritten by extended fields in
the firmware's larger struct. The values read (1/1) are garbage.

The driver searches for tag 0x00 (SSID IE) matching the SSID from
the fixed header to find the actual IE boundary. Falls back to
`ie_offset` if valid, then to offset 128 for legacy firmware.
See `spec/A2-structures.md` for details.

## SDIO RX poll design

**Decision**: 50ms callout → taskqueue_thread task, 16 frames/tick max,
atomic `sdpcm_rx_busy` flag for mutual exclusion with ioctl path.

**Rationale**:

The Arasan SDHCI on RPi4 cannot sustain rapid F2 reads. A 20ms poll
caused hard hangs. 50ms is stable. The taskqueue task (not callout
context) is required because SDIO I/O sleeps in the CAM/sdiob stack.

Holding `ioctl_mtx` across SDIO reads panics with `sleeping thread
holds brcmfmac_ioctl` (WITNESS). Using an atomic flag instead avoids
the mutex-across-sleep issue while preventing concurrent F2 FIFO reads
that would interleave partial frames.

The ioctl poll loop handles events/data inline during its 3s timeout.
The RX task picks up frames between ioctls. Both paths ack
`I_HMB_FRAME_IND` in the SDIO core intstatus register — without
ack the firmware stops sending events.
