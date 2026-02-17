# Design Decisions

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

**Scan cache crash**: Caused by `sp->tstamp` being NULL. The
`ieee80211_scanparams.tstamp` field is a pointer, and `sta_add()` in
ieee80211_scan_sta.c dereferences it unconditionally. Fixed by providing
a zero-filled 8-byte buffer.

**IE offset bug**: Firmware reports `ie_offset=0` in `brcmf_bss_info_le`.
Our initial fallback used `sizeof(brcmf_bss_info_le)` (117 bytes), but the
firmware's actual struct is ~280 bytes. Fixed by computing `bi_len - ie_len`
when `ie_offset=0`.

**Current state**: Scan cache works, RSN IEs are properly parsed.
wpa_supplicant finds networks but can't associate yet — it brings the
interface down during init and never re-enables it. Needs investigation
into the BSD wpa_supplicant driver's interface lifecycle expectations.

**Sequence** (target):

1. `wpa_supplicant -Dbsd -iwlan0 -c/etc/wpa_supplicant.conf`
2. wpa_supplicant scans via net80211 → scan cache populated
3. wpa_supplicant finds matching BSS with RSN IE
4. wpa_supplicant triggers MLME join via net80211 ioctl
5. Driver sets wsec/wpa_auth and joins via firmware
6. Firmware associates, sends LINK event
7. AP sends EAPOL frame 1 → delivered to wlan0 via data path
8. wpa_supplicant handles 4-way handshake over EAPOL
9. wpa_supplicant installs keys via iv_key_set → wsec_key IOVAR

## Next steps

1. DMA ring initialization
2. Interrupt setup
3. msgbuf protocol
