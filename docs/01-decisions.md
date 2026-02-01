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

## Next steps

1. Debug firmware boot issue
2. Compare with working driver's initialization sequence
3. Check if PCIe core needs configuration before firmware start
