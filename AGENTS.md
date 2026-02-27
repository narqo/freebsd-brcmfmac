# FreeBSD Kernel Module

This project builds a brcmfmac WiFi driver for FreeBSD as a kernel module (KLD),
using Zig for pure logic and C for kernel interactions.

## Ultimate goal

Build a working brcmfmac driver for BCM4350 (MacBook Pro 2016) on FreeBSD 15.

Target hardware: PCI device `0x14e4:0x43a3`

## Before starting work

Read the docs/ directory first:

- **docs/00-progress.md** - Current status, milestones, what's done and what's next
- **docs/01-decisions.md** - Design decisions and rationale (especially the C/Zig split)
- **docs/02-build-test.md** - Build/deploy workflow, crash analysis
- **docs/03-known-issues.md** - Open and resolved bugs

These documents are the source of truth for project state and architecture choices.

## Driver specification

Study the spec/ directory for the brcmfmac driver specification:

| File | Description |
|------|-------------|
| spec/00-overview.md | Architecture overview, FullMAC concept |
| spec/01-data-structures.md | Core data structures |
| spec/02-bus-layer.md | PCIe bus interface, BAR mappings, firmware download |
| spec/03-protocol-layer.md | msgbuf protocol, DMA rings |
| spec/04-firmware-interface.md | FWIL layer, ioctls, iovars |
| spec/05-event-handling.md | Firmware event processing |
| spec/06-cfg80211-operations.md | Wireless configuration operations |
| spec/07-initialization.md | Driver and firmware init sequence |
| spec/08-data-path.md | TX/RX packet flow |
| spec/09-firmware-commands.md | Command reference |
| spec/10-structures-reference.md | Firmware structure definitions |

## Source code

The source code is in the src/ directory.

## Build environment

The code is built and tested on a remote host, that runs FreeBSD 15.0-RELEASE, with Zig 0.16-dev.
The local machine **cannot** build the project -- FreeBSD kernel headers are required.

## Constraints

- Use native FreeBSD APIs (no LinuxKPI)
- Cannot use Zig's `@cImport` with kernel headers (see decisions doc)
- C for kernel API calls; Zig for pure logic only
- Build/test requires remote FreeBSD 15 host

## Linker limitations

The FreeBSD kernel linker (link_elf_obj) has limited support for relocation types.

When a new pitfall, limitation, or workaround is discovered during development,
**document it in this file** under the appropriate section. This ensures future
work doesn't repeat the same mistakes.

### TLS (Thread Local Storage)

The linker does not support TLS relocations. Many parts of Zig's standard library
use TLS internally and will cause `kldload` to fail with:

```
kldload: unexpected relocation type 23, symbol index N
```

#### Avoid

- `std.debug.*` - uses TLS for error traces
- `std.log.*` - built on std.debug
- `std.heap.*` - userspace allocators
- `std.Thread` - TLS, pthreads
- `std.os.*`, `std.fs.*`, `std.net.*`, `std.process.*` - userspace syscalls
- `std.io.getStdOut/getStdErr/getStdIn` - file descriptors
- `std.time.*` - userspace clock syscalls
- `std.crypto.random` - getrandom syscall
- `std.Progress` - uses TLS

#### Safe to use

- `std.mem` - memory utilities
- `std.math` - math operations
- `std.meta` - comptime metaprogramming
- `std.fmt.bufPrint` - formatting to a buffer
- `std.unicode`, `std.ascii` - pure functions
- `std.hash.*` - hash functions
- `std.sort` - sorting
- `std.BoundedArray` - stack-based container

### GOT (Global Offset Table)

The linker does not support GOT-relative relocations like `R_X86_64_REX_GOTPCRELX` (type 42) or `R_X86_64_GOTPCREL` (type 9).
Zig may generate these when declaring `extern` variables, from C headers (e.g., `M_TEMP` from `sys/malloc.h`).

```
kldload: unexpected relocation type 42, symbol index N
link_elf_obj: symbol M_TEMP undefined
```

Use `@extern` to import a pointer to a variable with visibility `hidden`. This should force LLVM to eliminate the need for GOTPCREL:

```zig
const M_TEMP = @extern(*c.struct_malloc_type, .{ .name = "M_TEMP", .visibility = .hidden });
```

## Zig translate-c limitations

Zig's `@cImport` does not work reliably with FreeBSD kernel headers. See **docs/01-decisions.md**
for full rationale.

**Current approach:** Avoid `@cImport`. Use `@extern` for function declarations.
Keep kernel interactions in C code.

### Bitfield structs

Zig's C translator demotes structs with bitfields to opaque types (ref "[Translation failures][1]"). FreeBSD headers
use bitfields in `struct user_segment_descriptor` and `struct gate_descriptor`, which are embedded in `struct pcpu`.

The `src/hack.h` header provides bitfield-free replacements. It must be included before other system headers if `@cImport` is used in the future.

[1]: https://ziglang.org/documentation/master/#Translation-failures

### LLVM printf optimization

Do not declare printf as `pub extern "c" fn printf(...)`. LLVM recognizes this as
libc printf and optimizes calls like `printf("foo\n")` to `puts("foo")`. The kernel
does not export `puts`, causing link failures.

Use `@extern` to import as a function pointer, which defeats the optimization:

```zig
const printf = @extern(*const fn ([*:0]const u8) callconv(.c) c_int, .{ .name = "printf" });
```

## net80211 swscan private struct layout

The swscan module uses a private `struct scan_state` that extends
`ieee80211_scan_state`. The struct is not exported, but the driver needs
access to drain scan tasks during VAP teardown. Layout (FreeBSD 15):

```c
struct scan_state {
    struct ieee80211_scan_state base;
    u_int ss_iflags;           // ISCAN_* flags
    unsigned long ss_chanmindwell;
    unsigned long ss_scanend;
    u_int ss_duration;
    struct task ss_scan_start;
    struct timeout_task ss_scan_curchan;
};
```

ISCAN flags: MINDWELL=0x01, DISCARD=0x02, INTERRUPT=0x04, CANCEL=0x08,
ABORT=0x10, RUNNING=0x20.

`scan_curchan_task` accesses `ss->ss_vap` via `IEEE80211_DPRINTF` BEFORE
checking abort flags. If `ss_vap` is NULL, the kernel faults at address 0x6a
(`vap->iv_debug` offset). Pre-set `ic->ic_scan->ss_vap` in vap_create.

## Group key EA field

The `wsec_key` iovar for group keys requires `ea` field set to all zeros.
Setting `ea=ff:ff:ff:ff:ff:ff` (broadcast) returns BCME_UNSUPPORTED (5).
The Linux driver leaves `ea` zeroed for group keys in STA mode.

## Firmware WPA2 limitations (v7.35.180.133)

- `WPA2_AUTH_PSK_SHA256` (0x8000) as `wpa_auth` value is NOT supported.
  Setting `wpa_auth=0x8080` causes `SET_SSID failed, status=1`.
  However, the firmware auto-negotiates PSK-SHA256 (AKM type 6) when
  the AP advertises it. Use `wpa_auth=0x80` (WPA2_AUTH_PSK) and let the
  firmware select the AKM based on the AP's RSN IE.
- `sup_wpa=1` + `SET_WSEC_PMK` returns BCME_BADARG (-23). The firmware
  does not support internal supplicant mode.
- Must use `sup_wpa=0` for host-managed WPA.

## net80211 regdomain channel filtering

When `ifconfig wlan0 create` is called, ifconfig's regdomain code
rebuilds the channel list from the regdomain database, replacing
`ic_channels` and `ic_nchans`. This silently drops channels not in
the regulatory domain (e.g., DFS channels without `IEEE80211_CHAN_DFS`
flag).

**Fix**: Set `ic_regdomain` to `SKU_DEBUG` (0x1ff) / `CTRY_DEBUG`
(0x1ff) before `ieee80211_ifattach`. This bypasses the regdomain
filter and preserves all channels from `ic_getradiocaps`. The
firmware handles regulatory enforcement.

## Chip stuck after kernel panic

After a kernel panic, the BCM4350 PCI device may stop responding to
BAR0 MMIO reads (returns 0xffffffff). The ARM core is in an undefined
state and the backplane ignores reads.

- `devctl reset` does not help
- D3→D0 PCI power management transition does not help
- VM reboot does not help (QEMU PCI passthrough doesn't reset the
  physical device)
- **Physical host power cycle required** to restore the chip
