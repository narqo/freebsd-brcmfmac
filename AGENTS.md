# FreeBSD Kernel Module in Zig

This project builds a brcmfmac WiFi driver for FreeBSD as a kernel module (KLD),
using Zig for pure logic and C for kernel interactions.

## Goal

Build a working brcmfmac driver for BCM4350 (MacBook Pro 2016) on FreeBSD 15.

Target hardware: PCI device `0x14e4:0x43a3`

## Constraints

- Use FreeBSD's LinuxKPI compatibility layer
- Cannot use Zig's `@cImport` with kernel headers (see decisions doc)
- C for kernel API calls; Zig for pure logic only
- Build/test requires remote FreeBSD 15 host

## Build environment

The code is built and tested on a remote host, that runs FreeBSD 15.0-RELEASE, with Zig 0.16-dev.

The local machine **cannot** build the project -- FreeBSD kernel headers are required.

## Before starting work

**Read the docs/ directory first:**

- **docs/00-progress.md** - Current status, milestones, what's done and what's next
- **docs/01-decisions.md** - Design decisions and rationale (especially the C/Zig split)

These documents are the source of truth for project state and architecture choices.

## Driver specification

The **spec/** directory contains the brcmfmac driver specification:

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

Zig's `@cImport` does not work reliably with FreeBSD kernel headers due to:

- Generated headers (vnode_if.h) not in source tree
- Implicit function declarations (panic, printf, vsnprintf)
- Complex include order dependencies
- Bitfield structs requiring workarounds

**Current approach:** Avoid `@cImport`. Use `@extern` for function declarations.
Keep kernel interactions in C code.

See docs/01-decisions.md for full rationale.

### Zig translate-c bitfield limitation

Zig's C translator demotes structs with bitfields to opaque types (ref "[Translation failures][1]"). FreeBSD headers
use bitfields in `struct user_segment_descriptor` and `struct gate_descriptor`, which are embedded in `struct pcpu`.

The `src/hack.h` header provides bitfield-free replacements. It must be included before other system headers in `@cImport` if @cImport is used in the future.

[1]: https://ziglang.org/documentation/master/#Translation-failures

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

## LLVM printf optimization

Do not declare printf as `pub extern "c" fn printf(...)`. LLVM recognizes this as
libc printf and optimizes calls like `printf("foo\n")` to `puts("foo")`. The kernel
does not export `puts`, causing link failures.

Use `@extern` to import as a function pointer, which defeats the optimization:

```zig
const printf = @extern(*const fn ([*:0]const u8) callconv(.c) c_int, .{ .name = "printf" });
```
