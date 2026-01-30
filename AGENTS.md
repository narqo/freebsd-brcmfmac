# FreeBSD Kernel Module in Zig

This project builds a FreeBSD kernel module (KLD) using Zig.

## Build environment

The code is built and tested on a remote host, that runs FreeBSD 15.0-RELEASE, with Zig 0.16-dev.

The local machine **cannot** build the project -- FreeBSD kernel headers are required.

## Before starting work

**Read the docs/ directory first:**

- **docs/00-progress.md** - Current status, milestones, what's done and what's next
- **docs/01-decisions.md** - Design decisions and rationale (especially the C/Zig split)

These documents are the source of truth for project state and architecture choices.

## Linker limitations

The FreeBSD kernel linker (link_elf_obj) has limited support for relocation types.

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

## Zig translate-c bitfield limitation

Zig's C translator demotes structs with bitfields to opaque types (ref "[Translation failures][1]"). FreeBSD headers
use bitfields in `struct user_segment_descriptor` and `struct gate_descriptor`, which are embedded in `struct pcpu`.

The `include/hack.h` header provides bitfield-free replacements. It must be
included before other system headers in `@cImport`.

[1]: https://ziglang.org/documentation/master/#Translation-failures

## LLVM printf optimization

Do not declare printf as `pub extern "c" fn printf(...)`. LLVM recognizes this as
libc printf and optimizes calls like `printf("foo\n")` to `puts("foo")`. The kernel
does not export `puts`, causing link failures.

Use `@extern` to import as a function pointer, which defeats the optimization:

```zig
const printf = @extern(*const fn ([*:0]const u8) callconv(.c) c_int, .{ .name = "printf" });
```
