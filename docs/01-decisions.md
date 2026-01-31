# Design Decisions

## 2026-01-31: LinuxKPI approach

Use FreeBSD's LinuxKPI compatibility layer rather than native FreeBSD driver APIs.

Rationale:
- The spec is based on Linux brcmfmac driver
- LinuxKPI provides Linux-compatible PCI, firmware, DMA APIs
- Simplifies mapping spec to implementation

Trade-offs:
- Extra abstraction layer
- May hit LinuxKPI limitations or bugs

## 2026-01-31: Iterative milestones

Build incrementally:
1. PCI probe (detect device)
2. Firmware load (prove firmware runs)
3. Ring setup + commands (bidirectional communication)
4. Network interface + data path

Rationale:
- Each milestone is independently testable
- Reduces debugging scope at each step

## 2026-01-31: Minimal error handling initially

Early iterations: return errors, don't handle all edge cases.

Rationale:
- Faster iteration
- Add robustness once core functionality works

## 2026-01-31: C for kernel interactions, Zig for pure logic

**Updated approach** after @cImport issues with FreeBSD kernel headers.

Architecture:
- `main.c`: All kernel API usage (LinuxKPI, PCI, bus_space, etc.)
- `*.zig`: Pure logic without @cImport (constants, parsing, state machines)

Zig integration pattern:
- Use `@extern` to declare functions, not `@cImport`
- Export Zig functions with `pub export fn`
- Define C-compatible structs in both C and Zig
- C calls Zig for computation; Zig avoids kernel headers

Rationale:
- Zig's @cImport with kernel headers fails due to:
  - Generated headers (vnode_if.h) not in source tree
  - Implicit function declarations (panic, printf, vsnprintf)
  - Complex include order dependencies
  - Bitfield structs requiring workarounds
- C handles kernel complexity; Zig adds type safety for logic

Trade-offs:
- More C code than originally planned
- Must manually keep C and Zig struct definitions in sync
- Zig benefits limited to non-kernel logic

## 2026-01-31: hack.h for Zig bitfield workaround

Keep `src/hack.h` for the `user_segment_descriptor` and `gate_descriptor`
bitfield workarounds. Only needed if future Zig code uses @cImport with
headers that pull in `x86/segments.h`.

Currently unused since we moved to extern-based approach.
