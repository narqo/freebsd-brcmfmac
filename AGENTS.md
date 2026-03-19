# FreeBSD Kernel Module

This project builds a brcmfmac WiFi driver for FreeBSD as a kernel module (KLD),
using Zig for pure logic and C for kernel interactions.

## Ultimate goal

Build a working brcmfmac driver for BCM4350 (MacBook Pro 2016) on FreeBSD 15.

Target hardware: PCI device `0x14e4:0x43a3`

## Before starting work

Read the docs/ directory first:

- **docs/00-progress.md** - Current status, milestones, what's done and what's next
- **docs/01-decisions.md** - Design decisions and rationale
- **docs/02-build-test.md** - Build/deploy workflow, crash analysis

These documents are the source of truth for project state and architecture choices.

Good to know:

docs/03-known-issues.md keeps the archive of open and resolved bugs.

Use the docs/10-investigations.md document to persist mid-session investigation scratch notes.

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

The code is built and tested on a remote host, that runs FreeBSD 15.0-RELEASE.
The local machine **cannot** build the project -- FreeBSD kernel headers are required.

When starting a new milestone, ensure the current worktree is synced to the build host.

## Constraints

- Use native FreeBSD APIs (no LinuxKPI)
- Build/test requires remote FreeBSD 15 host

Read docs/01-decisions.md for the rest.

## Linker limitations

The FreeBSD kernel linker (link_elf_obj) has limited support for relocation types.

When a new pitfall, limitation, or workaround is discovered during development,
document it under the appropriate section in docs/03-known-issues.md. This ensures future
work doesn't repeat the same mistakes.

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
