# Progress Tracker

## Current status

**Milestone 1: PCI device probe** - DONE (rewritten to native FreeBSD)
**Milestone 2: Firmware download** - BLOCKED

## Build and test

Cannot build or test locally. Requires FreeBSD 15 host with kernel headers.

To build on the FreeBSD target:
```sh
cd /path/to/brcmfmac2
make clean; make
```

To test:
```sh
sudo kldload ./brcmfmac.ko
dmesg | tail -20
sudo kldunload brcmfmac
```

## Recent changes

Rewrote driver from LinuxKPI to native FreeBSD APIs:

- Removed all LinuxKPI dependencies (`linux/pci.h`, `linux/firmware.h`, etc.)
- Using native FreeBSD PCI API (`sys/bus.h`, `dev/pci/pcivar.h`)
- Using native FreeBSD firmware API (`sys/firmware.h`)
- Using `bus_space_*` for register access instead of `readl`/`writel`
- Using `DELAY`/`pause_sbt` instead of `udelay`/`msleep`
- Using `malloc`/`free` with `M_BRCMFMAC` instead of `kzalloc`/`kfree`

## Milestones

### Milestone 1: PCI device probe (DONE)

Goal: Register as FreeBSD PCI driver, probe BCM4350, print chip ID.

- [x] Project skeleton with working Makefile
- [x] Native FreeBSD PCI driver registration (main.c)
- [x] Device probe callback (main.c)
- [x] BAR0/BAR2 mapping via bus_alloc_resource
- [x] Chip ID read and print
- [x] Zig helper functions for chip ID parsing

Result: BCM4350 rev 5 detected on MacBook Pro 2016.

### Milestone 2: Firmware download (BLOCKED)

Goal: Load firmware into device RAM, verify firmware boots.

- [x] Map BAR2 (TCM)
- [x] Request firmware via FreeBSD firmware API
- [x] Verify TCM read/write access
- [x] Read EROM base address
- [x] Implement EROM parser in Zig
- [x] Find ARM CR4 core (id=0x3e, base=0x18002000)
- [x] Find ARM CR4 wrapper (0x18102000, slave wrapper)
- [x] Find SOCRAM core (id=0x1a, base=0x18004000, wrap=0x18104000)
- [x] Halt ARM CR4 core via wrapper registers
- [x] Copy firmware to TCM at ram_base (0x180000)
- [x] Write reset vector to TCM[0]
- [x] Release ARM from reset
- [x] NVRAM parsing and loading (optional)
- [ ] **BLOCKED**: Firmware doesn't boot - never writes shared RAM address

#### Current blocker: Firmware not executing

**Symptoms:**
- ARM core state looks correct: ioctl=0x1 (CLK), resetctl=0x0, iost=0x0
- Reset vector written to TCM[0]: 0x180000
- Firmware intact at ram_base after timeout
- Shared RAM address stays 0x0 (firmware never writes it)

**What we've verified:**
- TCM read/write works (firmware copy verified)
- Correct wrapper address (0x18102000) - fixed EROM parsing to find slave wrappers
- Core reset sequence: halt with CPUHALT, copy firmware, release without CPUHALT
- NVRAM loaded and placed correctly (but another driver worked without NVRAM)

**Key insight:**
A different FreeBSD driver (ported from Linux) worked with the same firmware and no NVRAM.
This suggests we're missing some initialization step, not NVRAM data.

**Possible missing steps to investigate:**
1. PCIe core initialization (core 0x3c, wrapper 0x18003000)
2. Other core initialization before ARM start
3. Different reset sequence
4. Memory/DMA setup the firmware expects
5. Interrupt or doorbell configuration

**Next steps:**
- Find/compare with the working driver's initialization sequence
- Check if PCIe core needs configuration
- Look for other initialization Linux does before firmware download

### Future milestones

- Parse shared RAM structure
- DMA ring setup
- Basic msgbuf protocol
- Firmware command interface
- Event handling
- net80211 integration (native FreeBSD, not cfg80211)
- Data path (TX/RX)
