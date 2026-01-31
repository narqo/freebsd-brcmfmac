# Progress Tracker

## Current status

**Milestone 1: PCI device probe** - DONE
**Milestone 2: Firmware download** - NOT STARTED

## Build and test

Cannot build or test locally. Requires FreeBSD 15 host with kernel headers.

To build on the FreeBSD target:
```sh
cd /path/to/brcmfmac2
make
```

To test:
```sh
sudo kldload ./brcmfmac.ko
dmesg | tail -20
sudo kldunload brcmfmac
```

## Milestones

### Milestone 1: PCI device probe (DONE)

Goal: Register as LinuxKPI PCI driver, probe BCM4350, print chip ID.

- [x] Project skeleton with working Makefile
- [x] LinuxKPI PCI driver registration (main.c)
- [x] Device probe callback (main.c)
- [x] BAR0 mapping via pcim_iomap
- [x] Chip ID read and print
- [x] Zig helper functions for chip ID parsing (no @cImport)

Result: BCM4350 rev 5 detected on MacBook Pro 2016.

### Milestone 2: Firmware download

Goal: Load firmware into device RAM, verify firmware boots.

- [ ] Request firmware via LinuxKPI firmware API
- [ ] Parse NVRAM
- [ ] Halt ARM core
- [ ] Copy firmware to TCM
- [ ] Copy NVRAM to TCM
- [ ] Release ARM reset
- [ ] Poll for shared RAM address (firmware boot confirmation)

### Future milestones

- DMA ring setup
- Basic msgbuf protocol
- Firmware command interface
- Event handling
- cfg80211/net80211 integration
- Data path (TX/RX)
