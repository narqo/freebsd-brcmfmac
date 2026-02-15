# Progress Tracker

## Current status

**Milestone 8: Data path** - IN PROGRESS (TX/RX completions not received)

## Build and test

See docs/02-build-test.md for full workflow.

## Milestones

### Milestone 1-7: DONE

See git history for details on PCI probe, firmware download, DMA rings, msgbuf init,
interface init, scan support, and association.

### Milestone 8: Data path (IN PROGRESS)

**Completed:**
- [x] Flow ring creation (MSGBUF_TYPE_FLOW_RING_CREATE)
- [x] Flow ring ID calculation (flowid + BRCMF_NROF_H2D_COMMON_MSGRINGS)
- [x] TCM ring descriptor setup for flow rings
- [x] TX packet submission (MSGBUF_TYPE_TX_POST)
- [x] TX buffer tracking with DMA mapping
- [x] RX buffer posting structure and initial post
- [x] Fixed scan state machine crashes (set ss_next=ss_last=0)

**Not working:**
- [ ] TX completion handling - firmware not sending TX_STATUS messages
- [ ] RX completion handling - firmware not sending RX_CMPLT messages
- [ ] Packet delivery to net80211

**Current state:**
- Flowring created successfully (status 0)
- Ring addresses verified correct:
  - ringmem=0x23b3ac, h2d_w=0x23b67c, h2d_r=0x23b724
  - flowring desc at 0x23b3fc, w_idx at 0x23b680, r_idx at 0x23b728
- TX function called, packets submitted to ring, doorbell rung
- D2H interrupts fire (status 0x10000)
- TX complete and RX complete ring write pointers stay at 0
- IOCTL/event completions work fine

**Suspected issues:**
1. Firmware may require additional configuration before data path works
2. May need "wlfc_mode" or similar iovar
3. Flowring may need different parameters
4. Data path might need explicit enable after association

### Future milestones

- WPA/WPA2 support (key management, sup_wpa iovar)
- Power management
- Proper scan result reporting to net80211

## Known issues

See docs/03-known-issues.md for tracked bugs.

## Debug information

### Ring addresses (from firmware shared memory)

```
ringmem_addr = 0x23b3ac
h2d_w_idx_addr = 0x23b67c  (write indices for H2D rings)
h2d_r_idx_addr = 0x23b724  (read indices for H2D rings)
d2h_w_idx_addr = 0x23b7cc  (write indices for D2H rings)
d2h_r_idx_addr = 0x23b7d8  (read indices for D2H rings)
max_flowrings = 40
max_submissionrings = 42
max_completionrings = 3
```

### Flowring 0 addresses

```
desc_addr = 0x23b3fc  (ringmem + 5*16, after 5 common rings)
w_idx_addr = 0x23b680 (h2d_w + 4, after 2 common H2D rings)
r_idx_addr = 0x23b728 (h2d_r + 4, after 2 common H2D rings)
ring_id = 2 (BRCMF_NROF_H2D_COMMON_MSGRINGS + flowid)
```

## Code structure

| Module | Purpose |
|--------|---------|
| pcie.c | PCIe bus layer: BAR mapping, DMA, ring allocation, interrupts, firmware load |
| msgbuf.c | Message buffer protocol: ring operations, D2H processing, IOCTL handling, TX/RX |
| core.c | Chip core management: enumeration, reset, firmware download state |
| fwil.c | Firmware interface layer: IOVAR get/set operations |
| cfg.c | net80211 interface: VAP management, scan, connect |
| brcmfmac.zig | EROM parser (pure Zig, no TLS/kernel deps) |
