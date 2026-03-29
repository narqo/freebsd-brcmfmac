# Progress Tracker

## Current Status (2026-03-27)

**PCIe (BCM4350, MacBook Pro 2016) — WORKING:**
- WPA2-PSK association, DHCP, internet connectivity
- 5GHz and 2.4GHz, HT40/VHT80 rates
- Flood ping 1000/1000, 0% loss
- Clean kldload/kldunload, interface cycling
- DHCP works, internet connectivity verified
- Ping to gateway and 8.8.8.8 successful

**SDIO (BCM43455, Raspberry Pi 4) — WORKING:**
- WPA2-PSK association on 5GHz
- EAPOL 4-way handshake completes
- PTK and GTK keys installed
- DHCP works, internet connectivity verified
- Ping to gateway and 8.8.8.8 successful

**Remaining issues:**
- 2.4GHz open AP: AUTH timeout — firmware reports "no ack". Possibly FEM/BT coex related.
- Rapid interface cycling with wpa_supplicant can deadlock (known issue, not fixed).

## Milestones

### PCIe Milestones 1-17: COMPLETE

Full FullMAC driver for BCM4350:
- Firmware download, msgbuf protocol, flow rings
- WPA2-PSK with host supplicant
- 5GHz/HT40/VHT80, latency optimization
- Link loss recovery, interface cycling
- Production hardening, D2H reliability

See git history for detailed milestone notes.

### SDIO Milestones M-S1 through M-S6: COMPLETE

Full FullMAC driver for BCM43455:
- SDIO bus layer, SDPCM/BCDC protocol
- CLM blob download, net80211 integration
- WPA2-PSK with host supplicant
- 5GHz association and data path

#### Key fixes (27 Mar 2026 session):

1. **wlan_ccmp kernel module missing** — test host kernel rebuilt with CCMP built-in

2. **RX path lock issue** — `if_input()` was called while holding `sdio_lock`. TCP processing triggered TX callback which needed the same lock. Fixed by queuing RX mbufs and delivering after releasing the lock.

3. **TX path sleeping** — `brcmf_sdpcm_tx` was called from TCP output path (holding `tcpinp` lock) and slept in SDIO/CAM. Fixed by queuing TX mbufs and sending from a taskqueue.

#### Earlier SDIO fixes (25-26 Mar 2026):

- Fixed SDIO core register offsets (SD_REG_TOHOSTMAILBOXDATA, SMB_INT_ACK, I_HMB_FC bits)
- Fixed join iovar struct alignment and size
- Fixed bsscfg encoding for idx=0
- Added firmware console reader (sysctl `dev.brcmfmac.0.fwcon`)
- Simplified SDPCM to synchronous with sx_lock serialization

### Milestone M-S7: 2.4GHz AUTH timeout (TODO)

5GHz works, 2.4GHz fails with "authentication failure, no ack".

Investigation steps:
- [ ] Compare Linux brcmfmac 2.4GHz init sequence vs FreeBSD
- [ ] Check NVRAM differences (txchain, rxchain, FEM config)
- [ ] Investigate `FIXME bt_coex` message during `wl_open`
- [ ] Test with `btc_mode` iovar variations at runtime (not NVRAM)
- [ ] Check if 2.4GHz TX power is configured correctly
- [ ] Packet capture on AP side to confirm frames not received

References:
- `docs/03-known-issues.md` — 2.4GHz AUTH timeout entry
- Linux `brcmfmac/cfg80211.c` — `brcmf_cfg80211_connect` for init sequence
- Firmware console (`dev.brcmfmac.0.fwcon`) for runtime diagnostics

### Milestone M-S8: Country code configuration (TODO)

- [ ] Add sysctl `dev.brcmfmac.X.country` (read/write)
- [ ] Add loader tunable `hw.brcmfmac.country`
- [ ] Remove hardcoded "DE" from `brcmf_cfg_attach`

### Milestone M-S9: Debug cleanup (DONE)

- [x] Remove `device_printf` spam (`rx_data`, `tx_data`, `key_set`)
- [x] Convert to `BRCMF_DBG` macro with sysctl-controlled verbosity
- [x] Keep error paths with `device_printf`

### Milestone M-S10: Clean kldunload (TODO)

- [ ] Verify kldunload while associated (5GHz WPA2)
- [ ] Verify kldunload after disassociation
- [ ] Check for resource leaks (memory, tasks, callouts)
- [ ] Ensure no panics or hangs

### Milestone M-S11: Stability testing (TODO)

- [ ] Sustained iperf3 download (10+ minutes)
- [ ] Sustained iperf3 upload (10+ minutes)
- [ ] Large file transfer (100MB+)
- [ ] Interface cycling under load
- [ ] Verify no rx_repost_fail, rx_deliver_fail counters

### Milestone M-S12: Firmware crash recovery (TODO)

- [ ] Detect firmware crash (trap in shared RAM, fw_dead flag)
- [ ] Re-download firmware without kldunload
- [ ] Reinitialize net80211 state
- [ ] Automatic reconnection after recovery

### Milestone M-S13: Automated testing (TODO)

- [ ] Test harness for kldload/kldunload cycles
- [ ] Association/disassociation stress test
- [ ] Throughput regression tests
- [ ] CI integration

### Milestone M-S14: FreeBSD port/package (TODO)

- [ ] Create FreeBSD port (ports tree structure)
- [ ] Firmware file handling (linux-firmware integration)
- [ ] Man page (brcmfmac.4)
- [ ] Installation documentation

## Code Structure

See `src/` directory.

## Known Issues

See `docs/03-known-issues.md` for issue tracking.
