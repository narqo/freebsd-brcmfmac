# Investigations

This document captures investigation notes and findings during driver development.
For current status, see `docs/00-progress.md`.

---

## 27 Mar 2026: SDIO WPA2 fully working

### Final fixes

1. **wlan_ccmp kernel module missing** — test host kernel needed CCMP built-in.
   Without it, `ieee80211_crypto_newkey()` failed with ENXIO, aborting the WPA handshake.

2. **RX path lock issue** — `if_input()` was called while holding `sdio_lock`.
   TCP processing triggered TX callback which needed the same lock → deadlock.
   Fixed by queuing RX mbufs and delivering after releasing the lock.

3. **TX path sleeping** — `brcmf_sdpcm_tx` was called from TCP output path
   (holding `tcpinp` lock) and slept in SDIO/CAM. WITNESS detected sleeping
   thread holding non-sleepable lock.
   Fixed by queuing TX mbufs and sending from a taskqueue.

### Result

WPA2 5GHz connection fully working:
- Association succeeds
- EAPOL 4-way handshake completes
- PTK and GTK keys installed
- DHCP works (got IP 192.168.188.182)
- Ping to gateway and internet (8.8.8.8) works
- No panics

---

## 26 Mar 2026: SDIO core register bugs (FIXED)

Three bugs broke the SDIO mailbox protocol:

1. **Wrong register offset**: `SD_REG_TOHOSTMAILBOXDATA` was 0x044, should be 0x04C
2. **Wrong ACK value**: `SMB_INT_ACK` was 0x020000, should be 0x02
3. **Wrong intstatus bits**: `I_HMB_FC_STATE` was 0x08, should be 0x10;
   `I_HMB_FC_CHANGE` was 0x10, should be 0x20

Fixed by consolidating all SDIO core register definitions into `brcmfmac.h`.

---

## 25-26 Mar 2026: SDPCM/BCDC audit

Systematic audit of Linux brcmfmac SDIO reference against FreeBSD code.
Found 12 deviations including:

- `proptxstatus_mode=1` sent (Linux doesn't enable this on default SDIO)
- TX credits not enforced
- No integrated DPC loop
- Attach ordering wrong
- Flow-control bitmap never read
- Mailbox content not interpreted

Most fixed during the session. The register bugs (above) were the actual blockers.

---

## 22 Mar 2026: SDIO F2 transport working

After fixing F2 block size (64 bytes), address mode (fixed, not incrementing),
and frame padding, the first successful ioctl completed:

```
brcmfmac0: firmware: wl0: Aug 29 2023 01:47:08 version 7.45.265
```

Key findings:
- Arasan SDHCI cannot sustain large PIO bursts to BCM43455 F2 port
- F2 is a FIFO — incrementing addresses cause chip death
- Block-mode transfers with 64-byte blocks work reliably

---

## 21 Mar 2026: sdiob F0 timeout bug (FIXED)

Root cause of IORdy poll hang: `sdiob_rw_direct_sc` uses
`sc->cardinfo.f[fn].timeout` for CAM CCB timeout. Function 0
was never initialized (loop starts at fn=1), so timeout=0.

Fixed in FreeBSD kernel sdiob.c.

---

## 19-20 Mar 2026: SDHCI bugs identified

Two separate Arasan SDHCI bugs:

1. **CMD52 poll hang**: Repeated CMD52 reads to CCCR 0x03 hang controller.
   Single reads work. Root cause: F0 timeout=0 (see above).

2. **CMD53 PIO write hang**: F2 CMD53 byte-mode writes hang when F2 ready.
   Fixed in FreeBSD kernel with SDHCI patches.

---

## Historical notes

Earlier investigation notes archived. Key learnings:

- BCM43455 firmware requires CLM blob for scanning
- SDIO events include 4-byte BCDC header (unlike PCIe)
- Firmware struct alignment must match (no __packed)
- Large stack buffers cause kernel stack overflow (moved to softc)
- Net80211 scan timing requires immediate result delivery
