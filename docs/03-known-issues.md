# Known Issues

## Open

### BCM43455 2.4GHz AUTH timeout

5GHz WPA2 works. 2.4GHz (tested on open AP "TestAP") fails with AUTH timeout.
Firmware console shows "authentication failure, no ack" — the firmware transmits
AUTH frames but the AP doesn't ACK them.

Possibly related to FEM/BT coexistence. `FIXME bt_coex` appears in firmware
console during radio init. `btc_mode=0` in NVRAM did not help.

### 5GHz limited to HT40

Firmware reports `bw_cap(5G)=0x1` (20MHz cap). `BRCMF_C_DOWN` returns NOTDOWN,
so the cap cannot be changed at runtime. The firmware still negotiates HT40+
in practice. Net80211 reports `11a ht/40+`.

### Rapid interface cycling unreliable

Down/up cycles with <5s gaps may not complete WPA2 association in time,
especially on DFS channels. 5s gaps are reliable.

### 2s-gap cycling deadlock with wpa_supplicant

Rapid down/up cycles (<3s) with wpa_supplicant running can deadlock the kernel.
Without wpa_supplicant the same cycles complete cleanly. Not yet diagnosed.

### Country code hardcoded to "DE"

`brcmf_cfg_attach` sets firmware regulatory domain to `DE` via `country` iovar.
Needs runtime configuration.

### wpa_supplicant DELKEY warning at startup

```
ioctl[SIOCS80211, op=20]: Invalid argument
```

Benign — wpa_supplicant flushes keys on an empty keyring. No functional impact.

---

## Resolved

### SDIO WPA2 connection failing (FIXED 27 Mar 2026)

Three issues fixed:
1. wlan_ccmp kernel module missing on test host
2. RX path called `if_input()` while holding `sdio_lock` → deadlock
3. TX path slept in SDIO/CAM while called from TCP output → lock violation

### SDIO register bugs (FIXED 26 Mar 2026)

Three SDIO core register/constant bugs broke the mailbox protocol:
1. `SD_REG_TOHOSTMAILBOXDATA` wrong offset
2. `SMB_INT_ACK` wrong value
3. `I_HMB_FC_STATE/CHANGE` wrong bit positions

### PCIe D2H ring processing (FIXED)

Missing DMA sync on ctrl/tx complete rings caused missed completions.
Fixed with proper `bus_dmamap_sync(POSTREAD)` on all three D2H rings.

### IOCTL timeouts on DFS channels (FIXED)

Firmware busy with radar detection caused cascading timeouts.
Fixed by skipping `wsec_key` delete when interface down, and removing
timeout→fw_dead escalation.

### Stack overflow in SDPCM ioctl (FIXED)

Two 8KB stack arrays overflowed 16KB kernel stack.
Moved to softc.
