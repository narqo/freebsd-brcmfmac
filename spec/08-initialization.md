# Initialization Sequence

## Overview

Driver initialization proceeds through these major phases:
1. Bus probe and resource setup
2. Chip identification and reset
3. Firmware and board-data loading
4. Protocol attachment
5. Firmware-event attachment
6. Core bring-up and cfg80211 attach
7. Network interface registration

The probe and firmware-download path differs by bus. After bus-specific setup completes, the driver enters the common core attach path, but later steps still depend on the selected protocol, enabled features, and bus callbacks.

For SDIO-specific probe details, see [02-bus-sdio.md](02-bus-sdio.md). For PCIe, see [01-bus-pcie.md](01-bus-pcie.md).

## Phase 1: Bus probe

### PCIe probe

1. Allocate device info structure.
2. **Chip attach**: Use buscore ops (read32/write32 via BAR0 window) to enumerate chip cores through the EROM table. Identify ARM core, memory core, PMU, etc.
3. **Get resources**: Enable PCI device, set bus master, map BAR0 and BAR1.
4. **Select register set**: Choose default or 64-bit register offsets based on PCIe core revision.
5. **Read OTP**: For Apple/WCC/BCA chips, read on-chip one-time-programmable data for board identification.
6. **Allocate bus structure**: Create `brcmf_bus` with proto type `BRCMF_PROTO_MSGBUF`.
7. **Allocate driver context**: `brcmf_alloc` creates the `brcmf_pub` and wiphy structures.
8. **Request firmware**: Asynchronous firmware fetch; completion calls `brcmf_pcie_setup`.

### PCIe setup (firmware callback)

1. **Attach**: Fix BAR1 window size if needed.
2. **Get RAM info**: Query chip RAM base and size.
3. **Adjust RAM size**: Check firmware image for embedded RAM size override.
4. **Download firmware and NVRAM** to device TCM (see [01-bus-pcie.md](01-bus-pcie.md#firmware-download)).
5. **Set state to UP**.
6. **Initialize ring buffers**: Read shared RAM info, allocate DMA rings.
7. **Initialize scratch buffers**.
8. **Request IRQ**: Enable MSI, install threaded handler.
9. **Wire rings**: Connect common rings and flow rings to the bus msgbuf structure.
10. **Common attach**: Call `brcmf_attach`.

### SDIO probe

1. **SDIO function probe**: Set block sizes, enable functions.
2. **Chip identification**: Access backplane to enumerate cores.
3. **Clock setup**: Request HT clock.
4. **Firmware download**: Write firmware and NVRAM to chip RAM.
5. **F2 ready**: Wait for firmware to signal readiness.
6. **Common attach**: Call `brcmf_attach`.

## Phase 2: Common attach (`brcmf_attach`)

This is the bus-independent path. `brcmf_attach` performs top-level setup, then calls `brcmf_bus_started` for firmware-level initialization.

### `brcmf_attach`

1. **Firmware vendor attach**: Load vendor-specific ops module (WCC/BCA/CYW).

2. **Protocol attach**: Based on `bus->proto_type`:
   - `PROTO_MSGBUF` → `brcmf_proto_msgbuf_attach` (ring buffers, packet IDs, flow rings, pre-posted buffers).
   - `PROTO_BCDC` → `brcmf_proto_bcdc_attach` (BCDC header, set `hdrlen`).

3. **Event handler attach**: Initialize event dispatch infrastructure.

4. Calls `brcmf_bus_started` (below).

### `brcmf_bus_started`

5. **Create primary interface**: `brcmf_add_if(drvr, 0, 0, false, "wlan%d", mac)`. Must happen first — subsequent firmware queries operate through this interface.

6. **Bus state**: Set to `BRCMF_BUS_UP`. Must precede any FWIL operation because all FWIL calls check `bus_if->state == BRCMF_BUS_UP`.

7. **Bus preinit**: Call the bus-specific preinit:
   - PCIe: enable interrupts and send host-ready doorbell.
   - SDIO: enable data flow.

8. **Preinit firmware commands** (`brcmf_c_preinit_dcmds`):
   - Query or set MAC address via `cur_etheraddr` IOVAR.
   - Query revision info.
   - Download CLM blob via `clmload` IOVAR (chunked).
   - Download TX cap blob via `txcapload` IOVAR (chunked), if available.
   - Query firmware version string via `ver` IOVAR.
   - Configure regulatory domain from module parameters or firmware defaults.

9. **Feature detection**: Query firmware capabilities, set feature flags.

10. **Protocol init done**:
    - For BCDC: attach firmware signaling (fwsignal).
    - For msgbuf: no-op.

11. **Configure primary bus IF**: Attach protocol-layer state for the primary interface.

12. **cfg80211 attach**: See below.

13. **Network interface registration**: Register the primary `net_device`.

14. **P2P**: Register P2P device if supported.

15. **Register INET notifiers**: For ARP/ND offload updates.

## Phase 3: cfg80211 attach

1. **Allocate cfg80211_info**: Contains scan state, connection info, VIF list, escan buffer.
2. **Create regulatory domain**: Set up initial regdomain.
3. **Initialize wiphy**:
   - Set supported bands (2.4 GHz and 5 GHz with rate tables).
   - Set cipher suites (WEP40, WEP104, TKIP, CCMP, AES-CMAC).
   - Set interface types (STA, AP, P2P variants depending on features).
   - Set scan IE length, max scan SSIDs, max match sets.
   - Set WOWL support if features present.
   - Set MFP support if `MFP` feature detected.
   - Set SAE support if `SAE` feature detected.
4. **Register wiphy**: `wiphy_register`.
5. **Allocate primary VIF**: Type `NL80211_IFTYPE_STATION`, linked to ifp[0].
6. **Register event handlers**:
   - `BRCMF_E_ESCAN_RESULT` → escan handler
   - `BRCMF_E_SET_SSID`, `BRCMF_E_LINK`, `BRCMF_E_DEAUTH`, `BRCMF_E_DEAUTH_IND`, `BRCMF_E_DISASSOC_IND` → connect/disconnect handlers
   - `BRCMF_E_ROAM` → roaming handler
   - `BRCMF_E_MIC_ERROR` → MIC failure handler
   - `BRCMF_E_PSK_SUP` → firmware supplicant handler
   - `BRCMF_E_IF` → interface event handler
   - `BRCMF_E_RSSI` → RSSI handler
   - `BRCMF_E_PFN_NET_FOUND` → PNO handler
   - P2P-specific events if P2P supported
7. **Activate events**: Push the `event_msgs` bitmask to firmware.
8. **Dongle init**:
   - `BRCMF_C_DOWN` (bring firmware interface down for configuration).
   - Set infrastructure mode (`BRCMF_C_SET_INFRA = 1`).
   - Set band preference.
   - Set country code via `BRCMF_C_SET_COUNTRY`.
   - `BRCMF_C_UP` (bring firmware interface up).
   - Set power management.
   - Set roam trigger (`-75` dBm) and delta (`20` dB).
   - Set beacon timeout (`2` when roaming enabled, `4` when disabled).
   - Set scan channel time (`40` ms) and scan unassoc time (`40` ms).
9. **Mark dongle as up**.

## Phase 4: Network interface registration

The primary interface (ifidx 0, bsscfgidx 0) is registered:

1. Allocate `net_device`.
2. Set `netdev_ops` (open, stop, start_xmit, set_mac_address, set_rx_mode).
3. Set `ieee80211_ptr` to the VIF's wireless_dev.
4. Register with `register_netdevice`.

The interface is now visible to userspace (e.g., `wlan0`).

## Interface model

### brcmf_pub

One per physical device. Holds:
- Bus pointer
- Protocol pointer
- Wiphy pointer
- cfg80211_info pointer
- Interface list (`iflist[16]`)
- Index mapping (`if2bss[16]`) — maps firmware ifidx to bsscfgidx
- MAC address
- Feature flags, chip quirks
- Protocol mutex and buffer
- Event handler info

### brcmf_if

Per virtual interface:
- `ifidx`: firmware interface index (0–15)
- `bsscfgidx`: BSS configuration index
- `vif`: pointer to cfg80211 VIF state
- `ndev`: network device
- `fws_desc`: firmware signaling descriptor (SDIO)
- `mac_addr`: assigned MAC
- Workers for multicast and ND offload

### brcmf_cfg80211_vif

Per VIF cfg80211 state:
- `wdev`: wireless_dev structure
- `profile`: connection profile (BSSID, security, keys)
- `sme_state`: bitmask of VIF status (READY, CONNECTING, CONNECTED, etc.)
- `saved_ie`: vendor IEs for different frame types
- `mgmt_tx`: completion for management frame TX
- `cqm_rssi_low/high/last`: RSSI monitoring state

### brcmf_bus

Per physical device bus state:
- Union of bus-private data (SDIO, PCIe, USB)
- Protocol type
- Bus state (DOWN, UP)
- ops table (bus callbacks)
- msgbuf pointer (for PCIe)

## Teardown

### Detach sequence

1. **cfg80211 detach**: Unregister wiphy, free VIFs, cancel scan timer, free escan buffer.
2. **Remove interfaces**: Unregister net devices, free interface objects.
3. **Protocol detach**: Free packet IDs, flow rings, DMA buffers, workqueues.
4. **Event detach**: Cancel event worker, free event queue.
5. **Bus-specific cleanup**: Free IRQ, release DMA rings, unmap BARs, free firmware references.
6. **Chip detach**: Free chip core list.
7. **Free driver context**.
