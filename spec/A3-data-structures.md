# Appendix: Host Driver Data Structures

## Overview

This appendix documents the key host-side data structures used by the driver. These are internal to the host and not exchanged with firmware on the wire.

## Core context (`brcmf_pub`)

One instance per physical device. Central structure linking all subsystems.

| Field | Type | Purpose |
|-------|------|---------|
| bus_if | brcmf_bus* | Bus layer abstraction |
| proto | brcmf_proto* | Protocol layer (msgbuf or BCDC) |
| wiphy | wiphy* | cfg80211 wiphy |
| ops | cfg80211_ops* | Copy of cfg80211 operations |
| config | brcmf_cfg80211_info* | cfg80211 state |
| hdrlen | uint | Total protocol + bus header length |
| fwver | char[32] | Firmware version string |
| mac | u8[6] | Device MAC address |
| iflist | brcmf_if*[16] | Virtual interface array (by bsscfgidx) |
| if2bss | s32[16] | Mapping: ifidx → bsscfgidx (-1 = unmapped) |
| proto_block | mutex | Serializes FWIL operations |
| proto_buf | u8[8192] | Wire buffer for FWIL |
| fweh | brcmf_fweh_info* | Event handler state |
| feat_flags | u32 | Detected feature bitmask |
| chip_quirks | u32 | Chip quirk bitmask |
| settings | brcmf_mp_device* | Module parameters |
| vops | brcmf_fwvid_ops* | Firmware vendor operations |

## Interface (`brcmf_if`)

One per virtual interface (up to 16).

| Field | Type | Purpose |
|-------|------|---------|
| drvr | brcmf_pub* | Parent device |
| vif | brcmf_cfg80211_vif* | cfg80211 VIF state |
| ndev | net_device* | Network device |
| ifidx | int | Firmware interface index |
| bsscfgidx | s32 | BSS configuration index |
| mac_addr | u8[6] | Interface MAC |
| netif_stop | u8 | Bitmask of stop reasons |
| pend_8021x_cnt | atomic_t | Outstanding 802.1X frames |
| pend_8021x_wait | wait_queue | Signaled when count reaches 0 |
| fwil_fwerr | bool | Return raw firmware errors |
| fws_desc | fws_mac_descriptor* | Firmware signaling state (SDIO) |

## Bus (`brcmf_bus`)

Abstraction over the physical bus.

| Field | Type | Purpose |
|-------|------|---------|
| bus_priv | union | Bus-private data (sdio/pcie/usb) |
| proto_type | enum | BCDC or MSGBUF |
| dev | device* | Kernel device |
| drvr | brcmf_pub* | Driver context |
| state | enum | DOWN or UP |
| maxctl | uint | Max control message size |
| chip | u32 | Chip ID |
| chiprev | u32 | Chip revision |
| fwvid | enum | Firmware vendor (WCC/CYW/BCA) |
| wowl_supported | bool | WOWL capable |
| ops | brcmf_bus_ops* | Bus callbacks |
| msgbuf | brcmf_bus_msgbuf* | Ring info (PCIe only) |

### Bus ops

| Callback | Purpose |
|----------|---------|
| preinit | Bus-specific post-firmware-load init |
| stop | Tear down bus communication |
| txdata | Send data frame |
| txctl | Send control message |
| rxctl | Receive control response |
| wowl_config | Configure WOWL |
| get_ramsize | Query device RAM size |
| get_memdump | Dump device memory |
| get_blob | Retrieve firmware blob (CLM, txcap) |
| reset | Reset device and re-probe |

## Protocol (`brcmf_proto`)

Protocol abstraction layer with callback table:

| Callback | Purpose |
|----------|---------|
| hdrpull | Strip protocol headers from RX frame |
| query_dcmd | Send get command to firmware |
| set_dcmd | Send set command to firmware |
| tx_queue_data | Queue data frame for TX |
| configure_addr_mode | Configure address mode for interface |
| delete_peer | Remove peer from flow rings |
| add_tdls_peer | Add TDLS peer |
| rxreorder | Handle AMPDU reorder |
| add_if | Protocol-layer interface add |
| del_if | Protocol-layer interface remove |
| reset_if | Protocol-layer interface reset |
| init_done | Post-attach initialization |

`pd` is a void pointer to protocol-specific private data (msgbuf or BCDC context).

## cfg80211 state (`brcmf_cfg80211_info`)

| Field | Type | Purpose |
|-------|------|---------|
| wiphy | wiphy* | Wireless PHY |
| conf | brcmf_cfg80211_conf* | Thresholds (frag, RTS, retry) |
| p2p | brcmf_p2p_info | P2P state |
| scan_request | cfg80211_scan_request* | Active scan request |
| scan_status | unsigned long | Bitmask: BUSY, ABORT, SUPPRESS |
| channel | u32 | Current channel number |
| escan_info | escan_info | Escan state and buffer |
| vif_list | list_head | Linked list of VIFs |
| vif_event | brcmf_cfg80211_vif_event | VIF add/del event wait |
| wowl | brcmf_cfg80211_wowl | WOWL state |
| pno | brcmf_pno_info* | PNO state |
| pub | brcmf_pub* | Back-pointer to driver |
| d11inf | brcmu_d11inf | Channel encoding helpers |
| ac_priority | u8[8] | 802.1D → AC mapping |

## VIF state (`brcmf_cfg80211_vif`)

| Field | Type | Purpose |
|-------|------|---------|
| ifp | brcmf_if* | Lower-layer interface |
| wdev | wireless_dev | cfg80211 wireless device |
| profile | brcmf_cfg80211_profile | Connection profile |
| sme_state | unsigned long | Status bits (READY, CONNECTING, CONNECTED, etc.) |
| saved_ie | vif_saved_ie | Vendor IEs per frame type |
| mgmt_tx | completion | Management TX completion |
| mgmt_rx_reg | u16 | Registered management frame types |
| cqm_rssi_low | s32 | CQM low threshold |
| cqm_rssi_high | s32 | CQM high threshold |
| cqm_rssi_last | s32 | Last reported RSSI |

## Connection profile (`brcmf_cfg80211_profile`)

| Field | Type | Purpose |
|-------|------|---------|
| bssid | u8[6] | Associated BSSID |
| sec | brcmf_cfg80211_security | WPA version, auth type, ciphers |
| key | brcmf_wsec_key[6] | Cached keys |
| use_fwsup | enum | Firmware supplicant mode (NONE/PSK/1X/SAE) |
| use_fwauth | u16 | Firmware authenticator mode |
| is_ft | bool | Fast transition in progress |

## VIF status bits

| Bit | Name | Meaning |
|-----|------|---------|
| 0 | READY | Interface is ready |
| 1 | CONNECTING | Association in progress |
| 2 | CONNECTED | Associated |
| 3 | DISCONNECTING | Disassociation in progress |
| 4 | AP_CREATED | AP mode active |
| 5 | EAP_SUCCESS | EAPOL handshake completed |
| 6 | ASSOC_SUCCESS | SET_SSID event received with success |

## Chip info (`brcmf_chip`)

| Field | Type | Purpose |
|-------|------|---------|
| chip | u32 | Chip ID |
| chiprev | u32 | Chip revision |
| enum_base | u32 | Enumeration ROM base address |
| cc_caps | u32 | ChipCommon capabilities |
| pmucaps | u32 | PMU capabilities |
| pmurev | u32 | PMU revision |
| rambase | u32 | RAM base address |
| ramsize | u32 | Total RAM (including retention) |
| srsize | u32 | Save-restore (retention) RAM |

## Core info (`brcmf_core`)

| Field | Type | Purpose |
|-------|------|---------|
| id | u16 | Core ID (BCMA constant) |
| rev | u16 | Core revision |
| base | u32 | Core register base address |

## Commonring

Circular buffer abstraction used by msgbuf.

| Field | Type | Purpose |
|-------|------|---------|
| r_ptr | u16 | Read pointer |
| w_ptr | u16 | Write pointer |
| f_ptr | u16 | Flush pointer |
| depth | u16 | Ring capacity |
| item_len | u16 | Per-entry byte size |
| buf_addr | void* | DMA buffer base |
| outstanding_tx | atomic_t | Pending TX count |
| lock | spinlock | Ring access serialization |
| was_full | bool | Hysteresis for full detection |

Callbacks: `ring_bell`, `update_rptr`, `update_wptr`, `write_rptr`, `write_wptr`.

## Flow ring

Flow rings manage per-flow TX queues. Each flow is identified by `(destination_mac, priority, ifidx)`.

| Concept | Detail |
|---------|--------|
| Hash table | 512 entries (must be power of 2), mapping MAC+priority to flow ID |
| Ring states | CLOSED, OPEN, CLOSING |
| Software queue | sk_buff queue per ring for buffering before DMA submission |
| Address modes | INDIRECT (default, per-peer rings) or DIRECT (single ring per interface, for AP/P2P-GO) |

## Event handler (`brcmf_fweh_info`)

| Field | Type | Purpose |
|-------|------|---------|
| event_work | work_struct | Worker for event dispatch |
| event_q | list_head | Queue of pending events |
| event_q_lock | spinlock | Queue serialization |
| evt_handler[] | function pointers | Per-event-code handler table |
| num_event_codes | u32 | Size of handler table |

## Module parameters (`brcmf_mp_device`)

Per-device parameters from module options, device tree, or ACPI:

| Field | Type | Purpose |
|-------|------|---------|
| p2pon | bool | Enable P2P |
| feature_disable | u32 | Force-disable feature bits |
| fcmode | int | Flow control mode |
| roamoff | bool | Disable firmware roaming |
| iapp | bool | IAPP support |
| board_type | char* | Board type string for firmware selection |
| antenna_sku | char* | Antenna SKU (Apple platforms) |
| country_codes | brcmf_country* | Country code mappings |
