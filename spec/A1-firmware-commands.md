# Appendix: Firmware Command Reference

## Overview

This document lists firmware direct commands (dcmd codes) and IOVARs used by the driver. Direct commands are numeric; IOVARs are string-named variables accessed through `C_GET_VAR` (262) / `C_SET_VAR` (263).

All integer values are little-endian on the wire.

## Direct commands

| Code | Name | Direction | Payload | Purpose |
|------|------|-----------|---------|---------|
| 1 | `C_GET_VERSION` | get | u32 | Firmware version |
| 2 | `C_UP` | set | none | Bring interface up |
| 3 | `C_DOWN` | set | none | Bring interface down |
| 10 | `C_SET_PROMISC` | set | u32 (bool) | Promiscuous mode |
| 12 | `C_GET_RATE` | get | u32 | Current TX rate |
| 19 | `C_GET_INFRA` | get | u32 | Infrastructure mode |
| 20 | `C_SET_INFRA` | set | u32 | Set infrastructure (1) vs IBSS (0) |
| 22 | `C_SET_AUTH` | set | u32 | Authentication type (0=open, 1=shared) |
| 23 | `C_GET_BSSID` | get | 6 bytes | Current BSSID |
| 25 | `C_GET_SSID` | get | ssid_le | Current SSID |
| 26 | `C_SET_SSID` | set | join_params | Associate (SET_SSID method) |
| 29 | `C_GET_CHANNEL` | get | u32 | Current channel |
| 30 | `C_SET_CHANNEL` | set | u32 | Set channel |
| 31 | `C_GET_SRL` | get | u32 | Short retry limit |
| 32 | `C_SET_SRL` | set | u32 | Set short retry limit |
| 33 | `C_GET_LRL` | get | u32 | Long retry limit |
| 34 | `C_SET_LRL` | set | u32 | Set long retry limit |
| 37 | `C_GET_RADIO` | get | u32 | Radio state |
| 45 | `C_SET_KEY` | set | wsec_key_le | Install key |
| 49 | `C_SET_PASSIVE_SCAN` | set | u32 | Passive scan mode |
| 50 | `C_SCAN` | set | scan_params | Initiate basic scan |
| 52 | `C_DISASSOC` | set | scb_val_le | Disassociate |
| 55 | `C_SET_ROAM_TRIGGER` | set | s32 | Roam trigger RSSI |
| 57 | `C_SET_ROAM_DELTA` | set | u32 | Roam RSSI delta |
| 75 | `C_GET_BCNPRD` | get | u32 | Beacon period |
| 76 | `C_SET_BCNPRD` | set | u32 | Set beacon period |
| 77 | `C_GET_DTIMPRD` | get | u32 | DTIM period |
| 78 | `C_SET_DTIMPRD` | set | u32 | Set DTIM period |
| 84 | `C_SET_COUNTRY` | set | country_le | Set country code |
| 85 | `C_GET_PM` | get | u32 | Power management mode |
| 86 | `C_SET_PM` | set | u32 | Set PM (0=off, 1=on, 2=fast) |
| 98 | `C_GET_REVINFO` | get | rev_info_le | Hardware/firmware revision |
| 107 | `C_GET_MONITOR` | get | u32 | Monitor mode state |
| 108 | `C_SET_MONITOR` | set | u32 | Set monitor mode |
| 114 | `C_GET_CURR_RATESET` | get | rateset_le | Current rate set |
| 117 | `C_GET_AP` | get | u32 | AP mode state |
| 118 | `C_SET_AP` | set | u32 | Enable (1) / disable (0) AP |
| 121 | `C_SET_SCB_AUTHORIZE` | set | ea (6 bytes) | Authorize STA |
| 122 | `C_SET_SCB_DEAUTHORIZE` | set | ea (6 bytes) | Deauthorize STA |
| 127 | `C_GET_RSSI` | get | scb_val_le | RSSI (signed, dBm) |
| 133 | `C_GET_WSEC` | get | u32 | Security flags |
| 134 | `C_SET_WSEC` | set | u32 | Set security flags |
| 135 | `C_GET_PHY_NOISE` | get | s32 | PHY noise floor |
| 136 | `C_GET_BSS_INFO` | get | bss_info_le | Current BSS info |
| 140 | `C_GET_BANDLIST` | get | u32[] | Supported bands |
| 158 | `C_SET_SCB_TIMEOUT` | set | u32 | Client timeout |
| 159 | `C_GET_ASSOCLIST` | get | assoclist_le | Associated clients |
| 185 | `C_SET_SCAN_CHANNEL_TIME` | set | u32 | Active scan dwell time |
| 187 | `C_SET_SCAN_UNASSOC_TIME` | set | u32 | Unassociated scan time |
| 201 | `C_SCB_DEAUTHENTICATE_FOR_REASON` | set | scb_val_le | Deauth client with reason |
| 217 | `C_GET_VALID_CHANNELS` | get | chanspec_list | Valid channels |
| 235 | `C_GET_KEY_PRIMARY` | get | u32 | Primary key index |
| 236 | `C_SET_KEY_PRIMARY` | set | u32 | Set primary key index |
| 258 | `C_SET_SCAN_PASSIVE_TIME` | set | u32 | Passive scan dwell time |
| 262 | `C_GET_VAR` | get | name+data | Get IOVAR |
| 263 | `C_SET_VAR` | set | name+data | Set IOVAR |
| 268 | `C_SET_WSEC_PMK` | set | wsec_pmk_le | Set PMK |

## IOVARs

### General

| Name | Type | Direction | Purpose |
|------|------|-----------|---------|
| `ver` | string | get | Firmware version string |
| `cap` | string | get | Firmware capability string |
| `cur_etheraddr` | 6 bytes | get/set | MAC address |
| `clmver` | string | get | CLM version |
| `revinfo` | rev_info_le | get | Revision info |
| `bus:txglomalign` | u32 | set | SDIO TX glom alignment |
| `bus:txglomsize` | u32 | set | SDIO TX glom size |

### Scan

| Name | Type | Direction | Purpose |
|------|------|-----------|---------|
| `escan` | escan_params_le | set | Start/abort enhanced scan |
| `scan_ver` | u32 | get | Scan parameter version |
| `scanmac_enable` | u32 | set | Enable scan MAC randomization |
| `scanmac_config` | struct | set | Configure randomized MAC |

### Security

| Name | Type | Direction | Purpose |
|------|------|-----------|---------|
| `wsec` | u32 | get/set | Wireless security flags |
| `wpa_auth` | u32 | get/set | WPA authentication mode |
| `wsec_key` | wsec_key_le | set | Install encryption key |
| `sup_wpa` | u32 | set | Enable firmware WPA supplicant |
| `wpaie` | raw IE | set | WPA/RSN information element |
| `mfp` | u32 | set | Management frame protection mode |
| `sae_password` | sae_pwd_le | set | SAE password |
| `pmkid_info` | pmk_list | set | PMKID cache |

### Connection

| Name | Type | Direction | Purpose |
|------|------|-----------|---------|
| `join` | ext_join_params_le | set | Extended join (BSS-config scoped) |
| `join_pref` | join_pref_params[] | set | Join selection preference |
| `assoc_info` | raw | get | Association info |
| `assoc_resp_ies` | raw | get | Association response IEs |

### Interface

| Name | Type | Direction | Purpose |
|------|------|-----------|---------|
| `bss` | bss_enable_le | set | Enable/disable BSS |
| `interface_create` | p2p_if_le | set | Create virtual interface |
| `interface_remove` | none | set | Remove virtual interface |
| `ssid` | mbss_ssid_le | set | Set BSS SSID |

### Power and offload

| Name | Type | Direction | Purpose |
|------|------|-----------|---------|
| `mpc` | u32 | set | Minimum Power Consumption mode |
| `arp_ol` | u32 | set | ARP offload mode |
| `arpoe` | u32 | set | ARP offload enable |
| `ndoe` | u32 | set | ND offload enable |
| `nd_hostip` | ipv6 addr | set | Host IPv6 for ND offload |
| `pfn` | u32 | get | PNO supported |

### AP mode

| Name | Type | Direction | Purpose |
|------|------|-----------|---------|
| `closednet` | u32 | set | Hidden SSID |
| `bss_max_assoc` | u32 | set | Max associated clients |
| `wme_ac_sta` | edcf_acparam | set | WMM parameters for STA |
| `wme_ac_ap` | edcf_acparam | set | WMM parameters for AP |

### TDLS

| Name | Type | Direction | Purpose |
|------|------|-----------|---------|
| `tdls_enable` | u32 | set | Enable TDLS |
| `tdls_endpoint` | tdls_iovar_le | set | TDLS peer operations |

### Event

| Name | Type | Direction | Purpose |
|------|------|-----------|---------|
| `event_msgs` | bitmask | set | Enable/disable firmware events |
| `event_msgs_ext` | bitmask | set | Extended event enable (vendor) |

### Monitor

| Name | Type | Direction | Purpose |
|------|------|-----------|---------|
| `monitor` | u32 | set | Monitor mode |
| `allmulti` | u32 | set | All-multicast |
| `mcast_list` | mac list | set | Multicast filter list |

### Firmware download

| Name | Type | Direction | Purpose |
|------|------|-----------|---------|
| `clmload` | dload_data_le | set | Load CLM blob (chunked) |
| `txcapload` | dload_data_le | set | Load TX cap blob (chunked) |
| `clmload_status` | u32 | get | CLM load status |
| `txcapload_status` | u32 | get | TX cap load status |

#### Chunked download protocol

CLM and TX cap blobs are sent via `dload_data_le`:

| Offset | Size | Field |
|--------|------|-------|
| 0 | 2 | flag (LE) |
| 2 | 2 | dload_type (LE), always 2 (`DL_TYPE_CLM`) |
| 4 | 4 | len (LE), chunk data length |
| 8 | 4 | crc (LE), always 0 |
| 12 | N | data (up to 1400 bytes per chunk) |

Flag bits: `DL_BEGIN = 0x0002` (first chunk), `DL_END = 0x0004` (last chunk), version `1 << 12` always ORed in. A single-chunk blob uses `DL_BEGIN | DL_END`. Multi-chunk: first chunk has `DL_BEGIN`, last has `DL_END`, middle chunks have neither.

After all chunks are sent, read `clmload_status` (or `txcapload_status`) to verify success.

### Flow control (SDIO fwsignal)

| Name | Type | Direction | Purpose |
|------|------|-----------|---------|
| `tlv` | u32 | get/set | Enable TLV signaling |
| `tdls_peer_addr` | mac | get | TDLS peer for signaling |

### RSSI

| Name | Type | Direction | Purpose |
|------|------|-----------|---------|
| `rssi_event` | rssi_event_le | set | RSSI event thresholds |

### WOWL (Wake on WLAN)

| Name | Type | Direction | Purpose |
|------|------|-----------|---------|
| `wowl` | u32 | set | WOWL feature flags |
| `wowl_activate` | u32 | set | Activate WOWL |
| `wowl_clear` | u32 | set | Clear WOWL |
| `wowl_pattern` | wowl_pattern_le | set | Add/del/clear patterns |
| `wowl_wakeind` | wowl_wakeind_le | get | Wake indication |
| `pfn_add` | pno_net_param_le | set | Add PNO network |
| `pfn_cfg` | pno_config_le | set | PNO channel config |
| `pfn_set` | pno_param_le | set | PNO scan parameters |
| `pfn_macaddr` | pno_macaddr_le | set | PNO MAC randomization |

### Regulatory

| Name | Type | Direction | Purpose |
|------|------|-----------|---------|
| `country` | country_le | get/set | Country code |
| `roam_off` | u32 | set | Disable firmware roaming |

## Security flag bitmask (`wsec`)

| Bit | Value | Meaning |
|-----|-------|---------|
| WEP | 0x01 | WEP enabled |
| TKIP | 0x02 | TKIP enabled |
| AES | 0x04 | AES-CCMP enabled |
| FIPS | 0x80 | FIPS mode |

## WPA auth bitmask (`wpa_auth`)

| Value | Meaning |
|-------|---------|
| 0x0000 | Disabled (legacy, non-WPA) |
| 0x0001 | WPA-NONE (IBSS) |
| 0x0002 | WPA-unspecified (802.1X) |
| 0x0004 | WPA-PSK |
| 0x0020 | Reserved (802.1X related) |
| 0x0040 | WPA2-unspecified (802.1X) |
| 0x0080 | WPA2-PSK |
| 0x1000 | WPA2-802.1X-SHA256 |
| 0x4000 | FT modifier (ORed with base auth type) |
| 0x8000 | WPA2-PSK-SHA256 |
| 0x40000 | WPA3-SAE-PSK |

FT (Fast BSS Transition) is not a standalone auth mode. `0x4000` is ORed with the base auth value to form FT variants: FT-PSK = `0x0080 | 0x4000`, FT-1X = `0x0040 | 0x4000`, FT-SAE = `0x40000 | 0x4000`.

## Crypto algorithm codes

| Code | Name | Key length |
|------|------|-----------|
| 0 | CRYPTO_ALGO_OFF | — |
| 1 | CRYPTO_ALGO_WEP1 | 5 (WEP-40) |
| 2 | CRYPTO_ALGO_TKIP | 32 |
| 3 | CRYPTO_ALGO_WEP128 | 13 (WEP-104) |
| 4 | CRYPTO_ALGO_AES_CCM | 16 |
| 5 | CRYPTO_ALGO_AES_RESERVED1 | — |
| 6 | CRYPTO_ALGO_AES_RESERVED2 | — |
| 11 | CRYPTO_ALGO_AES_GCM | — |
| 12 | CRYPTO_ALGO_AES_GCM256 | — |
