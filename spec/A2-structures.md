# Appendix: Firmware Structures Reference

## Overview

This appendix documents the binary structures exchanged between host and firmware. All multi-byte fields are little-endian unless explicitly noted. Event message fields are big-endian (see [06-event-handling.md](06-event-handling.md)).

## BSS info (`brcmf_bss_info_le`)

Variable-length structure returned by `C_GET_BSS_INFO` and escan results.
The structure uses natural alignment (not packed). The compiler inserts padding
after variable-length fields and before fields that require stricter alignment.

| Offset | Size | Field | Notes |
|--------|------|-------|-------|
| 0 | 4 | version | LE, expected: 109 |
| 4 | 4 | length | LE, total length including IEs |
| 8 | 6 | BSSID | |
| 14 | 2 | beacon_period | LE, Kusec |
| 16 | 2 | capability | LE, 802.11 capability bits |
| 18 | 1 | SSID_len | |
| 19 | 32 | SSID | |
| 51 | 1 | (padding) | Alignment to 4 for rateset.count |
| 52 | 4 | rateset.count | LE |
| 56 | 16 | rateset.rates | 500 kbps units, hi bit = basic |
| 72 | 2 | chanspec | LE, Broadcom channel spec |
| 74 | 2 | atim_window | LE |
| 76 | 1 | dtim_period | |
| 77 | 1 | (padding) | Alignment to 2 for RSSI |
| 78 | 2 | RSSI | LE, signed, dBm |
| 80 | 1 | phy_noise | Signed, dBm |
| 81 | 1 | n_cap | 802.11n capable |
| 82 | 2 | (padding) | Alignment to 4 for nbss_cap |
| 84 | 4 | nbss_cap | LE, HT capabilities |
| 88 | 1 | ctl_ch | Control channel |
| 89 | 3 | (padding) | Alignment to 4 for reserved32 |
| 92 | 4 | reserved32 | |
| 96 | 1 | flags | `RSSI_ON_CHANNEL = 0x04` |
| 97 | 3 | reserved | |
| 100 | 16 | basic_mcs | Required MCS set |
| 116 | 2 | ie_offset | LE, offset of IEs from struct start |
| 118 | 2 | (padding) | Alignment to 4 for ie_length |
| 120 | 4 | ie_length | LE, IE byte count |
| 124 | 2 | SNR | LE |
| 126 | 2 | (trailing pad) | Structure size 128 bytes |

IEs start at `struct_start + ie_offset`.

## Escan result (`brcmf_escan_result_le`)

| Offset | Size | Field | Endianness |
|--------|------|-------|------------|
| 0 | 4 | buflen | LE |
| 4 | 4 | version | LE |
| 8 | 2 | sync_id | LE |
| 10 | 2 | bss_count | LE |
| 12 | var | bss_info_le[0] | |

## Escan parameters (`brcmf_escan_params_le`)

| Field | Size | Notes |
|-------|------|-------|
| version | 4 | 1 (v1) or 2 (v2) |
| action | 2 | 1=start, 2=continue, 3=abort |
| sync_id | 2 | Random, matched in results |
| scan_params | var | v1 or v2 scan params |

### Scan params v1 (`brcmf_scan_params_le`)

Fixed size: 64 bytes before variable-length data.

| Field | Size | Notes |
|-------|------|-------|
| ssid_le | 36 | SSID length + 32-byte SSID |
| bssid | 6 | Broadcast for wildcard |
| bss_type | 1 | 2 = any |
| scan_type | 1 | 0xFF = default |
| nprobes | 4 | -1 = default |
| active_time | 4 | -1 = default |
| passive_time | 4 | -1 = default |
| home_time | 4 | -1 = default |
| channel_num | 4 | Low 16: channel count, high 16: SSID count |
| channel_list[] | 2 each | Chanspecs |

SSIDs follow the channel list, 4-byte aligned.

### Scan params v2 (`brcmf_scan_params_v2_le`)

Fixed size: 72 bytes. Adds a version (2) and length field at the start. `scan_type` is 32-bit instead of 8-bit.

## Extended join parameters (`brcmf_ext_join_params_le`)

| Field | Size | Notes |
|-------|------|-------|
| ssid_le | 36 | Target SSID |
| scan_le | 17 | Join scan parameters |
| assoc_le | 10+ | Association parameters |

### Join scan params

| Field | Size |
|-------|------|
| scan_type | 1 | (0xFF = default)
| nprobes | 4 |
| active_time | 4 |
| passive_time | 4 |
| home_time | 4 |

### Association params

| Field | Size |
|-------|------|
| bssid | 6 | (broadcast for any)
| chanspec_num | 4 |
| chanspec_list[] | 2 each |

## Key structure (`brcmf_wsec_key_le`)

Total size: 164 bytes (natural alignment).

| Field | Size | Notes |
|-------|------|-------|
| index | 4 | Key slot (0-5) |
| len | 4 | Key data length |
| data | 32 | Key material (WLAN_MAX_KEY_LEN) |
| pad_1 | 72 | Reserved (18 × u32) |
| algo | 4 | Crypto algorithm code |
| flags | 4 | `PRIMARY = 0x02` for TX key |
| pad_2 | 12 | Reserved |
| iv_initialized | 4 | |
| pad_3 | 4 | |
| rxiv.hi | 4 | Upper IV |
| rxiv.lo | 2 | Lower IV |
| pad_4 | 8 | Reserved |
| ea | 6 | Peer MAC (pairwise) or zero (group) |

## PMK structure (`brcmf_wsec_pmk_le`)

| Field | Size | Notes |
|-------|------|-------|
| key_len | 2 | Octets in key |
| flags | 2 | `PASSPHRASE = 0x01` |
| key | 128 | PMK or passphrase data |

## SAE password (`brcmf_wsec_sae_pwd_le`)

| Field | Size |
|-------|------|
| key_len | 2 |
| key | 128 |

## Country (`brcmf_fil_country_le`)

| Field | Size | Notes |
|-------|------|-------|
| country_abbrev | 4 | NUL-terminated country code |
| rev | 4 | Revision (-1 = unspecified) |
| ccode | 4 | Built-in country code |

## STA info (`brcmf_sta_info_le`)

Variable-length, versioned structure. Key fields:

| Field | Version | Notes |
|-------|---------|-------|
| ver | all | Structure version |
| len | all | Structure length |
| cap | all | Capabilities |
| flags | all | STA flags (BRCM, WME, AUTHE, ASSOC, AUTHO, etc.) |
| idle | all | Seconds since last data packet |
| ea | all | Station MAC |
| in | all | Seconds since association |
| tx_pkts | >= 3 | TX packet count |
| rx_ucast_pkts | >= 3 | RX unicast count |
| tx_rate | >= 3 | Last TX rate |
| rx_rate | >= 3 | Last RX rate |
| rssi[] | >= 4 | Per-antenna RSSI (up to 4) |

## Event message (`brcmf_event_msg`)

Carried inside Ethernet frames. All fields big-endian.

| Field | Size | Notes |
|-------|------|-------|
| version | 2 | |
| flags | 2 | LINK, FLUSHTXQ, GROUP |
| event_type | 4 | Event code |
| status | 4 | Status/result code |
| reason | 4 | Reason code |
| auth_type | 4 | |
| datalen | 4 | Payload length after this header |
| addr | 6 | Peer MAC |
| ifname | 16 | Interface name |
| ifidx | 1 | Interface index |
| bsscfgidx | 1 | BSS config index |

Preceded in the Ethernet frame by:
- Ethernet header with `ETH_P_LINK_CTL` (0x886c)
- Broadcom OUI (00:10:18)
- User subtype (1)

## Action frame (`brcmf_fil_af_params_le`)

| Field | Size |
|-------|------|
| channel | 4 |
| dwell_time | 4 |
| bssid | 6 |
| pad | 2 |
| action_frame.da | 6 |
| action_frame.len | 2 |
| action_frame.packet_id | 4 |
| action_frame.data | 1800 |

## Join preference (`brcmf_join_pref_params`)

4 bytes per entry:

| Field | Size | Notes |
|-------|------|-------|
| type | 1 | 1=RSSI, 2=WPA, 3=BAND, 4=RSSI_DELTA |
| len | 1 | Always 2 |
| rssi_gain | 1 | For RSSI_DELTA type |
| band | 1 | For BAND or RSSI_DELTA type |

## DMA buffer address (`msgbuf_buf_addr`)

8-byte structure used in msgbuf messages:

| Field | Size |
|-------|------|
| low_addr | 4 |
| high_addr | 4 |

## RSSI event (`brcmf_rssi_event_le`)

| Field | Size | Notes |
|-------|------|-------|
| rate_limit_msec | 4 | Rate limit for events |
| rssi_level_num | 1 | Number of threshold levels |
| rssi_levels | 8 | Threshold values (signed, ascending) |

## Chanspec encoding

Broadcom chanspecs encode channel, band, bandwidth, and sideband in a 16-bit value. Two encodings exist, selected by the D11 core revision. The driver determines the encoding at init time and installs matching encode/decode functions in the `d11inf` structure.

### D11N encoding (older chips, e.g. BCM43455)

Used when `io_type = 1` (D11N).

| Bits | Field | Values |
|------|-------|--------|
| 7:0 | Channel number | |
| 9:8 | CTL sideband | Lower=0x1, Upper=0x2, None=0x3 |
| 11:10 | Bandwidth | 10=0x1, 20=0x2, 40=0x3 |
| 13:12 | Band | 5G=0x1, 2G=0x2 |
| 15:14 | Unused | |

### D11AC encoding (modern chips, e.g. BCM4350)

Used when `io_type = 2` (D11AC).

| Bits | Field | Values |
|------|-------|--------|
| 7:0 | Channel number | For 80+80: low nibble=low ch, high nibble=high ch |
| 10:8 | CTL sideband | LLL=0x0 through UUU=0x7 |
| 13:11 | Bandwidth | 5=0x0, 10=0x1, 20=0x2, 40=0x3, 80=0x4, 160=0x5, 80+80=0x6 |
| 15:14 | Band | 2G=0x0, 3G=0x1, 4G=0x2, 5G=0x3 |

The D11 core revision (from backplane enumeration) determines which encoding the firmware uses. The driver's `brcmu_d11_attach` selects the appropriate encoder/decoder.
