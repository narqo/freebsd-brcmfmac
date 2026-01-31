# Firmware Structures Reference

## Scan structures

### brcmf_scan_params_le

```c
struct brcmf_scan_params_le {
    struct brcmf_ssid_le ssid_le;   // default: {0, ""}
    u8 bssid[ETH_ALEN];             // default: broadcast
    s8 bss_type;                    // DOT11_BSSTYPE_ANY/INFRA/INDEPENDENT
    u8 scan_type;                   // flags, 0=use default
    __le32 nprobes;                 // -1=use default
    __le32 active_time;             // -1=use default (ms)
    __le32 passive_time;            // -1=use default (ms)
    __le32 home_time;               // -1=use default (ms)
    __le32 channel_num;             // low half: channel count, high half: SSID count
    __le16 channel_list[];          // Chanspec list
};
```

### brcmf_ssid_le

```c
struct brcmf_ssid_le {
    __le32 SSID_len;                // 0-32
    unsigned char SSID[32];
};
```

### brcmf_escan_params_le

```c
struct brcmf_escan_params_le {
    __le32 version;                 // BRCMF_ESCAN_REQ_VERSION or _V2
    __le16 action;                  // START/CONTINUE/ABORT
    __le16 sync_id;                 // Sync ID for result matching
    union {
        struct brcmf_scan_params_le params_le;
        struct brcmf_scan_params_v2_le params_v2_le;
    };
};
```

### brcmf_scan_params_v2_le

```c
struct brcmf_scan_params_v2_le {
    __le16 version;                 // Structure version
    __le16 length;                  // Structure length
    struct brcmf_ssid_le ssid_le;
    u8 bssid[ETH_ALEN];
    s8 bss_type;
    u8 pad;
    __le32 scan_type;               // flags
    __le32 nprobes;
    __le32 active_time;
    __le32 passive_time;
    __le32 home_time;
    __le32 channel_num;             // low half: channel count, high half: SSID count
    __le16 channel_list[];          // Chanspec list
};
```

### brcmf_escan_result_le

Event data for BRCMF_E_ESCAN_RESULT:

```c
struct brcmf_escan_result_le {
    __le32 buflen;                  // Total buffer length
    __le32 version;
    __le16 sync_id;                 // Matches request sync_id
    __le16 bss_count;               // Number of BSS in results
    struct brcmf_bss_info_le bss_info_le; // First BSS (variable length)
};
```

### brcmf_bss_info_le

BSS information structure:

```c
struct brcmf_bss_info_le {
    __le32 version;
    __le32 length;                  // Total length including IEs
    u8 BSSID[ETH_ALEN];
    __le16 beacon_period;           // Kusec
    __le16 capability;
    u8 SSID_len;
    u8 SSID[32];
    struct {
        __le32 count;
        u8 rates[16];
    } rateset;
    __le16 chanspec;                // Channel spec
    __le16 atim_window;             // Kusec
    u8 dtim_period;                 // DTIM period
    __le16 RSSI;                    // Signal strength (dBm)
    s8 phy_noise;                   // Noise floor (dBm)
    u8 n_cap;                       // HT capable
    __le32 nbss_cap;                // BSS capabilities
    u8 ctl_ch;                      // Control channel
    __le32 reserved32[1];
    u8 flags;                       // BSS flags
    u8 reserved[3];
    u8 basic_mcs[16];               // Basic MCS set
    __le16 ie_offset;               // Offset to IEs from struct start
    __le32 ie_length;               // Length of IEs
    __le16 SNR;                     // Signal-to-noise ratio
    // IEs follow at ie_offset
};
```

## Connection structures

### brcmf_join_params

```c
struct brcmf_join_params {
    struct brcmf_ssid_le ssid_le;
    struct brcmf_assoc_params_le params_le;
};
```

### brcmf_assoc_params_le

```c
struct brcmf_assoc_params_le {
    u8 bssid[ETH_ALEN];             // Target BSSID (or broadcast)
    __le32 chanspec_num;            // Number of chanspecs
    __le16 chanspec_list[];         // Preferred channels
};
```

### brcmf_join_pref_params

```c
struct brcmf_join_pref_params {
    u8 type;                        // Preference type
    u8 len;                         // Length
    u8 rssi_gain;
    u8 band;
};

#define BRCMF_JOIN_PREF_RSSI    1
#define BRCMF_JOIN_PREF_WPA     2
#define BRCMF_JOIN_PREF_BAND    3
```

## Security structures

### brcmf_wsec_key

```c
struct brcmf_wsec_key {
    u32 index;                      // Key index
    u32 len;                        // Key length
    u8 data[32];                    // Key material
    u32 pad_1[18];
    u32 algo;                       // CRYPTO_ALGO_*
    u32 flags;                      // Key flags
    u32 pad_2[2];
    s32 iv_initialized;
    s32 pad_3;
    struct {
        u32 hi;
        u16 lo;
    } rxiv;                         // RX IV (for replay protection)
    u32 pad_4[2];
    u8 ea[ETH_ALEN];               // Peer MAC (for pairwise keys)
};

// Key flags
#define BRCMF_PRIMARY_KEY       (1 << 1)
```

### brcmf_wsec_pmk_le

```c
struct brcmf_wsec_pmk_le {
    __le16 key_len;                 // Key/passphrase length
    __le16 flags;                   // BRCMF_WSEC_PASSPHRASE if ASCII
    u8 key[BRCMF_WSEC_MAX_PSK_LEN]; // Key or passphrase
};

#define BRCMF_WSEC_MAX_PSK_LEN  64
#define BRCMF_WSEC_PASSPHRASE   (1 << 0)
```

## Event structures

### brcmf_event_msg

Host-format event message (after byte-swap):

```c
struct brcmf_event_msg {
    u16 version;
    u16 flags;                      // BRCMF_EVENT_MSG_*
    u32 event_code;                 // Event type
    u32 status;                     // Event status
    u32 reason;                     // Reason code
    s32 auth_type;
    u32 datalen;                    // Payload length
    u8 addr[ETH_ALEN];             // Source address
    char ifname[IFNAMSIZ];
    u8 ifidx;                       // Interface index
    u8 bsscfgidx;                   // BSS config index
};
```

### brcmf_if_event

Event data for BRCMF_E_IF:

```c
struct brcmf_if_event {
    u8 ifidx;                       // Interface index
    u8 action;                      // ADD/DEL/CHANGE
    u8 flags;                       // BRCMF_E_IF_FLAG_*
    u8 bsscfgidx;                   // BSS config index
    u8 role;                        // Interface role
};
```

## Channel specification

### Chanspec format

Chanspec is a 16-bit value encoding channel and bandwidth:

```
Bits 0-7:   Channel number
Bits 8-9:   Sideband (for 40MHz: lower/upper)
Bits 10-11: Bandwidth (20/40/80/160 MHz)
Bits 12-13: Band (2.4/5 GHz)
Bits 14-15: Reserved
```

```c
#define CHANSPEC_CHAN_MASK      0x00ff
#define CHANSPEC_BAND_MASK      0xc000
#define CHANSPEC_BAND_5G        0xc000
#define CHANSPEC_BAND_2G        0x0000
#define CHANSPEC_BW_MASK        0x3800
#define CHANSPEC_BW_20          0x1000
#define CHANSPEC_BW_40          0x1800
#define CHANSPEC_BW_80          0x2000
```

## Miscellaneous structures

### brcmf_scb_val_le

Station/value pair (used for RSSI, etc):

```c
struct brcmf_scb_val_le {
    __le32 val;
    u8 ea[ETH_ALEN];
};
```

### brcmf_country_le

Country code configuration:

```c
struct brcmf_country_le {
    char country_abbrev[4];         // Abbreviation (e.g., "US")
    __le32 rev;                     // Regulatory revision
    char ccode[4];                  // Country code (e.g., "US")
};
```

### brcmf_rev_info_le

Chip/firmware revision info:

```c
struct brcmf_rev_info_le {
    __le32 vendorid;
    __le32 deviceid;
    __le32 radiorev;
    __le32 corerev;
    __le32 boardid;
    __le32 boardvendor;
    __le32 boardrev;
    __le32 driverrev;
    __le32 ucoderev;
    __le32 bus;
    __le32 chipnum;
    __le32 phytype;
    __le32 phyrev;
    __le32 anarev;
    __le32 chippkg;
    __le32 nvramrev;
};
```

### brcmf_assoclist_le

Associated stations list (AP mode):

```c
struct brcmf_assoclist_le {
    __le32 count;
    u8 mac[BRCMF_MAX_ASSOCLIST][ETH_ALEN];
};

#define BRCMF_MAX_ASSOCLIST     128
```

## msgbuf ring structures

### msgbuf_buf_addr

64-bit DMA address:

```c
struct msgbuf_buf_addr {
    __le32 low_addr;
    __le32 high_addr;
};
```

### Message sizes

```c
// Control rings
#define BRCMF_H2D_MSGRING_CONTROL_SUBMIT_MAX_ITEM   64
#define BRCMF_D2H_MSGRING_CONTROL_COMPLETE_MAX_ITEM 64

// RX post ring
#define BRCMF_H2D_MSGRING_RXPOST_SUBMIT_MAX_ITEM    512

// Completion rings
#define BRCMF_D2H_MSGRING_TX_COMPLETE_MAX_ITEM      1024
#define BRCMF_D2H_MSGRING_RX_COMPLETE_MAX_ITEM      512

// Item sizes
#define BRCMF_H2D_MSGRING_CONTROL_SUBMIT_ITEMSIZE   40
#define BRCMF_H2D_MSGRING_RXPOST_SUBMIT_ITEMSIZE    32
#define BRCMF_D2H_MSGRING_CONTROL_COMPLETE_ITEMSIZE 24
#define BRCMF_D2H_MSGRING_TX_COMPLETE_ITEMSIZE      16
#define BRCMF_D2H_MSGRING_RX_COMPLETE_ITEMSIZE      32
```

## Endianness notes

All multi-byte fields in firmware structures are **little-endian**. Use:
- `cpu_to_le16()` / `le16_to_cpu()` for 16-bit
- `cpu_to_le32()` / `le32_to_cpu()` for 32-bit

Event messages (`brcmf_event_msg_be`) are the exception - they are **big-endian** as they arrive in Ethernet frames.
