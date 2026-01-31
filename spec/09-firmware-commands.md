# Firmware Command Reference

## Overview

This document provides detailed information about key firmware commands and IOVARs used by the driver.

## Initialization commands

### BRCMF_C_UP (2) - Bring interface up

```c
brcmf_fil_cmd_int_set(ifp, BRCMF_C_UP, 0);
```

In the Linux driver, `BRCMF_C_UP` is used with value 0 during `brcmf_config_dongle()` (invoked by `brcmf_cfg80211_up()`), not during attach. `BRCMF_C_DOWN` is not used in `brcmf_cfg80211_down()`.

### BRCMF_C_SET_INFRA (20) - Set infrastructure mode

```c
brcmf_fil_cmd_int_set(ifp, BRCMF_C_SET_INFRA, 1);  // Infrastructure mode
brcmf_fil_cmd_int_set(ifp, BRCMF_C_SET_INFRA, 0);  // IBSS/ad-hoc mode
```

### BRCMF_C_SET_AP (118) - Set AP mode

```c
brcmf_fil_cmd_int_set(ifp, BRCMF_C_SET_AP, 1);  // Enable AP mode
brcmf_fil_cmd_int_set(ifp, BRCMF_C_SET_AP, 0);  // Disable AP mode
```

## Connection commands

### BRCMF_C_SET_SSID (26) - Connect to network

```c
struct brcmf_join_params {
    struct brcmf_ssid_le ssid_le;
    struct brcmf_assoc_params_le params_le;
};

struct brcmf_ssid_le {
    __le32 SSID_len;
    unsigned char SSID[32];
};

struct brcmf_assoc_params_le {
    u8 bssid[ETH_ALEN];
    __le32 chanspec_num;
    __le16 chanspec_list[];
};

// Usage:
join_params.ssid_le.SSID_len = cpu_to_le32(ssid_len);
memcpy(join_params.ssid_le.SSID, ssid, ssid_len);
memcpy(join_params.params_le.bssid, bssid, ETH_ALEN);  // Or broadcast for any
brcmf_fil_cmd_data_set(ifp, BRCMF_C_SET_SSID, &join_params, sizeof(join_params));
```

### BRCMF_C_DISASSOC (52) - Disconnect

```c
struct brcmf_scb_val_le {
    __le32 val;
    u8 ea[ETH_ALEN];
};

scbval.val = cpu_to_le32(reason_code);
memcpy(scbval.ea, bssid, ETH_ALEN);
brcmf_fil_cmd_data_set(ifp, BRCMF_C_DISASSOC, &scbval, sizeof(scbval));
```

### BRCMF_C_GET_BSSID (23) - Get current BSSID

```c
u8 bssid[ETH_ALEN];
brcmf_fil_cmd_data_get(ifp, BRCMF_C_GET_BSSID, bssid, ETH_ALEN);
```

### BRCMF_C_GET_SSID (25) - Get current SSID

```c
struct brcmf_ssid_le ssid;
brcmf_fil_cmd_data_get(ifp, BRCMF_C_GET_SSID, &ssid, sizeof(ssid));
```

## Security commands

### WSEC / WPA auth

The Linux driver primarily configures security via IOVARs:
- `wsec` (bitmask of cipher capabilities)
- `wpa_auth` (AKM suites)

`BRCMF_C_SET_WSEC` exists but is not the main path in `cfg80211.c` for association.

### BRCMF_C_SET_KEY (45) - Set encryption key

```c
struct brcmf_wsec_key {
    u32 index;                  // Key index (0-3 for group, 0 for pairwise)
    u32 len;                    // Key length
    u8 data[32];                // Key data
    u32 pad_1[18];
    u32 algo;                   // CRYPTO_ALGO_*
    u32 flags;                  // BRCMF_PRIMARY_KEY, etc.
    u32 pad_2[2];
    s32 iv_initialized;
    s32 pad_3;
    struct {
        u32 hi;
        u16 lo;
    } rxiv;
    u32 pad_4[2];
    u8 ea[ETH_ALEN];           // MAC address (for pairwise)
};

// Cipher algorithms
#define CRYPTO_ALGO_OFF         0
#define CRYPTO_ALGO_WEP1        1
#define CRYPTO_ALGO_TKIP        2
#define CRYPTO_ALGO_WEP128      3
#define CRYPTO_ALGO_AES_CCM     4
#define CRYPTO_ALGO_AES_GCM     5
#define CRYPTO_ALGO_AES_GCM256  6

brcmf_fil_bsscfg_data_set(ifp, "wsec_key", &key, sizeof(key));
```

### BRCMF_C_SET_WSEC_PMK (268) - Set PSK/PMK

```c
struct brcmf_wsec_pmk_le {
    __le16 key_len;
    __le16 flags;               // BRCMF_WSEC_PASSPHRASE for ASCII
    u8 key[64];
};

#define BRCMF_WSEC_MAX_PSK_LEN  64
#define BRCMF_WSEC_PASSPHRASE   BIT(0)

pmk.key_len = cpu_to_le16(psk_len);
pmk.flags = cpu_to_le16(BRCMF_WSEC_PASSPHRASE);
memcpy(pmk.key, passphrase, psk_len);
brcmf_fil_cmd_data_set(ifp, BRCMF_C_SET_WSEC_PMK, &pmk, sizeof(pmk));
```

## Scanning

### escan IOVAR - Enhanced scan

```c
struct brcmf_escan_params_le {
    __le32 version;
    __le16 action;              // WL_ESCAN_ACTION_START/CONTINUE/ABORT
    __le16 sync_id;
    struct brcmf_scan_params_le params;
};

#define WL_ESCAN_ACTION_START    1
#define WL_ESCAN_ACTION_CONTINUE 2
#define WL_ESCAN_ACTION_ABORT    3

#define BRCMF_ESCAN_REQ_VERSION  1

brcmf_fil_iovar_data_set(ifp, "escan", &params, sizeof(params));
```

Results delivered via `BRCMF_E_ESCAN_RESULT` events.

### BRCMF_C_SCAN (50) - Legacy scan

```c
brcmf_fil_cmd_data_set(ifp, BRCMF_C_SCAN, &params, sizeof(params));
```

Results via `BRCMF_E_SCAN_COMPLETE` event, then retrieved with `BRCMF_C_SCAN_RESULTS`.

## Power management

### BRCMF_C_SET_PM (86) - Set power mode

```c
#define PM_OFF          0   // No power save
#define PM_MAX          1   // Maximum power save
#define PM_FAST         2   // Fast power save

brcmf_fil_cmd_int_set(ifp, BRCMF_C_SET_PM, PM_FAST);
```

### mpc IOVAR - Minimum power consumption

```c
brcmf_fil_iovar_int_set(ifp, "mpc", 0);  // Disable MPC
brcmf_fil_iovar_int_set(ifp, "mpc", 1);  // Enable MPC
```

## Configuration IOVARs

### cur_etheraddr - Get/set MAC address

```c
u8 mac[ETH_ALEN];
brcmf_fil_iovar_data_get(ifp, "cur_etheraddr", mac, ETH_ALEN);
brcmf_fil_iovar_data_set(ifp, "cur_etheraddr", mac, ETH_ALEN);
```

### ver - Get firmware version

```c
char ver[256];
brcmf_fil_iovar_data_get(ifp, "ver", ver, sizeof(ver));
```

### country - Set country code

```c
struct brcmf_country_le {
    char country_abbrev[4];
    __le32 rev;
    char ccode[4];
};

country.country_abbrev = "US";
country.rev = cpu_to_le32(0);
country.ccode = "US";
brcmf_fil_iovar_data_set(ifp, "country", &country, sizeof(country));
```

### wpa_auth - Set WPA authentication mode

```c
#define WPA_AUTH_DISABLED    0x0000
#define WPA_AUTH_NONE        0x0001
#define WPA_AUTH_UNSPECIFIED 0x0002
#define WPA_AUTH_PSK         0x0004
#define WPA2_AUTH_UNSPECIFIED 0x0040
#define WPA2_AUTH_PSK        0x0080
#define WPA2_AUTH_1X_SHA256  0x1000
#define WPA2_AUTH_PSK_SHA256 0x8000
#define WPA3_AUTH_SAE_PSK    0x40000

brcmf_fil_bsscfg_int_set(ifp, "wpa_auth", WPA2_AUTH_PSK);
```

### sup_wpa - Enable firmware supplicant

```c
brcmf_fil_iovar_int_set(ifp, "sup_wpa", 1);  // Firmware handles 4-way handshake
```

### bss - BSS up/down

```c
struct brcmf_bss_info {
    __le32 bsscfgidx;
    __le32 up;
};

bss.bsscfgidx = cpu_to_le32(ifp->bsscfgidx);
bss.up = cpu_to_le32(1);  // or 0 for down
brcmf_fil_iovar_data_set(ifp, "bss", &bss, sizeof(bss));
```

### event_msgs - Enable firmware events

```c
u8 event_mask[16];  // Bitmask, one bit per event code
memset(event_mask, 0, sizeof(event_mask));
setbit(event_mask, BRCMF_E_LINK);
setbit(event_mask, BRCMF_E_SET_SSID);
setbit(event_mask, BRCMF_E_ESCAN_RESULT);
// ... etc

brcmf_fil_iovar_data_set(ifp, "event_msgs", event_mask, sizeof(event_mask));
```

### assoc_info - Get association info

```c
struct brcmf_cfg80211_assoc_ielen_le {
    __le32 req_len;
    __le32 resp_len;
};

brcmf_fil_iovar_data_get(ifp, "assoc_info", &assoc_info, sizeof(assoc_info));
// Then read assoc_req_ies and assoc_resp_ies
```

### chanspecs - Get available channels

```c
struct {
    __le32 count;
    __le32 chanspecs[256];
} chanlist;

brcmf_fil_iovar_data_get(ifp, "chanspecs", &chanlist, sizeof(chanlist));
```

## Radio control

### BRCMF_C_SET_RADIO (38) - Enable/disable radio

```c
brcmf_fil_cmd_int_set(ifp, BRCMF_C_SET_RADIO, 0);  // Radio on
brcmf_fil_cmd_int_set(ifp, BRCMF_C_SET_RADIO, 1);  // Radio off
```

### BRCMF_C_SET_CHANNEL (30) - Set channel

```c
brcmf_fil_cmd_int_set(ifp, BRCMF_C_SET_CHANNEL, channel_number);
```

### BRCMF_C_GET_CHANNEL (29) - Get current channel

```c
u32 channel;
brcmf_fil_cmd_int_get(ifp, BRCMF_C_GET_CHANNEL, &channel);
```

## Information queries

### BRCMF_C_GET_RSSI (127) - Get signal strength

```c
struct brcmf_scb_val_le scbval;
memcpy(scbval.ea, bssid, ETH_ALEN);
brcmf_fil_cmd_data_get(ifp, BRCMF_C_GET_RSSI, &scbval, sizeof(scbval));
// scbval.val contains RSSI in dBm (negative value)
```

### BRCMF_C_GET_RATE (12) - Get current TX rate

```c
u32 rate;
brcmf_fil_cmd_int_get(ifp, BRCMF_C_GET_RATE, &rate);
// rate in 500kbps units
```

### BRCMF_C_GET_BSS_INFO (136) - Get BSS info

```c
struct brcmf_bss_info_le {
    __le32 version;
    __le32 length;
    u8 BSSID[ETH_ALEN];
    __le16 beacon_period;
    __le16 capability;
    u8 SSID_len;
    u8 SSID[32];
    // ... many more fields
};

brcmf_fil_cmd_data_get(ifp, BRCMF_C_GET_BSS_INFO, buf, sizeof(buf));
```

### BRCMF_C_GET_REVINFO (98) - Get chip/firmware revision

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

brcmf_fil_cmd_data_get(ifp, BRCMF_C_GET_REVINFO, &revinfo, sizeof(revinfo));
```

## Offload configuration

### arp_ol / arpoe - ARP offload

```c
#define BRCMF_ARP_OL_AGENT           0x01
#define BRCMF_ARP_OL_SNOOP           0x02
#define BRCMF_ARP_OL_HOST_AUTO_REPLY 0x04
#define BRCMF_ARP_OL_PEER_AUTO_REPLY 0x08

brcmf_fil_iovar_int_set(ifp, "arp_ol", BRCMF_ARP_OL_AGENT | BRCMF_ARP_OL_PEER_AUTO_REPLY);
brcmf_fil_iovar_int_set(ifp, "arpoe", 1);  // Enable
```

### arp_hostip - Add IP for ARP offload

```c
__be32 ip_addr = inet_addr("192.168.1.100");
brcmf_fil_iovar_data_set(ifp, "arp_hostip", &ip_addr, sizeof(ip_addr));
```

### nd_hostip - Add IPv6 for neighbor discovery offload

```c
struct in6_addr ip6;
brcmf_fil_iovar_data_set(ifp, "nd_hostip", &ip6, sizeof(ip6));
```

## Monitor mode

### BRCMF_C_SET_MONITOR (108) - Enable monitor mode

```c
brcmf_fil_cmd_int_set(ifp, BRCMF_C_SET_MONITOR, 3);  // Enable
brcmf_fil_cmd_int_set(ifp, BRCMF_C_SET_MONITOR, 0);  // Disable
```
