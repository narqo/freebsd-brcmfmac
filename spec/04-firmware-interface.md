# Firmware Interface Layer (FWIL)

## Overview

FWIL (`fwil.c`) provides the API for sending commands and querying/setting variables in firmware. It sits between cfg80211 operations and the protocol layer.

## Command types

### Direct commands (dcmd)

Direct commands use numeric command codes. Set via `BRCMF_C_*` constants.

```c
s32 brcmf_fil_cmd_data_set(struct brcmf_if *ifp, u32 cmd, void *data, u32 len);
s32 brcmf_fil_cmd_data_get(struct brcmf_if *ifp, u32 cmd, void *data, u32 len);
s32 brcmf_fil_cmd_int_set(struct brcmf_if *ifp, u32 cmd, u32 data);
s32 brcmf_fil_cmd_int_get(struct brcmf_if *ifp, u32 cmd, u32 *data);
```

### IOVARs (named variables)

IOVARs use string names. Implemented via `BRCMF_C_GET_VAR` and `BRCMF_C_SET_VAR` commands.

```c
s32 brcmf_fil_iovar_data_set(struct brcmf_if *ifp, const char *name, const void *data, u32 len);
s32 brcmf_fil_iovar_data_get(struct brcmf_if *ifp, const char *name, void *data, u32 len);
s32 brcmf_fil_iovar_int_set(struct brcmf_if *ifp, const char *name, u32 data);
s32 brcmf_fil_iovar_int_get(struct brcmf_if *ifp, const char *name, u32 *data);
```

### BSS-config IOVARs

For multi-interface support, IOVARs can be addressed to specific BSS configurations:

```c
s32 brcmf_fil_bsscfg_data_set(struct brcmf_if *ifp, const char *name, void *data, u32 len);
s32 brcmf_fil_bsscfg_data_get(struct brcmf_if *ifp, const char *name, void *data, u32 len);
s32 brcmf_fil_bsscfg_int_set(struct brcmf_if *ifp, const char *name, u32 data);
s32 brcmf_fil_bsscfg_int_get(struct brcmf_if *ifp, const char *name, u32 *data);
```

### XTLV IOVARs

For IOVARs that use eXtended TLV encoding (name + XTLV header + data):

```c
s32 brcmf_fil_xtlv_data_set(struct brcmf_if *ifp, const char *name, u16 id, void *data, u32 len);
s32 brcmf_fil_xtlv_data_get(struct brcmf_if *ifp, const char *name, u16 id, void *data, u32 len);
```

Buffer format: `[name\0][xtlv_header][data]` where the XTLV header contains the `id`, length, and data, 32-bit aligned.

## Buffer encoding

### IOVAR format

```
[name\0][data]
```

```c
static u32 brcmf_create_iovar(const char *name, const char *data, u32 datalen,
                              char *buf, u32 buflen) {
    u32 len = strlen(name) + 1;
    memcpy(buf, name, len);
    if (data && datalen)
        memcpy(&buf[len], data, datalen);
    return len + datalen;
}
```

### BSS-config IOVAR format

```
bsscfg:[name\0][bsscfgidx_le32][data]
```

```c
static u32 brcmf_create_bsscfg(s32 bsscfgidx, const char *name, char *data, u32 datalen,
                               char *buf, u32 buflen) {
    if (bsscfgidx == 0)
        return brcmf_create_iovar(name, data, datalen, buf, buflen);

    static const char *prefix = "bsscfg:";
    // Copy prefix
    memcpy(buf, prefix, strlen(prefix));
    // Copy name with null
    memcpy(buf + strlen(prefix), name, strlen(name) + 1);
    // Add bsscfgidx
    __le32 idx_le = cpu_to_le32(bsscfgidx);
    memcpy(buf + strlen(prefix) + strlen(name) + 1, &idx_le, sizeof(idx_le));
    // Copy data
    memcpy(buf + strlen(prefix) + strlen(name) + 1 + sizeof(idx_le), data, datalen);
}
```

## Command execution

All commands go through `brcmf_fil_cmd_data()`:

```c
static s32 brcmf_fil_cmd_data(struct brcmf_if *ifp, u32 cmd, void *data, u32 len, bool set) {
    struct brcmf_pub *drvr = ifp->drvr;
    s32 err, fwerr;

    // Check bus state
    if (drvr->bus_if->state != BRCMF_BUS_UP)
        return -EIO;

    // Limit length
    len = min_t(uint, len, BRCMF_DCMD_MAXLEN);

    // Call protocol layer
    if (set)
        err = brcmf_proto_set_dcmd(drvr, ifp->ifidx, cmd, data, len, &fwerr);
    else
        err = brcmf_proto_query_dcmd(drvr, ifp->ifidx, cmd, data, len, &fwerr);

    // Handle firmware errors
    if (err == 0 && fwerr < 0) {
        err = -EBADE;
    }

    // If ifp->fwil_fwerr is set, return raw firmware error instead of -EBADE
    if (ifp->fwil_fwerr)
        return fwerr;

    return err;
}
```

## Common command codes

```c
#define BRCMF_C_GET_VERSION         1
#define BRCMF_C_UP                  2     // Bring interface up
#define BRCMF_C_DOWN                3     // Bring interface down
#define BRCMF_C_SET_PROMISC        10
#define BRCMF_C_GET_RATE           12
#define BRCMF_C_GET_INFRA          19
#define BRCMF_C_SET_INFRA          20     // Set infrastructure mode
#define BRCMF_C_GET_AUTH           21
#define BRCMF_C_SET_AUTH           22
#define BRCMF_C_GET_BSSID          23
#define BRCMF_C_GET_SSID           25
#define BRCMF_C_SET_SSID           26     // Connect to AP
#define BRCMF_C_TERMINATED         28
#define BRCMF_C_GET_CHANNEL        29
#define BRCMF_C_SET_CHANNEL        30
#define BRCMF_C_GET_SRL            31     // Short retry limit
#define BRCMF_C_SET_SRL            32
#define BRCMF_C_GET_LRL            33     // Long retry limit
#define BRCMF_C_SET_LRL            34
#define BRCMF_C_GET_RADIO          37
#define BRCMF_C_SET_RADIO          38
#define BRCMF_C_GET_PHYTYPE        39
#define BRCMF_C_SET_KEY            45     // Set WEP key
#define BRCMF_C_SET_PASSIVE_SCAN   49
#define BRCMF_C_SCAN               50     // Legacy scan
#define BRCMF_C_SCAN_RESULTS       51
#define BRCMF_C_DISASSOC           52     // Disassociate
#define BRCMF_C_REASSOC            53
#define BRCMF_C_SET_ROAM_TRIGGER   55
#define BRCMF_C_SET_ROAM_DELTA     57
#define BRCMF_C_SET_COUNTRY        84
#define BRCMF_C_GET_PM             85     // Power management
#define BRCMF_C_SET_PM             86
#define BRCMF_C_GET_REVINFO        98
#define BRCMF_C_GET_MONITOR       107
#define BRCMF_C_SET_MONITOR       108
#define BRCMF_C_GET_AP            117
#define BRCMF_C_SET_AP            118     // AP mode
#define BRCMF_C_GET_RSSI          127
#define BRCMF_C_GET_WSEC          133
#define BRCMF_C_SET_WSEC          134     // Security mode
#define BRCMF_C_GET_BSS_INFO      136
#define BRCMF_C_GET_BANDLIST      140
#define BRCMF_C_GET_ASSOCLIST     159
#define BRCMF_C_SET_SCAN_CHANNEL_TIME  185
#define BRCMF_C_GET_VALID_CHANNELS 217
#define BRCMF_C_GET_VAR           262     // Get IOVAR
#define BRCMF_C_SET_VAR           263     // Set IOVAR
#define BRCMF_C_SET_WSEC_PMK      268     // Set PSK
```

## Common IOVARs

### General

| IOVAR | Type | Description |
|-------|------|-------------|
| `ver` | string | Firmware version |
| `cur_etheraddr` | MAC | Current MAC address |
| `mpc` | int | Minimum power consumption mode |
| `ampdu_ba_wsize` | int | AMPDU BA window size |
| `arp_ol` | int | ARP offload mode |
| `arpoe` | int | ARP offload enable |
| `ndoe` | int | Neighbor discovery offload enable |

### Scan

| IOVAR | Type | Description |
|-------|------|-------------|
| `escan` | struct | Start enhanced scan |
| `scanresults` | struct | Get scan results |
| `scan_channel_time` | int | Dwell time per channel |

### Association

| IOVAR | Type | Description |
|-------|------|-------------|
| `bss` | int | BSS up/down |
| `ssid` | struct | SSID for connection |
| `assoc_info` | struct | Association info |
| `assoc_req_ies` | bytes | Association request IEs |
| `assoc_resp_ies` | bytes | Association response IEs |

### Security

| IOVAR | Type | Description |
|-------|------|-------------|
| `wsec` | int | Wireless security mode |
| `wpa_auth` | int | WPA authentication mode |
| `sup_wpa` | int | Firmware supplicant enable |
| `wsec_key` | struct | WEP/TKIP/AES key |
| `wsec_pmk` | struct | PMK for WPA-PSK |
| `mfp` | int | Management frame protection |

### Interface

| IOVAR | Type | Description |
|-------|------|-------------|
| `interface_create` | struct | Create virtual interface |
| `interface_remove` | int | Remove virtual interface |
| `p2p_ifadd` | struct | Add P2P interface |
| `p2p_ifdel` | struct | Delete P2P interface |

### Events

| IOVAR | Type | Description |
|-------|------|-------------|
| `event_msgs` | bytes | Event mask (which events to receive) |

### Offloads

| IOVAR | Type | Description |
|-------|------|-------------|
| `arp_hostip` | IP | Add ARP offload IP |
| `arp_hostip_clear` | none | Clear ARP offload IPs |
| `nd_hostip` | IPv6 | Add ND offload IP |
| `nd_hostip_clear` | none | Clear ND offload IPs |

## Firmware error codes

```c
#define BCME_OK                    0
#define BCME_ERROR                -1
#define BCME_BADARG               -2
#define BCME_BADOPTION            -3
#define BCME_NOTUP                -4
#define BCME_NOTDOWN              -5
#define BCME_NOTAP                -6
#define BCME_NOTSTA               -7
#define BCME_BADKEYIDX            -8
#define BCME_RADIOOFF             -9
#define BCME_NOTBANDLOCKED       -10
#define BCME_NOCLK               -11
#define BCME_BADRATESET          -12
#define BCME_BADBAND             -13
#define BCME_BUFTOOSHORT         -14
#define BCME_BUFTOOLONG          -15
#define BCME_BUSY                -16
#define BCME_NOTASSOCIATED       -17
#define BCME_BADSSIDLEN          -18
#define BCME_OUTOFRANGECHAN      -19
#define BCME_BADCHAN             -20
#define BCME_BADADDR             -21
#define BCME_NORESOURCE          -22
#define BCME_UNSUPPORTED         -23
#define BCME_BADLEN              -24
#define BCME_NOTREADY            -25
#define BCME_EPERM               -26
#define BCME_NOMEM               -27
#define BCME_ASSOCIATED          -28
#define BCME_RANGE               -29
#define BCME_NOTFOUND            -30
#define BCME_SCANREJECT          -43
```

## Thread safety

All FWIL operations are serialized via `drvr->proto_block` mutex:

```c
s32 brcmf_fil_iovar_data_set(struct brcmf_if *ifp, const char *name,
                             const void *data, u32 len) {
    mutex_lock(&drvr->proto_block);

    buflen = brcmf_create_iovar(name, data, len, drvr->proto_buf, sizeof(drvr->proto_buf));
    err = brcmf_fil_cmd_data(ifp, BRCMF_C_SET_VAR, drvr->proto_buf, buflen, true);

    mutex_unlock(&drvr->proto_block);
    return err;
}
```

The proto_buf (8KB) is shared for all commands to avoid per-command allocations.
