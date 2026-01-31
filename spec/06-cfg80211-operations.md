# cfg80211 Operations

## Overview

The cfg80211 layer (`cfg80211.c`) implements the wireless configuration API. For FullMAC, this translates high-level operations into firmware commands.

## cfg80211_ops structure

```c
static struct cfg80211_ops brcmf_cfg80211_ops = {
    // Interface management
    .add_virtual_intf = brcmf_cfg80211_add_iface,
    .del_virtual_intf = brcmf_cfg80211_del_iface,
    .change_virtual_intf = brcmf_cfg80211_change_iface,

    // Scanning
    .scan = brcmf_cfg80211_scan,
    .sched_scan_start = brcmf_cfg80211_sched_scan_start,
    .sched_scan_stop = brcmf_cfg80211_sched_scan_stop,

    // Connection
    .connect = brcmf_cfg80211_connect,
    .disconnect = brcmf_cfg80211_disconnect,

    // Key management
    .add_key = brcmf_cfg80211_add_key,
    .del_key = brcmf_cfg80211_del_key,
    .get_key = brcmf_cfg80211_get_key,
    .set_default_key = brcmf_cfg80211_config_default_key,
    .set_default_mgmt_key = brcmf_cfg80211_config_default_mgmt_key,

    // IBSS
    .join_ibss = brcmf_cfg80211_join_ibss,
    .leave_ibss = brcmf_cfg80211_leave_ibss,

    // AP mode
    .start_ap = brcmf_cfg80211_start_ap,
    .stop_ap = brcmf_cfg80211_stop_ap,
    .change_beacon = brcmf_cfg80211_change_beacon,
    .del_station = brcmf_cfg80211_del_station,
    .change_station = brcmf_cfg80211_change_station,

    // Station info
    .get_station = brcmf_cfg80211_get_station,
    .dump_station = brcmf_cfg80211_dump_station,
    .get_channel = brcmf_cfg80211_get_channel,

    // Power management
    .set_power_mgmt = brcmf_cfg80211_set_power_mgmt,
    .set_wiphy_params = brcmf_cfg80211_set_wiphy_params,
    .suspend = brcmf_cfg80211_suspend,
    .resume = brcmf_cfg80211_resume,

    // Management frames
    .mgmt_tx = brcmf_cfg80211_mgmt_tx,
    .update_mgmt_frame_registrations =
        brcmf_cfg80211_update_mgmt_frame_registrations,
    .remain_on_channel = brcmf_p2p_remain_on_channel,
    .cancel_remain_on_channel = brcmf_cfg80211_cancel_remain_on_channel,

    // PMK management
    .set_pmksa = brcmf_cfg80211_set_pmksa,
    .del_pmksa = brcmf_cfg80211_del_pmksa,
    .flush_pmksa = brcmf_cfg80211_flush_pmksa,
    .set_pmk = brcmf_cfg80211_set_pmk,
    .del_pmk = brcmf_cfg80211_del_pmk,

    // TDLS
    .tdls_oper = brcmf_cfg80211_tdls_oper,

    // Channel info
    .get_channel = brcmf_cfg80211_get_channel,

    // TX power
    .set_tx_power = brcmf_cfg80211_set_tx_power,
    .get_tx_power = brcmf_cfg80211_get_tx_power,

    // P2P device
    .start_p2p_device = brcmf_p2p_start_device,
    .stop_p2p_device = brcmf_p2p_stop_device,

    // Critical protocol
    .crit_proto_start = brcmf_cfg80211_crit_proto_start,
    .crit_proto_stop = brcmf_cfg80211_crit_proto_stop,

    // Connect parameter updates
    .update_connect_params = brcmf_cfg80211_update_conn_params,

    // RSSI/CQM
    .set_cqm_rssi_range_config = brcmf_cfg80211_set_cqm_rssi_range_config,

    // BSS change
    .change_bss = brcmf_cfg80211_change_bss,

    // etc.
};
```

## Scan operation

### Enhanced scan (escan)

brcmfmac uses enhanced scan for better control and results streaming.

```c
static s32 brcmf_cfg80211_scan(struct wiphy *wiphy,
                               struct cfg80211_scan_request *request) {
    // Check state
    if (test_bit(BRCMF_SCAN_STATUS_BUSY, &cfg->scan_status))
        return -EAGAIN;

    // Store request
    cfg->scan_request = request;
    set_bit(BRCMF_SCAN_STATUS_BUSY, &cfg->scan_status);

    // Set probe request IEs
    brcmf_vif_set_mgmt_ie(vif, BRCMF_VNDR_IE_PRBREQ_FLAG, request->ie, request->ie_len);

    // Start scan
    err = brcmf_do_escan(vif->ifp, request);

    // Start timeout timer
    mod_timer(&cfg->escan_timeout, jiffies + msecs_to_jiffies(10000));

    return err;
}
```

### escan parameters

```c
struct brcmf_escan_params_le {
    __le32 version;
    __le16 action;              // WL_ESCAN_ACTION_START/CONTINUE/ABORT
    __le16 sync_id;
    struct brcmf_scan_params_le params;
};

struct brcmf_scan_params_le {
    struct brcmf_ssid_le ssid;
    u8 bssid[ETH_ALEN];
    s8 bss_type;
    u8 scan_type;               // 0=active, 1=passive
    __le32 nprobes;
    __le32 active_time;
    __le32 passive_time;
    __le32 home_time;
    __le32 channel_num;
    __le16 channel_list[];      // Chanspec list
};
```

### escan execution

```c
static s32 brcmf_do_escan(struct brcmf_if *ifp, struct cfg80211_scan_request *request) {
    params = kzalloc(params_size, GFP_KERNEL);

    // Fill in scan params
    params->version = cpu_to_le32(BRCMF_ESCAN_REQ_VERSION_V2);
    params->action = cpu_to_le16(WL_ESCAN_ACTION_START);
    params->sync_id = cpu_to_le16(0x1234);

    // Submit to firmware
    err = brcmf_fil_iovar_data_set(ifp, "escan", params, params_size);

    kfree(params);
    return err;
}
```

Notes:
- v2 scan params (`BRCMF_ESCAN_REQ_VERSION_V2`) are used by default. The code falls back to v1 if `BRCMF_FEAT_SCAN_V2` is not set and converts v2 → v1.
- P2P scan requests are preprocessed and may be redirected to the primary interface.

### Scan results handling

Results arrive via `BRCMF_E_ESCAN_RESULT` events:

```c
static s32 brcmf_cfg80211_escan_handler(struct brcmf_if *ifp,
                                        const struct brcmf_event_msg *e,
                                        void *data) {
    struct brcmf_escan_result_le *escan_result = data;
    struct brcmf_bss_info_le *bi;

    if (e->status == BRCMF_E_STATUS_PARTIAL) {
        // More results coming
        bi = &escan_result->bss_info_le;

        // Report BSS to cfg80211
        brcmf_inform_single_bss(cfg, bi);

    } else if (e->status == BRCMF_E_STATUS_SUCCESS ||
               e->status == BRCMF_E_STATUS_ABORT) {
        // Scan complete
        cfg80211_scan_done(cfg->scan_request, &info);
        cfg->scan_request = NULL;
        clear_bit(BRCMF_SCAN_STATUS_BUSY, &cfg->scan_status);
    }
}
```

## Connect operation

### Overview

Connection involves multiple steps:
1. Configure security parameters
2. Set SSID to initiate connection
3. Wait for firmware events
4. Report result to cfg80211

### Connect flow

```c
static s32 brcmf_cfg80211_connect(struct wiphy *wiphy, struct net_device *ndev,
                                  struct cfg80211_connect_params *sme) {
    struct brcmf_if *ifp = netdev_priv(ndev);
    struct brcmf_cfg80211_profile *profile = &ifp->vif->profile;

    // Mark connecting
    set_bit(BRCMF_VIF_STATUS_CONNECTING, &ifp->vif->sme_state);

    // Set infrastructure mode
    brcmf_fil_cmd_int_set(ifp, BRCMF_C_SET_INFRA, 1);

    // Configure security
    brcmf_set_wsec_mode(ndev, sme);
    brcmf_set_key_mgmt(ndev, sme);
    brcmf_set_sharedkey(ndev, sme);  // For WEP

    // Set PSK if WPA-PSK
    if (sme->crypto.psk) {
        struct brcmf_wsec_pmk_le pmk;
        pmk.key_len = cpu_to_le16(BRCMF_WSEC_MAX_PSK_LEN);
        pmk.flags = cpu_to_le16(BRCMF_WSEC_PASSPHRASE);
        memcpy(pmk.key, sme->crypto.psk, BRCMF_WSEC_MAX_PSK_LEN);
        brcmf_fil_cmd_data_set(ifp, BRCMF_C_SET_WSEC_PMK, &pmk, sizeof(pmk));
    }

    // Store BSSID if specified
    if (sme->bssid)
        memcpy(profile->bssid, sme->bssid, ETH_ALEN);

    // Start connection by setting SSID
    struct brcmf_join_params join_params;
    memcpy(join_params.ssid_le.SSID, sme->ssid, sme->ssid_len);
    join_params.ssid_le.SSID_len = cpu_to_le32(sme->ssid_len);
    memcpy(join_params.params_le.bssid, profile->bssid, ETH_ALEN);

    err = brcmf_fil_cmd_data_set(ifp, BRCMF_C_SET_SSID, &join_params, sizeof(join_params));

    return err;
}
```

### Connection result

Connection completes via `BRCMF_E_SET_SSID` or `BRCMF_E_LINK` events:

```c
static s32 brcmf_notify_connect_status(struct brcmf_if *ifp,
                                       const struct brcmf_event_msg *e,
                                       void *data) {
    struct brcmf_cfg80211_info *cfg = ifp->drvr->config;
    struct brcmf_cfg80211_vif *vif = ifp->vif;

    if (e->event_code == BRCMF_E_SET_SSID) {
        if (e->status == BRCMF_E_STATUS_SUCCESS) {
            // Association succeeded
            set_bit(BRCMF_VIF_STATUS_ASSOC_SUCCESS, &vif->sme_state);
        } else {
            // Association failed
            clear_bit(BRCMF_VIF_STATUS_CONNECTING, &vif->sme_state);
            cfg80211_connect_result(ndev, NULL, NULL, 0, NULL, 0,
                                    WLAN_STATUS_UNSPECIFIED_FAILURE, GFP_KERNEL);
        }
    }

    if (e->event_code == BRCMF_E_LINK) {
        if (e->flags & BRCMF_EVENT_MSG_LINK) {
            // Link up - connection complete
            brcmf_bss_connect_done(cfg, ndev, e, true);
        } else {
            // Link down
            brcmf_bss_connect_done(cfg, ndev, e, false);
        }
    }
}

static void brcmf_bss_connect_done(struct brcmf_cfg80211_info *cfg,
                                   struct net_device *ndev,
                                   const struct brcmf_event_msg *e,
                                   bool completed) {
    if (completed) {
        // Get connection info from firmware
        brcmf_fil_cmd_data_get(ifp, BRCMF_C_GET_BSSID, profile->bssid, ETH_ALEN);

        // Get association IEs
        brcmf_fil_iovar_data_get(ifp, "assoc_info", &assoc_info, sizeof(assoc_info));

        // Report to cfg80211
        cfg80211_connect_result(ndev, profile->bssid,
                                conn_info->req_ie, conn_info->req_ie_len,
                                conn_info->resp_ie, conn_info->resp_ie_len,
                                WLAN_STATUS_SUCCESS, GFP_KERNEL);

        set_bit(BRCMF_VIF_STATUS_CONNECTED, &vif->sme_state);
        clear_bit(BRCMF_VIF_STATUS_CONNECTING, &vif->sme_state);

        // Enable carrier
        netif_carrier_on(ndev);
    } else {
        // Report failure
        cfg80211_connect_result(ndev, NULL, NULL, 0, NULL, 0,
                                WLAN_STATUS_UNSPECIFIED_FAILURE, GFP_KERNEL);
        clear_bit(BRCMF_VIF_STATUS_CONNECTING, &vif->sme_state);
    }
}
```

## Disconnect

```c
static s32 brcmf_cfg80211_disconnect(struct wiphy *wiphy, struct net_device *ndev,
                                     u16 reason_code) {
    struct brcmf_if *ifp = netdev_priv(ndev);
    struct brcmf_scb_val_le scbval;

    if (!test_bit(BRCMF_VIF_STATUS_CONNECTED, &ifp->vif->sme_state) &&
        !test_bit(BRCMF_VIF_STATUS_CONNECTING, &ifp->vif->sme_state))
        return 0;

    set_bit(BRCMF_VIF_STATUS_DISCONNECTING, &ifp->vif->sme_state);

    // Send disassoc to firmware
    memcpy(scbval.ea, bssid, ETH_ALEN);
    scbval.val = cpu_to_le32(reason_code);
    brcmf_fil_cmd_data_set(ifp, BRCMF_C_DISASSOC, &scbval, sizeof(scbval));

    return 0;
}
```

## Key management

### Add key

```c
static s32 brcmf_cfg80211_add_key(struct wiphy *wiphy, struct net_device *ndev,
                                  int link_id, u8 key_idx, bool pairwise,
                                  const u8 *mac_addr, struct key_params *params) {
    struct brcmf_wsec_key *key;

    key = kzalloc(sizeof(*key), GFP_KERNEL);
    key->index = key_idx;
    key->len = params->key_len;
    memcpy(key->data, params->key, key->len);

    if (mac_addr)
        memcpy(key->ea, mac_addr, ETH_ALEN);

    // Set cipher type
    switch (params->cipher) {
    case WLAN_CIPHER_SUITE_WEP40:
    case WLAN_CIPHER_SUITE_WEP104:
        key->algo = CRYPTO_ALGO_WEP128;
        break;
    case WLAN_CIPHER_SUITE_TKIP:
        key->algo = CRYPTO_ALGO_TKIP;
        break;
    case WLAN_CIPHER_SUITE_CCMP:
        key->algo = CRYPTO_ALGO_AES_CCM;
        break;
    }

    // Set key in firmware
    brcmf_fil_bsscfg_data_set(ifp, "wsec_key", key, sizeof(*key));

    kfree(key);
    return 0;
}
```

## Security modes

```c
// WSEC values
#define WEP_ENABLED      0x0001
#define TKIP_ENABLED     0x0002
#define AES_ENABLED      0x0004
#define WSEC_SWFLAG      0x0008

// WPA auth values
#define WPA_AUTH_DISABLED    0x0000
#define WPA_AUTH_NONE        0x0001
#define WPA_AUTH_PSK         0x0004
#define WPA2_AUTH_PSK        0x0080
#define WPA2_AUTH_1X_SHA256  0x1000
#define WPA2_AUTH_PSK_SHA256 0x8000
#define WPA3_AUTH_SAE_PSK    0x40000

static s32 brcmf_set_wsec_mode(struct net_device *ndev,
                               struct cfg80211_connect_params *sme) {
    u32 wsec = 0;
    u32 wpa_auth = 0;

    // Determine WSEC from ciphers
    for (i = 0; i < sme->crypto.n_ciphers_pairwise; i++) {
        switch (sme->crypto.ciphers_pairwise[i]) {
        case WLAN_CIPHER_SUITE_WEP40:
        case WLAN_CIPHER_SUITE_WEP104:
            wsec |= WEP_ENABLED;
            break;
        case WLAN_CIPHER_SUITE_TKIP:
            wsec |= TKIP_ENABLED;
            break;
        case WLAN_CIPHER_SUITE_CCMP:
            wsec |= AES_ENABLED;
            break;
        }
    }

    brcmf_fil_bsscfg_int_set(ifp, "wsec", wsec);

    // Determine WPA auth from AKM
    for (i = 0; i < sme->crypto.n_akm_suites; i++) {
        switch (sme->crypto.akm_suites[i]) {
        case WLAN_AKM_SUITE_PSK:
            if (sme->crypto.wpa_versions & NL80211_WPA_VERSION_1)
                wpa_auth |= WPA_AUTH_PSK;
            if (sme->crypto.wpa_versions & NL80211_WPA_VERSION_2)
                wpa_auth |= WPA2_AUTH_PSK;
            break;
        case WLAN_AKM_SUITE_SAE:
            wpa_auth |= WPA3_AUTH_SAE_PSK;
            break;
        }
    }

    brcmf_fil_bsscfg_int_set(ifp, "wpa_auth", wpa_auth);
}
```

## Bringing interface up/down

```c
s32 brcmf_cfg80211_up(struct net_device *ndev) {
    struct brcmf_if *ifp = netdev_priv(ndev);

    set_bit(BRCMF_VIF_STATUS_READY, &ifp->vif->sme_state);

    // Configure dongle once per device
    return brcmf_config_dongle(ifp->drvr->config);
}

s32 brcmf_cfg80211_down(struct net_device *ndev) {
    struct brcmf_if *ifp = netdev_priv(ndev);

    // If associated, issue link down and wait for events
    brcmf_link_down(ifp->vif, WLAN_REASON_UNSPECIFIED, true);
    brcmf_delay(500);

    brcmf_abort_scanning(cfg);
    clear_bit(BRCMF_VIF_STATUS_READY, &ifp->vif->sme_state);

    return 0;
}
```

Notes:
- `brcmf_config_dongle()` performs `BRCMF_C_UP` with value 0, configures scan times, power mode, roam policy, ARP/ND offload, and frameburst; it is the only place dongle-wide init occurs.
- There is no `BRCMF_C_DOWN` in `brcmf_cfg80211_down()`.
