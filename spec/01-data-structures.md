# Core Data Structures

## Main driver context: `brcmf_pub`

Primary driver state, one per physical device. Allocated as `wiphy_priv()` data.

```c
struct brcmf_pub {
    struct brcmf_bus *bus_if;           // Bus abstraction
    struct brcmf_proto *proto;          // Protocol layer (msgbuf)
    struct wiphy *wiphy;                // cfg80211 wiphy
    struct cfg80211_ops *ops;           // cfg80211 operations
    struct brcmf_cfg80211_info *config; // cfg80211 state

    uint hdrlen;                        // Total header length (proto + bus)

    char fwver[32];                     // Firmware version string
    u8 mac[ETH_ALEN];                   // Device MAC address
    struct mac_address addresses[16];   // MAC pool for interfaces

    struct brcmf_if *iflist[16];        // Interface array (by bsscfgidx)
    s32 if2bss[16];                     // ifidx → bsscfgidx mapping
    struct brcmf_if *mon_if;            // Monitor interface

    struct mutex proto_block;           // Serializes firmware commands
    unsigned char proto_buf[8192];      // Command buffer

    struct brcmf_fweh_info *fweh;       // Event handling state

    u32 feat_flags;                     // Feature flags
    u32 chip_quirks;                    // Hardware quirks

    struct brcmf_rev_info revinfo;      // Chip revision info
    struct brcmf_mp_device *settings;   // Module parameters
};
```

Key points:
- `iflist[]` indexed by `bsscfgidx` (firmware BSS config index)
- `if2bss[]` maps `ifidx` (firmware interface index) to `bsscfgidx`
- `proto_block` mutex serializes all firmware command/query operations

## Interface: `brcmf_if`

Per-interface state. Firmware supports up to 16 interfaces.

```c
struct brcmf_if {
    struct brcmf_pub *drvr;                  // Parent driver
    struct brcmf_cfg80211_vif *vif;          // cfg80211 vif state
    struct net_device *ndev;                 // Network device
    struct work_struct multicast_work;       // Multicast list update
    struct work_struct ndoffload_work;       // IPv6 offload update
    struct brcmf_fws_mac_descriptor *fws_desc; // Flow control descriptor

    int ifidx;                               // Firmware interface index
    s32 bsscfgidx;                           // Firmware BSS config index
    u8 mac_addr[ETH_ALEN];                   // Interface MAC

    u8 netif_stop;                           // TX queue stop reasons
    spinlock_t netif_stop_lock;
    atomic_t pend_8021x_cnt;                 // Pending 802.1x frames
    wait_queue_head_t pend_8021x_wait;

    struct in6_addr ipv6_addr_tbl[8];        // IPv6 offload table
    u8 ipv6addr_idx;
    bool fwil_fwerr;                         // Return firmware errors
};
```

**Interface indices**:
- `ifidx`: Firmware-assigned interface index (used in packets/events)
- `bsscfgidx`: BSS configuration index (used for iovar addressing)

## VIF state: `brcmf_cfg80211_vif`

cfg80211 virtual interface state.

```c
struct brcmf_cfg80211_vif {
    struct brcmf_if *ifp;                    // Underlying interface
    struct wireless_dev wdev;                // cfg80211 wireless device
    struct brcmf_cfg80211_profile profile;   // Connection profile
    unsigned long sme_state;                 // State bits (enum brcmf_vif_status)
    struct vif_saved_ie saved_ie;            // Saved IEs for beacons/probes
    struct list_head list;                   // Link in vif_list
    struct completion mgmt_tx;               // Mgmt TX completion
    unsigned long mgmt_tx_status;            // Last TX status
    u32 mgmt_tx_id;
    u16 mgmt_rx_reg;                         // Registered RX types
    bool mbss;                               // Multi-BSS mode
    int is_11d;                              // 802.11d state
    s32 cqm_rssi_low;                        // RSSI low threshold
    s32 cqm_rssi_high;                       // RSSI high threshold
    s32 cqm_rssi_last;                       // Last RSSI reading
};
```

**VIF status bits** (`sme_state`):
```c
enum brcmf_vif_status {
    BRCMF_VIF_STATUS_READY,         // Ready for operation
    BRCMF_VIF_STATUS_CONNECTING,    // Connect in progress
    BRCMF_VIF_STATUS_CONNECTED,     // Connected to AP
    BRCMF_VIF_STATUS_DISCONNECTING, // Disconnect in progress
    BRCMF_VIF_STATUS_AP_CREATED,    // AP mode active
    BRCMF_VIF_STATUS_EAP_SUCCESS,   // EAPOL handshake done
    BRCMF_VIF_STATUS_ASSOC_SUCCESS, // Association succeeded
};
```

## Bus abstraction: `brcmf_bus`

Bus-independent interface to hardware.

```c
struct brcmf_bus {
    union {
        struct brcmf_sdio_dev *sdio;
        struct brcmf_usbdev *usb;
        struct brcmf_pciedev *pcie;
    } bus_priv;

    enum brcmf_bus_protocol_type proto_type; // BCDC or msgbuf
    struct device *dev;                      // Parent device
    struct brcmf_pub *drvr;                  // Driver context
    enum brcmf_bus_state state;              // UP or DOWN
    struct brcmf_bus_stats stats;            // Statistics

    uint maxctl;                             // Max control message size
    u32 chip;                                // Chip ID
    u32 chiprev;                             // Chip revision
    enum brcmf_fwvendor fwvid;               // Firmware vendor
    bool always_use_fws_queue;
    bool wowl_supported;

    const struct brcmf_bus_ops *ops;         // Bus callbacks
    struct brcmf_bus_msgbuf *msgbuf;         // msgbuf rings (PCIe only)
};
```

**Bus operations**:
```c
struct brcmf_bus_ops {
    int (*preinit)(struct device *dev);      // Bus-specific init
    void (*stop)(struct device *dev);        // Stop bus
    int (*txdata)(struct device *dev, struct sk_buff *skb);
    int (*txctl)(struct device *dev, unsigned char *msg, uint len);
    int (*rxctl)(struct device *dev, unsigned char *msg, uint len);
    struct pktq *(*gettxq)(struct device *dev);
    void (*wowl_config)(struct device *dev, bool enabled);
    size_t (*get_ramsize)(struct device *dev);
    int (*get_memdump)(struct device *dev, void *data, size_t len);
    int (*get_blob)(struct device *dev, const struct firmware **fw, enum brcmf_blob_type type);
    void (*debugfs_create)(struct device *dev);
    int (*reset)(struct device *dev);
    void (*remove)(struct device *dev);
};
```

## Protocol layer: `brcmf_proto`

Protocol abstraction (BCDC for SDIO/USB, msgbuf for PCIe).

```c
struct brcmf_proto {
    int (*hdrpull)(struct brcmf_pub *drvr, bool do_fws,
                   struct sk_buff *skb, struct brcmf_if **ifp);
    int (*query_dcmd)(struct brcmf_pub *drvr, int ifidx, uint cmd,
                      void *buf, uint len, int *fwerr);
    int (*set_dcmd)(struct brcmf_pub *drvr, int ifidx, uint cmd,
                    void *buf, uint len, int *fwerr);
    int (*tx_queue_data)(struct brcmf_pub *drvr, int ifidx, struct sk_buff *skb);
    int (*txdata)(struct brcmf_pub *drvr, int ifidx, u8 offset, struct sk_buff *skb);
    void (*configure_addr_mode)(struct brcmf_pub *drvr, int ifidx, enum proto_addr_mode);
    void (*delete_peer)(struct brcmf_pub *drvr, int ifidx, u8 peer[ETH_ALEN]);
    void (*add_tdls_peer)(struct brcmf_pub *drvr, int ifidx, u8 peer[ETH_ALEN]);
    void (*rxreorder)(struct brcmf_if *ifp, struct sk_buff *skb);
    void (*add_if)(struct brcmf_if *ifp);
    void (*del_if)(struct brcmf_if *ifp);
    void (*reset_if)(struct brcmf_if *ifp);
    int (*init_done)(struct brcmf_pub *drvr);
    void (*debugfs_create)(struct brcmf_pub *drvr);
    void *pd;                               // Protocol-private data
};
```

## cfg80211 state: `brcmf_cfg80211_info`

cfg80211 subsystem state.

```c
struct brcmf_cfg80211_info {
    struct wiphy *wiphy;
    struct brcmf_cfg80211_conf *conf;
    struct brcmf_p2p_info p2p;
    struct brcmf_btcoex_info *btcoex;
    struct cfg80211_scan_request *scan_request;
    struct mutex usr_sync;                   // User-space synchronization
    struct wl_cfg80211_bss_info *bss_info;
    struct brcmf_cfg80211_connect_info conn_info;
    struct brcmf_pmk_list_le pmk_list;
    unsigned long scan_status;               // BRCMF_SCAN_STATUS_* bits
    struct brcmf_pub *pub;
    u32 channel;
    u32 int_escan_map;
    bool ibss_starter;
    bool pwr_save;
    bool dongle_up;
    bool scan_tried;
    u8 *dcmd_buf;
    u8 *extra_buf;
    struct escan_info escan_info;
    struct timer_list escan_timeout;
    struct work_struct escan_timeout_work;
    struct list_head vif_list;               // All VIFs
    struct brcmf_cfg80211_vif_event vif_event;
    struct completion vif_disabled;
    struct brcmu_d11inf d11inf;
    struct brcmf_assoclist_le assoclist;
    struct brcmf_cfg80211_wowl wowl;
    struct brcmf_pno_info *pno;
    u8 ac_priority[8];                       // WMM priority mapping
};
```

## Event handling: `brcmf_fweh_info`

Firmware event subsystem state.

```c
struct brcmf_fweh_info {
    struct brcmf_pub *drvr;
    bool p2pdev_setup_ongoing;
    struct work_struct event_work;           // Event worker
    spinlock_t evt_q_lock;
    struct list_head event_q;                // Event queue
    uint event_mask_len;
    u8 *event_mask;                          // Enabled events bitmask
    const struct brcmf_fweh_event_map *event_map;
    uint num_event_codes;
    brcmf_fweh_handler_t evt_handler[];      // Handler array
};
```

Event handlers are registered at initialization and called from the event worker thread.
