# Firmware Event Handling

## Overview

Firmware sends asynchronous events to the host for state changes, scan results, connection status, etc. The event system (`fweh.c`) dispatches these to registered handlers.

## Event packet format

Events are delivered as Ethernet frames with special encapsulation:

```c
struct brcmf_event {
    struct ethhdr eth;                    // Ethernet header
    struct brcm_ethhdr hdr;               // Broadcom header
    struct brcmf_event_msg_be msg;        // Event message (big-endian)
} __packed;

struct brcm_ethhdr {
    __be16 subtype;
    __be16 length;
    u8 version;
    u8 oui[3];                            // Must be BRCM_OUI "\x00\x10\x18"
    __be16 usr_subtype;                   // Must be BCMILCP_BCM_SUBTYPE_EVENT (1)
} __packed;

struct brcmf_event_msg_be {
    __be16 version;
    __be16 flags;
    __be32 event_type;                    // Event code
    __be32 status;                        // Event status
    __be32 reason;                        // Reason code
    __be32 auth_type;
    __be32 datalen;                       // Payload length
    u8 addr[ETH_ALEN];
    char ifname[IFNAMSIZ];
    u8 ifidx;                             // Interface index
    u8 bsscfgidx;                         // BSS config index
} __packed;
```

Event identification:
- `eth.h_proto` = `ETH_P_LINK_CTL` (0x886c)
- `hdr.oui` = `"\x00\x10\x18"` (Broadcom OUI)
- `hdr.usr_subtype` = 1 (Event subtype)

## Event codes

```c
enum brcmf_fweh_event_code {
    BRCMF_E_SET_SSID        = 0,   // SSID set result
    BRCMF_E_JOIN            = 1,   // Join network
    BRCMF_E_START           = 2,   // Start BSS
    BRCMF_E_AUTH            = 3,   // Authentication
    BRCMF_E_AUTH_IND        = 4,   // Auth indication (AP mode)
    BRCMF_E_DEAUTH          = 5,   // Deauthentication
    BRCMF_E_DEAUTH_IND      = 6,   // Deauth indication
    BRCMF_E_ASSOC           = 7,   // Association
    BRCMF_E_ASSOC_IND       = 8,   // Assoc indication (AP mode)
    BRCMF_E_REASSOC         = 9,
    BRCMF_E_REASSOC_IND     = 10,
    BRCMF_E_DISASSOC        = 11,
    BRCMF_E_DISASSOC_IND    = 12,
    BRCMF_E_LINK            = 16,  // Link up/down
    BRCMF_E_MIC_ERROR       = 17,  // MIC failure
    BRCMF_E_ROAM            = 19,  // Roaming
    BRCMF_E_TXFAIL          = 20,
    BRCMF_E_PMKID_CACHE     = 21,
    BRCMF_E_PRUNE           = 23,
    BRCMF_E_SCAN_COMPLETE   = 26,  // Legacy scan done
    BRCMF_E_PFN_NET_FOUND   = 33,  // PNO network found
    BRCMF_E_PFN_NET_LOST    = 34,  // PNO network lost
    BRCMF_E_PSM_WATCHDOG    = 41,  // PSM watchdog fired
    BRCMF_E_PROBREQ_MSG     = 44,
    BRCMF_E_PSK_SUP         = 46,  // PSK supplicant event
    BRCMF_E_IF              = 54,  // Interface add/del/change
    BRCMF_E_P2P_DISC_LISTEN_COMPLETE = 55,
    BRCMF_E_RSSI            = 56,  // RSSI change
    BRCMF_E_ACTION_FRAME    = 59,
    BRCMF_E_ACTION_FRAME_COMPLETE = 60,
    BRCMF_E_ESCAN_RESULT    = 69,  // Enhanced scan result
    BRCMF_E_ACTION_FRAME_OFF_CHAN_COMPLETE = 70,
    BRCMF_E_ACTION_FRAME_RX = 75,
    BRCMF_E_FIFO_CREDIT_MAP = 74,
    BRCMF_E_TDLS_PEER_EVENT = 92,
    BRCMF_E_BCMC_CREDIT_SUPPORT = 127,
};
```

## Event status codes

```c
#define BRCMF_E_STATUS_SUCCESS     0
#define BRCMF_E_STATUS_FAIL        1
#define BRCMF_E_STATUS_TIMEOUT     2
#define BRCMF_E_STATUS_NO_NETWORKS 3
#define BRCMF_E_STATUS_ABORT       4
#define BRCMF_E_STATUS_NO_ACK      5
#define BRCMF_E_STATUS_PARTIAL     8
#define BRCMF_E_STATUS_NEWSCAN     9
#define BRCMF_E_STATUS_NEWASSOC    10
#define BRCMF_E_STATUS_CS_ABORT    15
#define BRCMF_E_STATUS_ERROR       16
```

## Event reason codes

```c
// Link event reasons
#define BRCMF_E_REASON_INITIAL_ASSOC    0
#define BRCMF_E_REASON_LOW_RSSI         1
#define BRCMF_E_REASON_DEAUTH           2
#define BRCMF_E_REASON_DISASSOC         3
#define BRCMF_E_REASON_BCNS_LOST        4
#define BRCMF_E_REASON_FAST_ROAM_FAILED 5
#define BRCMF_E_REASON_DIRECTED_ROAM    6
#define BRCMF_E_REASON_BETTER_AP        8

// IF event actions
#define BRCMF_E_IF_ADD     1
#define BRCMF_E_IF_DEL     2
#define BRCMF_E_IF_CHANGE  3
```

## Event flags

```c
#define BRCMF_EVENT_MSG_LINK       0x01  // Link is up
#define BRCMF_EVENT_MSG_FLUSHTXQ   0x02  // Flush TX queue
#define BRCMF_EVENT_MSG_GROUP      0x04  // Group key
```

## Event registration

Handlers are registered at initialization:

```c
int brcmf_fweh_register(struct brcmf_pub *drvr, enum brcmf_fweh_event_code code,
                        brcmf_fweh_handler_t handler);

typedef int (*brcmf_fweh_handler_t)(struct brcmf_if *ifp,
                                    const struct brcmf_event_msg *emsg,
                                    void *data);
```

### Event code mapping

Event codes used by the driver (`enum brcmf_fweh_event_code`) may differ from firmware event codes. The `brcmf_fweh_event_map` (provided by vendor-specific module) translates between them. Abstract events (bit 31 set) are used for vendor-specific events that have different numeric codes across firmware vendors:

```c
#define BRCMF_ABSTRACT_EVENT_BIT    BIT(31)

// Abstract events
BRCMF_E_EXT_AUTH_REQ         = BRCMF_ABSTRACT_EVENT_BIT | 0
BRCMF_E_EXT_AUTH_FRAME_RX    = BRCMF_ABSTRACT_EVENT_BIT | 1
BRCMF_E_MGMT_FRAME_TXSTATUS  = BRCMF_ABSTRACT_EVENT_BIT | 2
BRCMF_E_MGMT_FRAME_OFFCHAN_DONE = BRCMF_ABSTRACT_EVENT_BIT | 3
```

`brcmf_fweh_register()` and `brcmf_fweh_unregister()` use `brcmf_fweh_map_event_code()` (driver code → firmware index) to determine the handler array slot. `brcmf_fweh_activate_events()` iterates handler indices directly and uses `brcmf_fweh_map_fwevt_code()` (firmware index → driver code) only for debug logging.

The full registration list is in [07-initialization.md](07-initialization.md#event-handler-registration). It is called from `wl_init_priv()` → `brcmf_register_event_handlers()` during `brcmf_cfg80211_attach()`. Additional handlers (e.g., `BRCMF_E_TDLS_PEER_EVENT`) may be registered later based on feature detection.

## Event activation

After registration, events must be enabled in firmware:

```c
int brcmf_fweh_activate_events(struct brcmf_if *ifp) {
    // Build event mask from registered handlers
    memset(fweh->event_mask, 0, fweh->event_mask_len);
    for (i = 0; i < fweh->num_event_codes; i++) {
        if (fweh->evt_handler[i])
            setbit(fweh->event_mask, i);
    }

    // Always enable IF event
    setbit(fweh->event_mask, BRCMF_E_IF);

    // Allow vendor-specific activation method
    if (!brcmf_fwvid_activate_events(ifp))
        return 0;

    // Send to firmware
    return brcmf_fil_iovar_data_set(ifp, "event_msgs", fweh->event_mask,
                                    fweh->event_mask_len);
}
```

## Event processing flow

### Reception

Events arrive via msgbuf `MSGBUF_TYPE_WL_EVENT` or as regular RX packets (identified by ETH_P_LINK_CTL).

```c
void brcmf_fweh_process_skb(struct brcmf_pub *drvr, struct sk_buff *skb,
                            u16 stype, gfp_t gfp) {
    // Validate Ethernet protocol
    if (skb->protocol != cpu_to_be16(ETH_P_LINK_CTL))
        return;

    event_packet = (struct brcmf_event *)skb_mac_header(skb);

    // Verify Broadcom OUI
    if (memcmp(BRCM_OUI, &event_packet->hdr.oui[0], 3))
        return;

    // Verify event subtype
    usr_stype = get_unaligned_be16(&event_packet->hdr.usr_subtype);
    if (usr_stype != BCMILCP_BCM_SUBTYPE_EVENT)
        return;

    brcmf_fweh_process_event(drvr, event_packet, skb->len + ETH_HLEN, gfp);
}
```

### Queuing

Events are queued for worker thread processing:

```c
void brcmf_fweh_process_event(struct brcmf_pub *drvr, struct brcmf_event *event_packet,
                              u32 packet_len, gfp_t gfp) {
    fwevt_idx = get_unaligned_be32(&event_packet->msg.event_type);
    datalen = get_unaligned_be32(&event_packet->msg.datalen);

    if (fwevt_idx >= fweh->num_event_codes)
        return;

    // Check if handler registered
    if (fwevt_idx != BRCMF_E_IF && !fweh->evt_handler[fwevt_idx])
        return;

    if (datalen > BRCMF_DCMD_MAXLEN ||
        datalen + sizeof(*event_packet) > packet_len)
        return;

    // Allocate queue item
    event = kzalloc(sizeof(*event) + datalen, gfp);
    event->code = fwevt_idx;
    event->datalen = datalen;
    memcpy(&event->emsg, &event_packet->msg, sizeof(event->emsg));
    memcpy(event->data, &event_packet[1], datalen);

    // Queue for worker
    brcmf_fweh_queue_event(fweh, event);
}

static void brcmf_fweh_queue_event(struct brcmf_fweh_info *fweh,
                                   struct brcmf_fweh_queue_item *event) {
    spin_lock_irqsave(&fweh->evt_q_lock, flags);
    list_add_tail(&event->q, &fweh->event_q);
    spin_unlock_irqrestore(&fweh->evt_q_lock, flags);
    schedule_work(&fweh->event_work);
}
```

### Worker dispatch

```c
static void brcmf_fweh_event_worker(struct work_struct *work) {
    while ((event = brcmf_fweh_dequeue_event(fweh))) {
        // Convert big-endian message to host format
        emsg.event_code = be32_to_cpu(event->emsg.event_type);
        emsg.status = be32_to_cpu(event->emsg.status);
        emsg.reason = be32_to_cpu(event->emsg.reason);
        // ... etc

        // Special handling for IF event
        if (event->code == BRCMF_E_IF) {
            brcmf_fweh_handle_if_event(drvr, &emsg, event->data);
            goto event_free;
        }

        // TDLS events always use iflist[0]
        if (event->code == BRCMF_E_TDLS_PEER_EVENT)
            ifp = drvr->iflist[0];
        else
            ifp = drvr->iflist[emsg.bsscfgidx];

        // Call registered handler
        brcmf_fweh_call_event_handler(drvr, ifp, event->code, &emsg, event->data);

event_free:
        kfree(event);
    }
}
```

## Interface events

IF events handle virtual interface creation/deletion:

```c
struct brcmf_if_event {
    u8 ifidx;      // Interface index
    u8 action;     // ADD/DEL/CHANGE
    u8 flags;      // BRCMF_E_IF_FLAG_*
    u8 bsscfgidx;  // BSS config index
    u8 role;       // STA/AP/P2P_GO/etc
};

#define BRCMF_E_IF_ROLE_STA        0
#define BRCMF_E_IF_ROLE_AP         1
#define BRCMF_E_IF_ROLE_WDS        2
#define BRCMF_E_IF_ROLE_P2P_GO     3
#define BRCMF_E_IF_ROLE_P2P_CLIENT 4
```

Handler:

```c
static void brcmf_fweh_handle_if_event(struct brcmf_pub *drvr,
                                       struct brcmf_event_msg *emsg,
                                       void *data) {
    struct brcmf_if_event *ifevent = data;

    if (ifevent->action == BRCMF_E_IF_ADD) {
        ifp = brcmf_add_if(drvr, ifevent->bsscfgidx, ifevent->ifidx,
                           is_p2pdev, emsg->ifname, emsg->addr);
        if (!drvr->fweh->evt_handler[BRCMF_E_IF])
            brcmf_net_attach(ifp, false);
    }

    if (ifevent->action == BRCMF_E_IF_CHANGE)
        brcmf_proto_reset_if(drvr, ifp);

    // Call any registered IF handler
    brcmf_fweh_call_event_handler(drvr, ifp, BRCMF_E_IF, emsg, data);

    if (ifevent->action == BRCMF_E_IF_DEL)
        brcmf_remove_interface(ifp, false);
}
```

## Key event handlers

### Connection status (`brcmf_notify_connect_status`)

Handles: `LINK`, `DEAUTH`, `DEAUTH_IND`, `DISASSOC_IND`, `SET_SSID`, `PSK_SUP`

Called when connection state changes. Updates VIF status bits and notifies cfg80211.

### Scan results (`brcmf_cfg80211_escan_handler`)

Handles: `ESCAN_RESULT`

Processes scan result BSS info and reports to cfg80211.

### Roaming (`brcmf_notify_roaming_status`)

Handles: `ROAM`

Called when firmware completes roaming to new AP.
