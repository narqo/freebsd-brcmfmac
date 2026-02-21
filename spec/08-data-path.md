# Data Path

## Overview

brcmfmac is a FullMAC driver - it exchanges Ethernet frames with firmware, not 802.11 frames. The data path handles TX/RX of these Ethernet frames via DMA rings.

## TX path

### Entry point

Network stack calls `ndo_start_xmit`:

```c
static netdev_tx_t brcmf_netdev_start_xmit(struct sk_buff *skb,
                                           struct net_device *ndev) {
    struct brcmf_if *ifp = netdev_priv(ndev);
    struct brcmf_pub *drvr = ifp->drvr;
    struct ethhdr *eh;

    // Check bus state
    if (drvr->bus_if->state != BRCMF_BUS_UP) {
        netif_stop_queue(ndev);
        dev_kfree_skb(skb);
        return NETDEV_TX_OK;
    }

    // Ensure enough headroom for protocol headers
    if (skb_headroom(skb) < drvr->hdrlen || skb_header_cloned(skb)) {
        ret = pskb_expand_head(skb, ALIGN(head_delta, NET_SKB_PAD), 0, GFP_ATOMIC);
        if (ret < 0) {
            dev_kfree_skb(skb);
            goto done;
        }
    }

    eh = (struct ethhdr *)(skb->data);

    // Track 802.1x frames for key handshake synchronization
    if (eh->h_proto == htons(ETH_P_PAE))
        atomic_inc(&ifp->pend_8021x_cnt);

    // Set priority from QoS/DSCP
    if ((skb->priority == 0) || (skb->priority > 7))
        skb->priority = cfg80211_classify8021d(skb, NULL);

    // Queue to protocol layer
    ret = brcmf_proto_tx_queue_data(drvr, ifp->ifidx, skb);
    if (ret < 0)
        brcmf_txfinalize(ifp, skb, false);

done:
    if (ret) {
        ndev->stats.tx_dropped++;
    } else {
        ndev->stats.tx_packets++;
        ndev->stats.tx_bytes += skb->len;
    }

    return NETDEV_TX_OK;
}
```

### Protocol TX queue

msgbuf uses flow rings per (TID, peer) for QoS:

---
**BCM4350 note**

For STA mode with a single peer (the AP), a simplified implementation can use a single flow ring for all traffic. The firmware handles QoS internally. Flow rings must be deleted and recreated on each association to avoid stale state.

---

```c
static int brcmf_msgbuf_tx_queue_data(struct brcmf_pub *drvr, int ifidx,
                                      struct sk_buff *skb) {
    struct brcmf_msgbuf *msgbuf = drvr->proto->pd;
    struct brcmf_flowring *flow = msgbuf->flow;
    struct ethhdr *eh = (struct ethhdr *)(skb->data);
    u32 flowid;

    // Get or create flow ring for this (TID, DA)
    flowid = brcmf_flowring_lookup(flow, eh->h_dest, skb->priority, ifidx);
    if (flowid == BRCMF_FLOWRING_INVALID_ID) {
        flowid = brcmf_msgbuf_flowring_create(msgbuf, ifidx, skb);
        if (flowid == BRCMF_FLOWRING_INVALID_ID) {
            return -ENOMEM;
        } else {
            brcmf_flowring_enqueue(flow, flowid, skb);
            return 0;
        }
    }

    // Queue skb for this flow
    queue_count = brcmf_flowring_enqueue(flow, flowid, skb);

    // Schedule TX worker
    force = ((queue_count % BRCMF_MSGBUF_TRICKLE_TXWORKER_THRS) == 0);
    brcmf_msgbuf_schedule_txdata(msgbuf, flowid, force);

    return 0;
}
```

### TX worker

```c
static void brcmf_msgbuf_txflow_worker(struct work_struct *work) {
    struct brcmf_msgbuf *msgbuf = container_of(work, struct brcmf_msgbuf, txflow_work);
    u32 flowid;

    for_each_set_bit(flowid, msgbuf->flow_map, msgbuf->max_flowrings) {
        clear_bit(flowid, msgbuf->flow_map);
        brcmf_msgbuf_txflow(msgbuf, flowid);
    }
}

static void brcmf_msgbuf_txflow(struct brcmf_msgbuf *msgbuf, u32 flowid) {
    struct brcmf_commonring *commonring;
    struct brcmf_flowring *flow = msgbuf->flow;
    struct sk_buff *skb;
    dma_addr_t physaddr;
    u32 pktid;
    u32 count;

    commonring = msgbuf->flowrings[flowid];
    if (!brcmf_commonring_write_available(commonring))
        return;

    brcmf_commonring_lock(commonring);
    count = BRCMF_MSGBUF_TX_FLUSH_CNT2 - BRCMF_MSGBUF_TX_FLUSH_CNT1;
    while (brcmf_flowring_qlen(flow, flowid)) {
        skb = brcmf_flowring_dequeue(flow, flowid);
        if (!skb)
            break;

        // Get ring slot
        ret_ptr = brcmf_commonring_reserve_for_write(commonring);
        if (!ret_ptr) {
            // Ring full, requeue and stop
            brcmf_flowring_reinsert(flow, flowid, skb);
            break;
        }

        // Allocate packet ID
        brcmf_msgbuf_alloc_pktid(dev, msgbuf->tx_pktids, skb, ETH_HLEN, &physaddr, &pktid);

        // Build TX header
        tx_msghdr = (struct msgbuf_tx_msghdr *)ret_ptr;
        tx_msghdr->msg.msgtype = MSGBUF_TYPE_TX_POST;
        tx_msghdr->msg.ifidx = brcmf_flowring_ifidx_get(flow, flowid);
        tx_msghdr->msg.request_id = cpu_to_le32(pktid + 1);

        // Copy Ethernet header to message
        memcpy(tx_msghdr->txhdr, skb->data, ETH_HLEN);
        tx_msghdr->flags = BRCMF_MSGBUF_PKT_FLAGS_FRAME_802_3;
        tx_msghdr->flags |= (skb->priority & 0x07) << BRCMF_MSGBUF_PKT_FLAGS_PRIO_SHIFT;

        // Set DMA address
        tx_msghdr->data_buf_addr.high_addr = cpu_to_le32(physaddr >> 32);
        tx_msghdr->data_buf_addr.low_addr = cpu_to_le32(physaddr & 0xffffffff);
        tx_msghdr->data_len = cpu_to_le16(skb->len - ETH_HLEN);

        count++;
        if (count >= BRCMF_MSGBUF_TX_FLUSH_CNT2) {
            brcmf_commonring_write_complete(commonring);
            count = 0;
        }
    }
    if (count)
        brcmf_commonring_write_complete(commonring);
    brcmf_commonring_unlock(commonring);
}
```

### TX completion

Firmware sends `MSGBUF_TYPE_TX_STATUS` when done with buffer:

```c
static void brcmf_msgbuf_process_txstatus(struct brcmf_msgbuf *msgbuf,
                                          void *buf) {
    struct msgbuf_tx_status *tx_status = buf;
    u32 pktid;
    struct sk_buff *skb;
    struct brcmf_if *ifp;

    pktid = le32_to_cpu(tx_status->msg.request_id) - 1;

    // Retrieve and unmap skb
    skb = brcmf_msgbuf_get_pktid(dev, msgbuf->tx_pktids, pktid);
    if (!skb)
        return;

    // Get interface
    ifp = brcmf_get_ifp(msgbuf->drvr, tx_status->msg.ifidx);

    // Complete TX
    brcmf_txfinalize(ifp, skb, true);
}
```

### TX finalize

```c
void brcmf_txfinalize(struct brcmf_if *ifp, struct sk_buff *txp, bool success) {
    struct ethhdr *eh;
    u16 type;

    if (!ifp) {
        brcmu_pkt_buf_free_skb(txp);
        return;
    }

    eh = (struct ethhdr *)(txp->data);
    type = ntohs(eh->h_proto);

    // Update 802.1x counter for key handshake sync
    if (type == ETH_P_PAE) {
        atomic_dec(&ifp->pend_8021x_cnt);
        if (waitqueue_active(&ifp->pend_8021x_wait))
            wake_up(&ifp->pend_8021x_wait);
    }

    if (!success)
        ifp->ndev->stats.tx_errors++;

    brcmu_pkt_buf_free_skb(txp);
}
```

## RX path

### RX buffer posting

Host pre-posts buffers for firmware to fill:

```c
static void brcmf_msgbuf_rxbuf_data_fill(struct brcmf_msgbuf *msgbuf) {
    struct brcmf_commonring *commonring;
    struct msgbuf_rx_bufpost *rx_bufpost;
    struct sk_buff *skb;
    dma_addr_t physaddr;
    u32 pktid;
    u32 count;

    commonring = msgbuf->commonrings[BRCMF_H2D_MSGRING_RXPOST_SUBMIT];
    count = msgbuf->max_rxbufpost - msgbuf->rxbufpost;

    while (count > 0) {
        // Allocate skb for RX
        skb = brcmu_pkt_buf_get_skb(BRCMF_MSGBUF_MAX_PKT_SIZE);
        if (!skb)
            break;

        // Allocate packet ID
        brcmf_msgbuf_alloc_pktid(dev, msgbuf->rx_pktids, skb,
                                 msgbuf->rx_dataoffset, &physaddr, &pktid);

        brcmf_commonring_lock(commonring);

        rx_bufpost = brcmf_commonring_reserve_for_write(commonring);
        if (!rx_bufpost) {
            brcmf_msgbuf_get_pktid(dev, msgbuf->rx_pktids, pktid);
            brcmu_pkt_buf_free_skb(skb);
            brcmf_commonring_unlock(commonring);
            break;
        }

        rx_bufpost->msg.msgtype = MSGBUF_TYPE_RXBUF_POST;
        rx_bufpost->msg.request_id = cpu_to_le32(pktid);
        rx_bufpost->data_buf_len = cpu_to_le16(BRCMF_MSGBUF_MAX_PKT_SIZE);
        rx_bufpost->data_buf_addr.high_addr = cpu_to_le32(physaddr >> 32);
        rx_bufpost->data_buf_addr.low_addr = cpu_to_le32(physaddr & 0xffffffff);

        brcmf_commonring_write_complete(commonring);
        brcmf_commonring_unlock(commonring);

        msgbuf->rxbufpost++;
        count--;
    }
}
```

### RX completion processing

When firmware fills a buffer, it sends `MSGBUF_TYPE_RX_CMPLT`:

```c
static void brcmf_msgbuf_process_rx_complete(struct brcmf_msgbuf *msgbuf, void *buf) {
    struct msgbuf_rx_complete *rx_complete = buf;
    struct sk_buff *skb;
    u16 data_len;
    u16 data_offset;
    u16 flags;
    u32 pktid;

    pktid = le32_to_cpu(rx_complete->msg.request_id);
    data_len = le16_to_cpu(rx_complete->data_len);
    data_offset = le16_to_cpu(rx_complete->data_offset);
    flags = le16_to_cpu(rx_complete->flags);

    // Retrieve skb
    skb = brcmf_msgbuf_get_pktid(dev, msgbuf->rx_pktids, pktid);
    if (!skb)
        return;

    // Adjust skb for actual data
    if (data_offset)
        skb_pull(skb, data_offset);
    else if (msgbuf->rx_dataoffset)
        skb_pull(skb, msgbuf->rx_dataoffset);
    skb_trim(skb, data_len);

    // Monitor frames vs Ethernet frames
    if ((flags & BRCMF_MSGBUF_PKT_FLAGS_FRAME_MASK) ==
        BRCMF_MSGBUF_PKT_FLAGS_FRAME_802_11) {
        brcmf_netif_mon_rx(mon_ifp, skb);
        return;
    }

    // Deliver to network stack
    brcmf_netif_rx(ifp, skb);

    // Repost buffer if below threshold
    if (msgbuf->rxbufpost < BRCMF_MSGBUF_RXBUFPOST_THRESHOLD)
        brcmf_msgbuf_rxbuf_data_fill(msgbuf);
}
```

Notes:
- For msgbuf, RX completions bypass `brcmf_rx_frame()` and go directly to `brcmf_netif_rx()`/`brcmf_netif_mon_rx()`.

### Frame reception

```c
void brcmf_rx_frame(struct device *dev, struct sk_buff *skb, bool handle_event,
                    bool inirq) {
    struct brcmf_if *ifp;
    struct brcmf_bus *bus_if = dev_get_drvdata(dev);
    struct brcmf_pub *drvr = bus_if->drvr;

    // Pull protocol header and get interface
    if (brcmf_rx_hdrpull(drvr, skb, &ifp))
        return;

    // Check for reorder info (AMPDU)
    if (brcmf_proto_is_reorder_skb(skb)) {
        brcmf_proto_rxreorder(ifp, skb);
    } else {
        // Check for firmware events
        if (handle_event) {
            gfp_t gfp = inirq ? GFP_ATOMIC : GFP_KERNEL;
            brcmf_fweh_process_skb(ifp->drvr, skb, BCMILCP_SUBTYPE_VENDOR_LONG, gfp);
        }

        // Deliver to network stack
        brcmf_netif_rx(ifp, skb);
    }
}
```

### Network delivery

```c
void brcmf_netif_rx(struct brcmf_if *ifp, struct sk_buff *skb) {
    // Filter IAPP frames if not enabled
    if (!ifp->drvr->settings->iapp && brcmf_skb_is_iapp(skb)) {
        brcmu_pkt_buf_free_skb(skb);
        return;
    }

    if (skb->pkt_type == PACKET_MULTICAST)
        ifp->ndev->stats.multicast++;

    if (!(ifp->ndev->flags & IFF_UP)) {
        brcmu_pkt_buf_free_skb(skb);
        return;
    }

    ifp->ndev->stats.rx_bytes += skb->len;
    ifp->ndev->stats.rx_packets++;

    // Pass to network stack
    netif_rx(skb);
}
```

## Header handling

### Header pull

msgbuf protocol header processing:

```c
static int brcmf_msgbuf_hdrpull(struct brcmf_pub *drvr, bool do_fws,
                                struct sk_buff *skb, struct brcmf_if **ifp) {
    // For msgbuf, interface is identified in message header, not packet header
    // RX completion handler already set skb->dev

    *ifp = brcmf_get_ifp(drvr, skb->cb[0]);  // ifidx stored in cb

    return 0;
}
```

## Flow control

### TX queue stop reasons

```c
enum brcmf_netif_stop_reason {
    BRCMF_NETIF_STOP_REASON_FWS_FC = BIT(0),     // Flow control from firmware
    BRCMF_NETIF_STOP_REASON_FLOW = BIT(1),       // Flow ring full
    BRCMF_NETIF_STOP_REASON_DISCONNECTED = BIT(2) // Not connected
};

void brcmf_txflowblock_if(struct brcmf_if *ifp,
                          enum brcmf_netif_stop_reason reason, bool state) {
    spin_lock_irqsave(&ifp->netif_stop_lock, flags);
    if (state) {
        if (!ifp->netif_stop)
            netif_stop_queue(ifp->ndev);
        ifp->netif_stop |= reason;
    } else {
        ifp->netif_stop &= ~reason;
        if (!ifp->netif_stop)
            netif_wake_queue(ifp->ndev);
    }
    spin_unlock_irqrestore(&ifp->netif_stop_lock, flags);
}
```

### Carrier state

```c
void brcmf_net_setcarrier(struct brcmf_if *ifp, bool on) {
    struct net_device *ndev = ifp->ndev;

    // Block/unblock TX when disconnected
    brcmf_txflowblock_if(ifp, BRCMF_NETIF_STOP_REASON_DISCONNECTED, !on);

    if (on) {
        if (!netif_carrier_ok(ndev))
            netif_carrier_on(ndev);
    } else {
        if (netif_carrier_ok(ndev))
            netif_carrier_off(ndev);
    }
}
```

## 802.1x synchronization

For WPA key handshake, driver must ensure EAPOL frames are transmitted before proceeding:

```c
int brcmf_netdev_wait_pend8021x(struct brcmf_if *ifp) {
    int err;

    // Wait for all pending 802.1x frames to complete
    err = wait_event_timeout(ifp->pend_8021x_wait,
                             !atomic_read(&ifp->pend_8021x_cnt),
                             MAX_WAIT_FOR_8021X_TX);

    if (!err) {
        bphy_err(drvr, "Timed out waiting for pending 802.1x packets\n");
        atomic_set(&ifp->pend_8021x_cnt, 0);
    }

    return !err;
}
```

This is called before installing keys to ensure EAPOL handshake completes.
