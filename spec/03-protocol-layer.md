# Protocol Layer (msgbuf)

## Overview

The msgbuf protocol is the PCIe communication protocol between host and firmware. It uses DMA ring buffers for message passing.

File: `msgbuf.c`

## Ring types

### H2D (Host to Device) rings

| Ring | Purpose |
|------|---------|
| Control Submit | IOCTL requests, buffer posts |
| RX Buffer Post | Post RX buffers for firmware to fill |
| Flow Rings (N) | TX data per flow (per TID/peer) |

### D2H (Device to Host) rings

| Ring | Purpose |
|------|---------|
| Control Complete | IOCTL responses |
| TX Complete | TX completion status |
| RX Complete | Received packets |

## Common ring operations

```c
struct brcmf_commonring {
    u16 r_ptr;           // Read pointer (producer reads, consumer updates)
    u16 w_ptr;           // Write pointer (producer updates, consumer reads)
    u16 f_ptr;           // Flush pointer (for TX coalescing)
    u16 depth;           // Ring size (max items)
    u16 item_len;        // Size per item
    void *buf_addr;      // Ring buffer (DMA memory)
    spinlock_t lock;

    // Callbacks
    int (*cr_ring_bell)(void *ctx);
    int (*cr_update_rptr)(void *ctx);
    int (*cr_update_wptr)(void *ctx);
    int (*cr_write_rptr)(void *ctx);
    int (*cr_write_wptr)(void *ctx);
    void *cr_ctx;
};
```

### Producer operations (e.g., host posting to H2D)

```c
void *brcmf_commonring_reserve_for_write(struct brcmf_commonring *ring) {
    // Check space (one slot is always left empty)
    if (ring->r_ptr <= ring->w_ptr)
        available = ring->depth - ring->w_ptr + ring->r_ptr;
    else
        available = ring->r_ptr - ring->w_ptr;
    if (available <= 1)
        return NULL;

    // Return pointer to next slot
    ret_ptr = ring->buf_addr + (ring->w_ptr * ring->item_len);
    ring->w_ptr++;
    if (ring->w_ptr == ring->depth)
        ring->w_ptr = 0;
    return ret_ptr;
}

int brcmf_commonring_write_complete(struct brcmf_commonring *ring) {
    ring->cr_write_wptr(ring->cr_ctx);  // Update firmware's view
    ring->cr_ring_bell(ring->cr_ctx);   // Signal firmware
}
```

### Consumer operations (e.g., host reading from D2H)

```c
void *brcmf_commonring_get_read_ptr(struct brcmf_commonring *ring, u16 *n_items) {
    ring->cr_update_wptr(ring->cr_ctx);  // Get latest write pointer

    if (ring->w_ptr >= ring->r_ptr)
        available = ring->w_ptr - ring->r_ptr;
    else
        available = ring->depth - ring->r_ptr;
    if (available == 0)
        return NULL;

    *n_items = available;
    return ring->buf_addr + (ring->r_ptr * ring->item_len);
}

int brcmf_commonring_read_complete(struct brcmf_commonring *ring, u16 n_items) {
    ring->r_ptr += n_items;
    if (ring->r_ptr == ring->depth)
        ring->r_ptr = 0;
    ring->cr_write_rptr(ring->cr_ctx);  // Update firmware's view
}
```

## Message types

### Common header

```c
struct msgbuf_common_hdr {
    u8 msgtype;          // Message type
    u8 ifidx;            // Interface index
    u8 flags;            // Message flags
    u8 rsvd0;
    __le32 request_id;   // Packet ID (for correlation)
};
```

### Message type codes

```c
// H2D messages
#define MSGBUF_TYPE_FLOW_RING_CREATE      0x3
#define MSGBUF_TYPE_FLOW_RING_DELETE      0x5
#define MSGBUF_TYPE_FLOW_RING_FLUSH       0x7
#define MSGBUF_TYPE_IOCTLPTR_REQ          0x9
#define MSGBUF_TYPE_IOCTLRESP_BUF_POST    0xB
#define MSGBUF_TYPE_EVENT_BUF_POST        0xD
#define MSGBUF_TYPE_TX_POST               0xF
#define MSGBUF_TYPE_RXBUF_POST            0x11

// D2H messages
#define MSGBUF_TYPE_GEN_STATUS            0x1
#define MSGBUF_TYPE_RING_STATUS           0x2
#define MSGBUF_TYPE_FLOW_RING_CREATE_CMPLT 0x4
#define MSGBUF_TYPE_FLOW_RING_DELETE_CMPLT 0x6
#define MSGBUF_TYPE_FLOW_RING_FLUSH_CMPLT  0x8
#define MSGBUF_TYPE_IOCTLPTR_REQ_ACK      0xA
#define MSGBUF_TYPE_IOCTL_CMPLT           0xC
#define MSGBUF_TYPE_WL_EVENT              0xE
#define MSGBUF_TYPE_TX_STATUS             0x10
#define MSGBUF_TYPE_RX_CMPLT              0x12
```

## IOCTL handling

### IOCTL request

Host sends IOCTL via control submit ring:

```c
struct msgbuf_ioctl_req_hdr {
    struct msgbuf_common_hdr msg;      // msgtype = MSGBUF_TYPE_IOCTLPTR_REQ
    __le32 cmd;                        // IOCTL command code
    __le16 trans_id;                   // Transaction ID
    __le16 input_buf_len;              // Input buffer length
    __le16 output_buf_len;             // Expected output length
    __le16 rsvd0[3];
    struct msgbuf_buf_addr req_buf_addr; // DMA address of input data
    __le32 rsvd1[2];
};

struct msgbuf_buf_addr {
    __le32 low_addr;                   // Lower 32 bits of DMA address
    __le32 high_addr;                  // Upper 32 bits of DMA address
};
```

### IOCTL flow

1. Allocate DMA buffer for IOCTL data (`ioctbuf`)
2. Copy input data to DMA buffer
3. Build `msgbuf_ioctl_req_hdr` with DMA address
4. Submit to control ring, ring doorbell
5. Wait for `MSGBUF_TYPE_IOCTL_CMPLT` in control complete ring
6. Copy response from DMA buffer

```c
int brcmf_msgbuf_tx_ioctl(drvr, ifidx, cmd, buf, len) {
    struct msgbuf_ioctl_req_hdr *request;

    brcmf_commonring_lock(commonring);
    request = brcmf_commonring_reserve_for_write(commonring);

    request->msg.msgtype = MSGBUF_TYPE_IOCTLPTR_REQ;
    request->msg.ifidx = ifidx;
    request->msg.request_id = BRCMF_IOCTL_REQ_PKTID;
    request->cmd = cpu_to_le32(cmd);
    request->trans_id = cpu_to_le16(msgbuf->reqid++);
    request->input_buf_len = cpu_to_le16(min(len, BRCMF_TX_IOCTL_MAX_MSG_SIZE));
    request->output_buf_len = cpu_to_le16(len);
    request->req_buf_addr.low_addr = cpu_to_le32(msgbuf->ioctbuf_phys_lo);
    request->req_buf_addr.high_addr = cpu_to_le32(msgbuf->ioctbuf_phys_hi);

    memcpy(msgbuf->ioctbuf, buf, len);
    brcmf_commonring_write_complete(commonring);
    brcmf_commonring_unlock(commonring);
}
```

### IOCTL response

```c
struct msgbuf_ioctl_resp_hdr {
    struct msgbuf_common_hdr msg;      // msgtype = MSGBUF_TYPE_IOCTL_CMPLT
    struct msgbuf_completion_hdr compl_hdr;
    __le16 resp_len;                   // Response data length
    __le16 trans_id;                   // Matches request trans_id
    __le32 cmd;                        // Echo of command
    __le32 rsvd0;
};

struct msgbuf_completion_hdr {
    __le16 status;                     // Firmware status code
    __le16 flow_ring_id;
};
```

## RX buffer posting

Host must pre-post RX buffers for firmware to fill with received packets. There are two distinct buffer pools:
- Data RX buffers (`MSGBUF_TYPE_RXBUF_POST`) in the RX post ring
- Control RX buffers (`MSGBUF_TYPE_IOCTLRESP_BUF_POST` and `MSGBUF_TYPE_EVENT_BUF_POST`) in the control submit ring

### Post RX buffer

```c
struct msgbuf_rx_bufpost {
    struct msgbuf_common_hdr msg;      // msgtype = MSGBUF_TYPE_RXBUF_POST
    __le16 metadata_buf_len;
    __le16 data_buf_len;               // Buffer size
    __le32 rsvd0;
    struct msgbuf_buf_addr metadata_buf_addr;
    struct msgbuf_buf_addr data_buf_addr; // DMA address of buffer
};
```

### RX completion

When firmware receives a packet, it fills a posted buffer and sends completion:

```c
struct msgbuf_rx_complete {
    struct msgbuf_common_hdr msg;      // msgtype = MSGBUF_TYPE_RX_CMPLT
    struct msgbuf_completion_hdr compl_hdr;
    __le16 metadata_len;
    __le16 data_len;                   // Actual data length
    __le16 data_offset;                // Offset in buffer
    __le16 flags;
    __le32 rx_status_0;
    __le32 rx_status_1;
    __le32 rsvd0;
};
```

`request_id` in header maps to the posted buffer's packet ID.

### Control buffers (IOCTL/event)

IOCTL responses and events use a separate posting path in the control submit ring with `MSGBUF_TYPE_IOCTLRESP_BUF_POST` and `MSGBUF_TYPE_EVENT_BUF_POST`. These are tracked by `cur_ioctlrespbuf`/`cur_eventbuf` and reposted after each completion.

## TX data flow

### Flow rings

Each TX flow (per TID, per peer) gets its own ring. Created on demand.

```c
struct msgbuf_tx_flowring_create_req {
    struct msgbuf_common_hdr msg;      // msgtype = MSGBUF_TYPE_FLOW_RING_CREATE
    u8 da[ETH_ALEN];                   // Destination MAC
    u8 sa[ETH_ALEN];                   // Source MAC
    u8 tid;                            // Traffic ID (0-7)
    u8 if_flags;
    __le16 flow_ring_id;               // Ring ID
    u8 tc;                             // Traffic class
    u8 priority;
    __le16 int_vector;
    __le16 max_items;                  // Ring depth
    __le16 len_item;                   // Item size
    struct msgbuf_buf_addr flow_ring_addr; // Ring DMA address
};
```

### TX post

```c
struct msgbuf_tx_msghdr {
    struct msgbuf_common_hdr msg;      // msgtype = MSGBUF_TYPE_TX_POST
    u8 txhdr[ETH_HLEN];                // Ethernet header
    u8 flags;                          // BRCMF_MSGBUF_PKT_FLAGS_*
    u8 seg_cnt;
    struct msgbuf_buf_addr metadata_buf_addr;
    struct msgbuf_buf_addr data_buf_addr;
    __le16 metadata_buf_len;
    __le16 data_len;
    __le32 rsvd0;
};

#define BRCMF_MSGBUF_PKT_FLAGS_FRAME_802_3  0x01
#define BRCMF_MSGBUF_PKT_FLAGS_PRIO_SHIFT   5
```

### TX completion

```c
struct msgbuf_tx_status {
    struct msgbuf_common_hdr msg;      // msgtype = MSGBUF_TYPE_TX_STATUS
    struct msgbuf_completion_hdr compl_hdr;
    __le16 metadata_len;
    __le16 tx_status;                  // 0 = success
};
```

## Event handling

### Event buffer post

Host posts event buffers for firmware async events:

```c
struct msgbuf_rx_ioctl_resp_or_event {
    struct msgbuf_common_hdr msg;      // msgtype = MSGBUF_TYPE_EVENT_BUF_POST
    __le16 host_buf_len;               // Buffer size
    __le16 rsvd0[3];
    struct msgbuf_buf_addr host_buf_addr;
    __le32 rsvd1[4];
};
```

### Event delivery

```c
struct msgbuf_rx_event {
    struct msgbuf_common_hdr msg;      // msgtype = MSGBUF_TYPE_WL_EVENT
    struct msgbuf_completion_hdr compl_hdr;
    __le16 event_data_len;             // Event payload length
    __le16 seqnum;
    __le16 rsvd0[4];
};
```

## Packet ID management

Packet IDs correlate requests with completions. Managed via arrays:

```c
struct brcmf_msgbuf_pktids {
    u32 array_size;
    u32 last_allocated_idx;
    enum dma_data_direction direction;
    struct brcmf_msgbuf_pktid *array;
};

struct brcmf_msgbuf_pktid {
    atomic_t allocated;
    u16 data_offset;
    struct sk_buff *skb;
    dma_addr_t physaddr;
};
```

Allocation returns an index; completion uses the index to retrieve the skb.

## Protocol initialization

```c
int brcmf_proto_msgbuf_attach(drvr) {
    msgbuf = kzalloc(sizeof(*msgbuf), GFP_KERNEL);

    // Set up commonrings from bus layer
    msgbuf->commonrings = drvr->bus_if->msgbuf->commonrings;
    msgbuf->flowrings = drvr->bus_if->msgbuf->flowrings;
    msgbuf->max_flowrings = drvr->bus_if->msgbuf->max_flowrings;
    msgbuf->rx_dataoffset = drvr->bus_if->msgbuf->rx_dataoffset;
    msgbuf->max_rxbufpost = drvr->bus_if->msgbuf->max_rxbufpost;

    // Allocate IOCTL buffer
    msgbuf->ioctbuf = dma_alloc_coherent(...);

    // Allocate packet ID trackers
    msgbuf->tx_pktids = brcmf_msgbuf_init_pktids(NR_TX_PKTIDS, DMA_TO_DEVICE);
    msgbuf->rx_pktids = brcmf_msgbuf_init_pktids(NR_RX_PKTIDS, DMA_FROM_DEVICE);

    // Set up protocol callbacks
    drvr->proto->hdrpull = brcmf_msgbuf_hdrpull;
    drvr->proto->query_dcmd = brcmf_msgbuf_query_dcmd;
    drvr->proto->set_dcmd = brcmf_msgbuf_set_dcmd;
    drvr->proto->tx_queue_data = brcmf_msgbuf_tx_queue_data;
    ...

    // Post initial RX buffers
    brcmf_msgbuf_rxbuf_data_fill(msgbuf);
    brcmf_msgbuf_rxbuf_event_post(msgbuf);
    brcmf_msgbuf_rxbuf_ioctlresp_post(msgbuf);
}
```

### PCIe RX handling note

For msgbuf on PCIe, RX completions are processed directly in `brcmf_msgbuf_process_rx_complete()` and delivered to `brcmf_netif_rx()` or `brcmf_netif_mon_rx()` based on flags. `brcmf_msgbuf_hdrpull()` is a stub and is not part of the PCIe RX path.
