# Protocol: msgbuf (PCIe)

## Overview

The msgbuf protocol is the PCIe communication protocol between host and firmware. It uses DMA ring buffers for message passing. All messages carry a common 8-byte header followed by type-specific fields. All multi-byte fields are little-endian.

For SDIO/USB buses, see [04-protocol-bcdc.md](04-protocol-bcdc.md).

## Ring types

### H2D (Host to Device) rings

| Ring | Index | Purpose |
|------|-------|---------|
| Control Submit | 0 | IOCTL requests, event/ioctl buffer posts |
| RX Buffer Post | 1 | Pre-posted RX data buffers |
| Flow Rings (N) | 2+ | Per-flow TX data (one per TID/peer pair) |

### D2H (Device to Host) rings

| Ring | Index | Purpose |
|------|-------|---------|
| Control Complete | 2 | IOCTL responses, event delivery |
| TX Complete | 3 | TX completion status |
| RX Complete | 4 | Received data packets |

Note: D2H ring indices in the common ring array start at 2, but their index pointers in the ring info structure are separate from H2D.

Flow ring IDs start at `FLOWRING_IDSTART = 2`, so the firmware ring ID for flow ring N is `N + 2`.

## Common message header

Every message starts with:

```
struct msgbuf_common_hdr {
    u8  msgtype;
    u8  ifidx;       // interface index
    u8  flags;
    u8  rsvd0;
    le32 request_id;  // links request to completion
};
```

## Message types

| Type | Value | Direction | Description |
|------|-------|-----------|-------------|
| GEN_STATUS | 0x01 | D2H | General firmware status |
| RING_STATUS | 0x02 | D2H | Per-ring status |
| FLOW_RING_CREATE | 0x03 | H2D | Create a TX flow ring |
| FLOW_RING_CREATE_CMPLT | 0x04 | D2H | Flow ring creation response |
| FLOW_RING_DELETE | 0x05 | H2D | Delete a TX flow ring |
| FLOW_RING_DELETE_CMPLT | 0x06 | D2H | Flow ring deletion response |
| FLOW_RING_FLUSH | 0x07 | H2D | Flush a TX flow ring |
| FLOW_RING_FLUSH_CMPLT | 0x08 | D2H | Flush response |
| IOCTLPTR_REQ | 0x09 | H2D | IOCTL request |
| IOCTLPTR_REQ_ACK | 0x0A | D2H | IOCTL request acknowledged |
| IOCTLRESP_BUF_POST | 0x0B | H2D | Post buffer for IOCTL response |
| IOCTL_CMPLT | 0x0C | D2H | IOCTL complete |
| EVENT_BUF_POST | 0x0D | H2D | Post buffer for firmware event |
| WL_EVENT | 0x0E | D2H | Firmware event delivered |
| TX_POST | 0x0F | H2D | Transmit a data frame |
| TX_STATUS | 0x10 | D2H | TX completion status |
| RXBUF_POST | 0x11 | H2D | Post buffer for RX data |
| RX_CMPLT | 0x12 | D2H | RX data delivered |

## Completion header

D2H completion messages include a secondary header after the common header:

```
struct msgbuf_completion_hdr {
    le16 status;
    le16 flow_ring_id;
};
```

## IOCTL transport

### IOCTL request

The host sends IOCTLs via the Control Submit ring:

```
struct msgbuf_ioctl_req_hdr {
    msgbuf_common_hdr msg;  // msgtype = IOCTLPTR_REQ
    le32 cmd;               // firmware command code
    le16 trans_id;          // transaction ID (incrementing)
    le16 input_buf_len;     // payload length sent
    le16 output_buf_len;    // expected response length
    le16 rsvd0[3];
    msgbuf_buf_addr req_buf_addr;  // DMA address of payload
    le32 rsvd1[2];
};
```

The request payload is placed in a pre-allocated coherent DMA buffer (`BRCMF_TX_IOCTL_MAX_MSG_SIZE = 1518` bytes, i.e., `ETH_FRAME_LEN + ETH_FCS_LEN`). The IOCTL request uses a fixed `request_id` of `0xFFFE`.

### IOCTL response

Firmware responds on the Control Complete ring with:

```
struct msgbuf_ioctl_resp_hdr {
    msgbuf_common_hdr msg;
    msgbuf_completion_hdr compl_hdr;
    le16 resp_len;
    le16 trans_id;
    le32 cmd;
    le32 rsvd0;
};
```

The response data is placed in a pre-posted buffer identified by `request_id`. The `compl_hdr.status` carries the firmware error code.

### IOCTL buffer management

The host pre-posts up to 8 IOCTL response buffers and up to 8 event buffers via Control Submit, using `IOCTLRESP_BUF_POST` and `EVENT_BUF_POST` message types respectively. Each buffer is `BRCMF_MSGBUF_MAX_CTL_PKT_SIZE = 8192` bytes, DMA-mapped and tracked by packet ID.

Both types use the same wire format (40 bytes):

| Offset | Size | Field |
|--------|------|-------|
| 0 | 8 | Common header (`msgtype` = 0x0B or 0x0D) |
| 8 | 2 | `host_buf_len` |
| 10 | 6 | Reserved |
| 16 | 8 | `host_buf_addr` (lo/hi) |
| 24 | 16 | Reserved |

When a response or event consumes a buffer, the host replenishes it.

### IOCTL flow

1. Host sets `ctl_completed = false`.
2. Writes `IOCTLPTR_REQ` to Control Submit ring.
3. Waits up to 2 seconds for the response (via wait queue).
4. On timeout, returns `EIO`.
5. On completion, retrieves the response buffer by packet ID.
6. Copies response data to the caller's buffer.
7. Returns firmware status from `compl_hdr.status`.

For set commands, the same path is used. Query and set share the implementation.

## TX data path

### Flow ring create message

Sent on Control Submit ring (40 bytes):

| Offset | Size | Field |
|--------|------|-------|
| 0 | 8 | Common header (msgtype = `FLOW_RING_CREATE`) |
| 8 | 6 | Destination MAC |
| 14 | 6 | Source MAC |
| 20 | 1 | TID |
| 21 | 1 | Interface flags |
| 22 | 2 | Flow ring ID (LE) |
| 24 | 1 | Traffic class |
| 25 | 1 | Priority |
| 26 | 2 | Interrupt vector (LE) |
| 28 | 2 | Max items (LE) |
| 30 | 2 | Item length (LE) |
| 32 | 8 | Flow ring DMA address (lo/hi) |

### Flow ring delete message

Sent on Control Submit ring (40 bytes):

| Offset | Size | Field |
|--------|------|-------|
| 0 | 8 | Common header (msgtype = `FLOW_RING_DELETE`) |
| 8 | 2 | Flow ring ID (LE) |
| 10 | 2 | Reason (LE) |
| 12 | 28 | Reserved |

Flow ring completion responses (`FLOW_RING_CREATE_CMPLT`, `FLOW_RING_DELETE_CMPLT`) share the same 24-byte layout:

| Offset | Size | Field |
|--------|------|-------|
| 0 | 8 | Common header |
| 8 | 4 | Completion header (`status`, `flow_ring_id`) |
| 12 | 12 | Reserved |

### Flow ring lifecycle

Flow rings are created per (destination MAC, priority, interface) tuple:

1. **Lookup**: Check if a flow ring exists for this (DA, priority, ifidx).
2. **Create**: If not found, allocate a flow ring ID from the flow ring subsystem, allocate a DMA buffer (`512 items × 48 bytes`), and send a `FLOW_RING_CREATE` message on Control Submit.
3. **Open**: When firmware responds with `FLOW_RING_CREATE_CMPLT` (status 0), mark the ring as open and schedule TX.

Each flow ring has a software queue with flow control thresholds:
- High-water mark: 1024 (stop accepting packets from the network stack)
- Low-water mark: 768 (resume accepting)
4. **Delete**: Send `FLOW_RING_DELETE` on Control Submit. Wait for outstanding TX to drain first (up to 10 retries × 5–10 ms). On response, free the DMA buffer.

### TX post

For each packet to transmit on a flow ring:

1. Dequeue the packet from the flow ring's software queue.
2. Allocate a packet ID from the TX packet ID pool (2048 entries).
3. DMA-map the packet data starting after the Ethernet header.
4. Write a `TX_POST` message to the flow ring:

```
struct msgbuf_tx_msghdr {
    msgbuf_common_hdr msg;   // msgtype = TX_POST, request_id = pktid + 1
    u8  txhdr[14];           // copy of Ethernet header
    u8  flags;               // frame type | (priority << 5)
    u8  seg_cnt;             // always 1
    msgbuf_buf_addr metadata_buf_addr;  // zero
    msgbuf_buf_addr data_buf_addr;      // DMA address of payload
    le16 metadata_buf_len;   // zero
    le16 data_len;           // skb->len - ETH_HLEN
    le32 rsvd0;
};
```

The `flags` field uses `0x01` for 802.3 frames (always the case for FullMAC).

5. Flush writes periodically via `write_complete` (doorbell). The flush uses two thresholds: the counter starts at `FLUSH_CNT2 - FLUSH_CNT1 = 96 - 32 = 64`, so the first flush occurs after 32 items (counter reaches 96). Subsequent flushes occur every 96 items (counter resets to 0). This means the first batch per TX worker invocation is smaller.

### TX completion

Firmware responds with `TX_STATUS` on the TX Complete ring:

```
struct msgbuf_tx_status {
    msgbuf_common_hdr msg;
    msgbuf_completion_hdr compl_hdr;
    le16 metadata_len;
    le16 tx_status;
};
```

The host uses `request_id - 1` as the packet ID index, DMA-unmaps and frees the packet, and decrements the outstanding-TX counter for the flow ring.

After processing TX completions, the host checks if flow rings have queued packets ready for re-submission.

### TX scheduling

TX work is managed by a dedicated single-threaded workqueue:
- A per-flow-ring bitmap tracks rings with pending data.
- The worker iterates all set bits, draining each flow ring's queue.
- Scheduling is either forced (after flow ring open, after TX completion) or throttled (when outstanding TX is below 96).

## RX data path

### Buffer posting

The host pre-posts RX data buffers via the RX Buffer Post ring:

```
struct msgbuf_rx_bufpost {
    msgbuf_common_hdr msg;  // msgtype = RXBUF_POST
    le16 metadata_buf_len;
    le16 data_buf_len;
    le32 rsvd0;
    msgbuf_buf_addr metadata_buf_addr;
    msgbuf_buf_addr data_buf_addr;
};
```

Each buffer is `BRCMF_MSGBUF_MAX_PKT_SIZE = 2048` bytes. The host maintains up to `max_rxbufpost` (default 255) posted buffers and refills when the count drops below a threshold of 32.

Buffer posting uses the `reserve_for_write_multiple` path for batching.

### RX completion

Firmware delivers received packets on the RX Complete ring:

```
struct msgbuf_rx_complete {
    msgbuf_common_hdr msg;
    msgbuf_completion_hdr compl_hdr;
    le16 metadata_len;
    le16 data_len;
    le16 data_offset;
    le16 flags;           // frame type flags
    le32 rx_status_0;
    le32 rx_status_1;
    le32 rsvd0;
};
```

Processing:
1. Retrieve the RX buffer by `request_id`.
2. Strip `data_offset` bytes (or the global `rx_dataoffset` if `data_offset` is zero).
3. Trim to `data_len`.
4. If `flags` indicate 802.11 frame, deliver to monitor interface.
5. Otherwise resolve the interface from `ifidx` and deliver as Ethernet frame.

### Event delivery

Events arrive as `WL_EVENT` on Control Complete:

```
struct msgbuf_rx_event {
    msgbuf_common_hdr msg;
    msgbuf_completion_hdr compl_hdr;
    le16 event_data_len;
    le16 seqnum;
    le16 rsvd0[4];
};
```

Processing:
1. Retrieve the event buffer by `request_id`.
2. Replenish the event buffer pool.
3. Strip `rx_dataoffset` bytes.
4. Trim to `event_data_len`.
5. Pass to the event subsystem via `brcmf_fweh_process_skb`.

## RX trigger

The interrupt handler calls `brcmf_proto_msgbuf_rx_trigger`, which processes the three D2H rings in this order:

1. RX Complete
2. TX Complete
3. Control Complete

After completion processing, it checks TX-status-done flow rings and reschedules their TX workers if they have queued packets.

## Ring buffer abstraction

The `commonring` abstraction implements a circular buffer with producer-consumer semantics:

- `w_ptr`: write pointer (producer, host for H2D, firmware for D2H)
- `r_ptr`: read pointer (consumer, firmware for H2D, host for D2H)
- `f_ptr`: flush pointer (tracks committed writes)
- `depth`: ring capacity
- `item_len`: per-entry size

### Write path

`reserve_for_write` returns a pointer to the next free slot and advances `w_ptr`. Available space is `depth - (w_ptr - r_ptr)`, leaving at least 1 slot empty to distinguish full from empty.

If the ring was previously full and has recovered to 1/8 capacity, it transitions out of the "was_full" state.

`write_complete` updates `f_ptr`, flushes `w_ptr` to the device, and rings the doorbell.

### Read path

`get_read_ptr` refreshes `w_ptr` from the device, then returns a pointer to `r_ptr` and the number of readable items. When `w_ptr < r_ptr` (wraparound), only items up to the end of the buffer are returned; the caller must call again to read the wrapped portion.

`read_complete` advances `r_ptr` and writes it back to the device.

## Packet ID management

TX and RX packet ID pools are separate arrays of fixed size:

- TX: 2048 entries, direction `DMA_TO_DEVICE`
- RX: 1024 entries, direction `DMA_FROM_DEVICE`

Allocation scans from the last-allocated index, wrapping around, using atomic compare-and-swap for lock-free allocation. Each entry stores the DMA address, data offset, and sk_buff pointer.

Retrieval unmaps the DMA buffer and returns the sk_buff, then marks the entry as free.

## Protocol attachment

`brcmf_proto_msgbuf_attach` is called during common driver attach:

1. Creates a single-threaded TX flow workqueue.
2. Allocates flow bitmaps.
3. Allocates a coherent DMA buffer for IOCTL payloads.
4. Installs protocol callbacks (query_dcmd, set_dcmd, tx_queue_data, etc.).
5. Wires up ring pointers from the bus layer.
6. Allocates TX and RX packet ID pools.
7. Attaches the flow ring subsystem.
8. Posts initial RX data buffers, event buffers, and IOCTL response buffers.
9. Initializes the flow ring work queue and work list.
