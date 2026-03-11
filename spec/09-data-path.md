# Data Path

## Overview

brcmfmac is a FullMAC driver — it exchanges Ethernet frames with firmware, not 802.11 frames.

The data path differs by bus type:
- **PCIe (msgbuf)**: DMA rings with per-flow TX rings and pre-posted RX buffers
- **SDIO (BCDC)**: SDPCM-framed byte streams over SDIO F2 with optional fwsignal flow control

## TX path

### Common entry point

The network device `ndo_start_xmit` handler:

1. Verify VIF is up and connected (for STA mode).
2. Ensure the packet has enough headroom for protocol headers; reallocate if needed.
3. Call `brcmf_proto_tx_queue_data(drvr, ifidx, skb)`.

### PCIe (msgbuf) TX

1. **Flow ring lookup**: Hash `(destination_mac, priority, ifidx)` to find an existing flow ring.
2. **Flow ring creation**: If none exists, allocate one (DMA buffer + firmware `FLOW_RING_CREATE` message). Queue the packet until the ring is open.
3. **Enqueue**: Add the packet to the flow ring's software queue.
4. **Schedule TX**: Set the flow ring's bit in the flow map, queue the TX worker.
5. **TX worker**: For each flow ring with pending data:
   a. Dequeue packets from the software queue.
   b. DMA-map data starting after the Ethernet header.
   c. Write `TX_POST` messages into the flow ring.
   d. After a batch (up to 96), flush the write pointer and ring the doorbell.
6. **TX completion**: Firmware sends `TX_STATUS` on the TX Complete ring. The host unmaps and frees the packet.

### SDIO (BCDC) TX

1. **BCDC header**: Prepend a 4-byte BCDC data header with protocol version, priority, interface index, and signaling data offset.
2. **Firmware signaling** (if active): Packet may be queued in the fwsignal layer for credit-based flow control. Signaling metadata is inserted between the BCDC header and the Ethernet payload.
3. **SDPCM framing**: Prepend a 12-byte SDPCM header with frame length, sequence number, channel=DATA, and data offset.
4. **Bus write**: Transmit the frame to SDIO F2 via CMD53.
5. **TX completion**: For BCDC without fwsignal, completion is immediate after bus write. With fwsignal, completion is signaled when firmware returns a TX status.

### TX flow control

- **PCIe**: Per-flow-ring `outstanding_tx` counter. New TX is throttled when outstanding count exceeds `DELAY_TXWORKER_THRS = 96`.
- **SDIO**: Credit-based. Firmware controls the max sequence number. Host stops TX when sequence would exceed the allowed window. Also, fwsignal manages per-FIFO credits.

### TX finalization

`brcmf_txfinalize` is called on completion:
1. Resolve the interface from `ifidx`.
2. If the packet is an 802.1X frame, decrement the pending 8021x counter and wake any waiter.
3. Free the packet.

## RX path

### PCIe (msgbuf) RX

1. **Interrupt**: D2H doorbell triggers `msgbuf_rx_trigger`.
2. **RX Complete ring**: Read entries. For each:
   a. Retrieve the pre-posted buffer by packet ID.
   b. Strip data offset.
   c. Trim to `data_len`.
   d. Identify frame type from flags.
3. **Data delivery**: Call `brcmf_netif_rx(ifp, skb)`:
   a. Set `skb->protocol` via `eth_type_trans`.
   b. Deliver to network stack.
4. **Event delivery**: Event frames go to `brcmf_fweh_process_skb` for event processing.
5. **Buffer replenish**: Maintain RX buffer count at `max_rxbufpost`.

### SDIO (BCDC) RX

1. **DPC thread**: Reads frames from F2.
2. **SDPCM demux**: Parse SDPCM header, extract channel.
3. **Channel routing**:
   - Control: deliver to IOCTL response path.
   - Event: deliver to event processing.
   - Data: continue to BCDC processing.
4. **BCDC header pull**:
   a. Validate packet length > 4 bytes.
   b. Extract interface index, priority, protocol version.
   c. Mark checksum status from firmware flags.
   d. Strip the 4-byte BCDC header.
   e. If fwsignal: strip/parse signaling metadata (based on `data_offset × 4`).
5. **Reorder processing**: If AMPDU reorder metadata is present, buffer and reorder packets.
6. **Data delivery**: Same as PCIe path via `brcmf_netif_rx`.

## Packet reception (common)

`brcmf_rx_frame`:
1. Extract interface via protocol `hdrpull`.
2. If the frame is an event (recognized by `ETH_P_LINK_CTL` + Broadcom OUI): process as event.
3. Otherwise: check for AMPDU reorder, then deliver to `brcmf_netif_rx`.

`brcmf_netif_rx`:
1. `eth_type_trans` to set protocol.
2. `netif_rx` to deliver to kernel network stack.
3. Update interface statistics (RX bytes, RX packets).

## Header length management

The driver tracks total header overhead in `drvr->hdrlen`:
- Bus layer adds its framing overhead.
- Protocol layer adds its header overhead.
- This total is used to ensure packets have sufficient headroom before TX.

For BCDC: `hdrlen += sizeof(bcdc_header) + BRCMF_PROT_FW_SIGNAL_MAX_TXBYTES`.

For msgbuf: no additional hdrlen (DMA-based, no in-band headers on TX data).

## Network device operations

| Callback | Action |
|----------|--------|
| `ndo_open` | `brcmf_cfg80211_up` (firmware UP, enable events) |
| `ndo_stop` | `brcmf_cfg80211_down` (firmware DOWN) |
| `ndo_start_xmit` | Queue packet for TX via protocol layer |
| `ndo_set_mac_address` | Set MAC via `cur_etheraddr` IOVAR |
| `ndo_set_rx_mode` | Configure multicast list, allmulti, promisc |

### Multicast configuration

When the multicast list changes:
1. Build a list of multicast MAC addresses.
2. Send via `mcast_list` IOVAR.
3. Set `allmulti` IOVAR based on device flags.
4. Set `BRCMF_C_SET_PROMISC` based on device flags.

### 802.1X wait

Before disconnection, the driver waits for all outstanding 802.1X frames to complete (`pend_8021x_cnt` reaches 0), with a 950 ms timeout.
