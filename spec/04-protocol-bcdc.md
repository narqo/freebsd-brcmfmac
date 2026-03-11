# Protocol: BCDC (SDIO/USB)

## Overview

BCDC (Broadcom Dongle Control) is the protocol used on SDIO and USB buses. It provides:
- command/response transport for firmware commands over the bus control path
- a compact per-packet data header carrying interface and priority metadata
- integration with firmware signaling (`fwsignal`) for flow control

Unlike msgbuf (PCIe), BCDC does not use DMA rings. Control messages are exchanged over the bus `txctl`/`rxctl` interfaces. Data packets carry a 4-byte BCDC header between the bus framing and the Ethernet payload.

## BCDC command message

The control message header is 16 bytes:

| Offset | Size | Field | Endianness |
|--------|------|-------|------------|
| 0 | 4 | cmd | LE |
| 4 | 4 | len | LE |
| 8 | 4 | flags | LE |
| 12 | 4 | status | LE |

### Flag bits

The flags field contains:
- `BCDC_DCMD_ERROR = 0x01` — response indicates firmware-side command failure
- `BCDC_DCMD_SET = 0x02` — set request; clear for query
- interface index in bits masked by `0xF000`
- request ID in bits masked by `0xFFFF0000`

The request ID is an incrementing 16-bit counter maintained by the host. Responses are matched against that ID.

### Length field

The implementation writes the request payload length as a 32-bit value before transmission. The source comment documents lower-16 / upper-16 subfields, but the host transmit path in this tree does not populate distinct input/output half-fields separately.

## BCDC data header

Each transmitted or received data packet begins with a 4-byte BCDC header:

| Offset | Size | Field |
|--------|------|-------|
| 0 | 1 | flags |
| 1 | 1 | priority |
| 2 | 1 | flags2 |
| 3 | 1 | data_offset (in 4-byte units) |

The protocol version used by this implementation is 2.

### Data header field encoding

`flags` byte:
| Bit | Mask | Name |
|-----|------|------|
| 2 | 0x04 | `SUM_GOOD` — valid RX checksum |
| 3 | 0x08 | `SUM_NEEDED` — request firmware TX checksum |
| 7:4 | 0xF0 | Protocol version (shifted left 4). Version 2 → `0x20` |

`priority` byte: 802.1d priority in the low 3 bits (mask `0x07`).

`flags2` byte: interface index in the low 4 bits (mask `0x0F`).

`data_offset` indicates how many 4-byte words of firmware-signaling metadata sit between the BCDC header and the Ethernet payload.

## Command flow

### Transmit path

To send a firmware command, the driver:
1. clears the control header
2. increments the request ID and encodes it into the flags field
3. encodes set/query direction and interface index into the flags field
4. copies the request payload into a buffer contiguous with the control header
5. transmits `sizeof(header) + payload_len`, capped at `BRCMF_TX_IOCTL_MAX_MSG_SIZE`

The in-memory request buffer is laid out so the control header is followed immediately by the payload bytes.

### Response matching

The low-level response helper reads control responses until it sees the expected request ID or the bus reports an error.

For query commands, the caller adds stale-response handling on top of that helper:
- if a returned response ID is older than the expected request ID, the query path retries
- retries are bounded by `RETRIES = 2`
- if the ID still does not match, the query fails

The set-command path does not implement that stale-response retry loop; it expects the first completed response to match the outstanding request.

### Query flow

For a query command:
1. send request with set/query bit cleared
2. wait for matching response
3. on success, copy returned payload bytes from the internal BCDC buffer into the caller buffer
4. if the response error bit is set, return the firmware status via the FWIL error path

### Set flow

For a set command:
1. send request with set/query bit set
2. wait for matching response
3. if the response error bit is set, return the firmware status via the FWIL error path

## Data path

### TX

For transmit data:
- if firmware signaling is not queueing the packet, the driver prepends a BCDC header and hands the packet directly to the bus layer
- otherwise the packet is passed through `fwsignal`, which may insert signaling metadata before final bus transmission

When pushing the BCDC header, the driver:
- writes protocol version 2
- propagates checksum-offload intent from `CHECKSUM_PARTIAL`
- writes packet priority
- writes the interface index
- writes the signaling-data offset

### RX

For received data, the driver:
1. validates that the packet is longer than the BCDC header
2. resolves the interface from the interface index in the header
3. validates protocol version
4. marks the skb checksum as unnecessary if firmware reported a good checksum
5. restores packet priority from the header
6. removes the 4-byte BCDC header
7. removes or parses the metadata region indicated by `data_offset * 4`

If firmware signaling is enabled, metadata parsing is delegated to `brcmf_fws_hdrpull()`. Otherwise the driver skips over the metadata region directly.

### TX completion

On transmit completion:
- if firmware signaling is active, completion is routed back through `fwsignal`
- otherwise the driver strips the local BCDC header view and finalizes the transmit against the resolved interface

## Protocol attachment

Protocol attach performs these host-side tasks:
- allocate the BCDC protocol context
- install protocol callbacks for command transport, data transmit, and RX header handling
- set `init_done` to the BCDC-specific post-attach callback
- increase `drvr->hdrlen` by the BCDC header plus maximum firmware-signaling TX bytes
- set the maximum control-buffer size on the bus object: `BRCMF_DCMD_MAXLEN (8192) + sizeof(bcdc_dcmd) (16) + 2048 = 10256`

`brcmf_proto_bcdc_init_done()` attaches firmware signaling.

## Firmware signaling (fwsignal)

Firmware signaling is layered on top of BCDC and is used on SDIO/USB, not PCIe. It provides:
- credit-based flow control
- transmit-status feedback
- MAC descriptor management
- reorder-related metadata

Signaling data sits between the BCDC header and the Ethernet payload. The BCDC `data_offset` field gives its length in 4-byte units.

Maximum TX-side signaling metadata is `BRCMF_PROT_FW_SIGNAL_MAX_TXBYTES = 12`.

### Credit-based flow control

Firmware manages credits per transmit FIFO. When credits are unavailable, the host queues packets locally. Credit-return signaling allows transmission to resume.

The implementation uses six FIFOs:
- background
- best effort
- video
- voice
- broadcast/multicast
- ATIM

### Initialization

`brcmf_fws_attach()` is invoked from the BCDC protocol `init_done` path during core attach.
