# Firmware Event Handling

## Overview

Firmware delivers asynchronous events for scan progress, connection state, interface lifecycle, roaming, security, and other state changes. The event subsystem validates incoming event frames, queues them, converts the event header from big-endian form, resolves the target interface, and dispatches the event to the registered handler.

## Event frame identification

An event frame is recognized by these outer fields:
- Ethernet protocol `ETH_P_LINK_CTL` (`0x886c`)
- Broadcom OUI `00:10:18`
- Broadcom event user subtype `1`

The event message embedded in the frame is carried in big-endian form.

## Event wire format

An event frame on the wire consists of three parts in order:

### 1. Standard Ethernet header (14 bytes)

EtherType `0x886c` (`ETH_P_LINK_CTL`).

### 2. Broadcom-specific Ethernet sub-header (10 bytes, packed)

| Offset | Size | Field | Endianness |
|--------|------|-------|------------|
| 0 | 2 | subtype | BE, `0x8001` for data-path events |
| 2 | 2 | length | BE |
| 4 | 1 | version | |
| 5 | 3 | OUI | `00:10:18` |
| 8 | 2 | usr_subtype | BE, must be 1 |

### 3. Event message (all fields big-endian, packed)

| Offset (from sub-header end) | Size | Field |
|-------------------------------|------|-------|
| 0 | 2 | version |
| 2 | 2 | flags |
| 4 | 4 | event_type |
| 8 | 4 | status |
| 12 | 4 | reason |
| 16 | 4 | auth_type |
| 20 | 4 | datalen |
| 24 | 6 | addr (peer MAC) |
| 30 | 16 | ifname |
| 46 | 1 | ifidx |
| 47 | 1 | bsscfgidx |

Event-specific payload of `datalen` bytes follows immediately after `bsscfgidx`.

## Event codes

Event codes used by this tree (prefixed `BRCMF_E_`):

| Code | Value | Used for |
|------|-------|----------|
| `SET_SSID` | 0 | Connection result |
| `JOIN` | 1 | Join |
| `AUTH` | 3 | Authentication |
| `AUTH_IND` | 4 | Auth indication (AP) |
| `DEAUTH` | 5 | Deauthentication |
| `DEAUTH_IND` | 6 | Deauth indication |
| `ASSOC` | 7 | Association |
| `ASSOC_IND` | 8 | Assoc indication (AP) |
| `REASSOC_IND` | 10 | Reassoc indication |
| `DISASSOC_IND` | 12 | Disassoc indication |
| `LINK` | 16 | Link up/down |
| `MIC_ERROR` | 17 | MIC failure |
| `ROAM` | 19 | Roaming |
| `PFN_NET_FOUND` | 33 | PNO network found |
| `PSM_WATCHDOG` | 41 | PSM watchdog |
| `PSK_SUP` | 46 | Firmware supplicant event |
| `IF` | 54 | Interface add/del/change |
| `P2P_DISC_LISTEN_COMPLETE` | 55 | P2P listen done |
| `RSSI` | 56 | RSSI change |
| `ACTION_FRAME` | 59 | Action frame |
| `ACTION_FRAME_COMPLETE` | 60 | Action frame TX done |
| `ESCAN_RESULT` | 69 | Enhanced scan result |
| `ACTION_FRAME_OFF_CHAN_COMPLETE` | 70 | Off-channel action TX done |
| `P2P_PROBEREQ_MSG` | 72 | P2P probe request |
| `FIFO_CREDIT_MAP` | 74 | FIFO credit update (fwsignal) |
| `ACTION_FRAME_RX` | 75 | Action frame received |
| `TDLS_PEER_EVENT` | 92 | TDLS peer state |
| `BCMC_CREDIT_SUPPORT` | 127 | Broadcast/multicast credit support |

## Event status codes

| Value | Name |
|-------|------|
| 0 | `BRCMF_E_STATUS_SUCCESS` |
| 1 | `BRCMF_E_STATUS_FAIL` |
| 2 | `BRCMF_E_STATUS_TIMEOUT` |
| 3 | `BRCMF_E_STATUS_NO_NETWORKS` |
| 4 | `BRCMF_E_STATUS_ABORT` |
| 5 | `BRCMF_E_STATUS_NO_ACK` |
| 6 | `BRCMF_E_STATUS_UNSOLICITED` |
| 7 | `BRCMF_E_STATUS_ATTEMPT` |
| 8 | `BRCMF_E_STATUS_PARTIAL` |
| 9 | `BRCMF_E_STATUS_NEWSCAN` |
| 10 | `BRCMF_E_STATUS_NEWASSOC` |
| 11 | `BRCMF_E_STATUS_11HQUIET` |
| 12 | `BRCMF_E_STATUS_SUPPRESS` |
| 13 | `BRCMF_E_STATUS_NOCHANS` |
| 15 | `BRCMF_E_STATUS_CS_ABORT` |
| 16 | `BRCMF_E_STATUS_ERROR` |

Firmware supplicant (`PSK_SUP`) status codes occupy the same field but have different meanings:

| Value | Name |
|-------|------|
| 4 | `BRCMF_E_STATUS_FWSUP_WAIT_M1` |
| 5 | `BRCMF_E_STATUS_FWSUP_PREP_M2` |
| 6 | `BRCMF_E_STATUS_FWSUP_COMPLETED` |
| 7 | `BRCMF_E_STATUS_FWSUP_TIMEOUT` |
| 8 | `BRCMF_E_STATUS_FWSUP_WAIT_M3` |
| 9 | `BRCMF_E_STATUS_FWSUP_PREP_M4` |
| 10 | `BRCMF_E_STATUS_FWSUP_WAIT_G1` |
| 11 | `BRCMF_E_STATUS_FWSUP_PREP_G2` |

## Event flags

| Value | Name | Meaning |
|-------|------|---------|
| 0x01 | `BRCMF_EVENT_MSG_LINK` | Link is up |
| 0x02 | `BRCMF_EVENT_MSG_FLUSHTXQ` | Flush TX queue |
| 0x04 | `BRCMF_EVENT_MSG_GROUP` | Group key |

## Event reason codes

Link/roam reason codes:

| Value | Name |
|-------|------|
| 0 | `BRCMF_E_REASON_INITIAL_ASSOC` |
| 1 | `BRCMF_E_REASON_LOW_RSSI` |
| 2 | `BRCMF_E_REASON_DEAUTH` |
| 3 | `BRCMF_E_REASON_DISASSOC` |
| 4 | `BRCMF_E_REASON_BCNS_LOST` |
| 5 | `BRCMF_E_REASON_FAST_ROAM_FAILED` |
| 6 | `BRCMF_E_REASON_DIRECTED_ROAM` |
| 8 | `BRCMF_E_REASON_BETTER_AP` |

Value 4 is also `BRCMF_E_REASON_LINK_BSSCFG_DIS` when used with the `LINK` event (bsscfg disabled).

TDLS peer event reason codes:

| Value | Name |
|-------|------|
| 0 | `BRCMF_E_REASON_TDLS_PEER_DISCOVERED` |
| 1 | `BRCMF_E_REASON_TDLS_PEER_CONNECTED` |
| 2 | `BRCMF_E_REASON_TDLS_PEER_DISCONNECTED` |

IF event actions:

| Value | Name |
|-------|------|
| 1 | `BRCMF_E_IF_ADD` |
| 2 | `BRCMF_E_IF_DEL` |
| 3 | `BRCMF_E_IF_CHANGE` |

IF event roles:

| Value | Name |
|-------|------|
| 0 | `BRCMF_E_IF_ROLE_STA` |
| 1 | `BRCMF_E_IF_ROLE_AP` |
| 2 | `BRCMF_E_IF_ROLE_WDS` |
| 3 | `BRCMF_E_IF_ROLE_P2P_GO` |
| 4 | `BRCMF_E_IF_ROLE_P2P_CLIENT` |

## Event registration and activation

Handlers are registered by event code into the firmware-event handler table.

After registration, the driver builds an `event_msgs` bitmask and pushes it to firmware. The `IF` event bit is always enabled by the event subsystem, even if no explicit handler was registered for it.

The firmware-vendor module may override or extend event activation.

## Reception and queuing

Incoming event frames are validated before they are queued:
- the event code must be within the firmware-event table bounds
- except for `IF`, an event without a registered handler is dropped
- payload length must not exceed `BRCMF_DCMD_MAXLEN`
- payload length must fit inside the received frame

Accepted events are copied into an internal queue item and processed later by a worker thread.

## Worker dispatch

The worker thread:
1. dequeues the next queued event
2. maps the firmware event code to the driver-visible event code when vendor mappings are in use
3. converts common event-header fields from big-endian to host byte order
4. resolves the target interface
5. dispatches to the registered handler

There is one notable dispatch exception in this tree:
- `TDLS_PEER_EVENT` is dispatched to `iflist[0]` rather than to `iflist[bsscfgidx]`

## Interface (`IF`) event handling

`IF` events are handled specially before normal callback dispatch.

The implementation:
- ignores most `NOIF` interface events
- preserves the special P2P-device setup case that also uses `NOIF`
- validates interface index bounds
- on `IF_ADD`, creates the interface object and attaches it to the protocol layer for non-P2P-device interfaces
- on `IF_CHANGE`, resets protocol-side state for that interface
- on `IF_DEL`, removes the interface if no higher-level code is waiting for the event

After this interface-specific handling, the normal `IF` event handler is called if registered.

## Connection-state classification

Connection-state handlers classify events into link-up, link-down, and connection-failure cases.

### Link up

Without firmware supplicant, link-up is recognized when:
- event = `SET_SSID`
- status = `SUCCESS`

With firmware supplicant in PSK or SAE mode, link-up requires both:
- `SET_SSID` with `SUCCESS`
- `PSK_SUP` with firmware-supplicant status `FWSUP_COMPLETED`

The implementation records the two partial-success conditions separately and only reports link-up once both have occurred.

### Link down

Link-down is recognized for:
- `DEAUTH`
- `DEAUTH_IND`
- `DISASSOC_IND`
- `LINK` with the link bit cleared

When these events arrive, transient connection-success bits are cleared.

### Connection failure / no-network

The implementation treats these as connection-failure cases:
- `LINK` with status `NO_NETWORKS`
- `SET_SSID` with any non-success status
- `PSK_SUP` with any status other than firmware-supplicant completion

That last case is required for correct WPA/SAE failure handling.

## Other handler behavior

### Roaming

A successful `ROAM` event triggers roam completion if the interface is already marked connected. Otherwise the roam success is treated like connection completion.

### MIC failure

`MIC_ERROR` reports a Michael MIC failure, with pairwise/group classification derived from the event flags.

### RSSI

`RSSI` events update the cached RSSI state and generate cfg80211 CQM threshold notifications when the configured low/high thresholds are crossed.
