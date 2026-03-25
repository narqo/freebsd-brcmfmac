# BCDC, firmware signalling, and association behavior in Linux brcmfmac SDIO

## Scope

This document describes the Linux BCDC protocol layer used on SDIO, the firmware-signalling subsystem attached to it, and the STA association path relevant to an authentication timeout on CYW43455.

The emphasis is on exact behavior that a clean-room implementation must replicate, not on Linux API details.

## Layering

For SDIO, Linux uses:
- SDPCM as the transport framing layer
- BCDC as the protocol layer
- firmware signalling (`fwsignal`, also called WLFC / proptxstatus support) as an extension on top of BCDC

BCDC is not complete without considering firmware signalling, because Linux wires the two together in the protocol attach path.

## BCDC control protocol

### Control message structure

BCDC control requests and responses use a 16-byte header:
- command: 32-bit little-endian
- length: 32-bit little-endian
  - full payload byte count as a single 32-bit LE value
  - (source comments describe a split low/high 16-bit layout, but the implementation writes and reads the complete byte count without splitting)
- flags: 32-bit little-endian
  - set/get bit
  - interface index field
  - request identifier field
- status: 32-bit little-endian

The host assigns a monotonically increasing request ID and embeds it in the flags field.

### Control request flow

For a set or query operation:
1. Fill the BCDC control header.
2. Copy payload immediately after it.
3. Send the control frame through the bus control-TX path.
4. Wait for a control response from SDPCM channel 0.
5. Reject responses whose request ID does not match.
6. If the BCDC error flag is set, use the returned firmware status.

Linux allows retries only in a narrow case for query completion matching; it does not hide systematic transport/runtime bugs.

## BCDC data header

Every BCDC data packet starts with a 4-byte header:
- flags
  - includes BCDC protocol version
  - checksum offload bits
- priority
- flags2
  - includes interface index
- data_offset
  - number of 4-byte words between the end of the 4-byte BCDC header and the start of the actual payload

This `data_offset` is the bridge to firmware signalling.

Interpretation:
- data_offset == 0 means payload starts immediately after the BCDC header
- data_offset > 0 means there are extra bytes between the BCDC header and the real payload
- those extra bytes are firmware-signalling TLVs when signalling is enabled

On receive:
- Linux strips the 4-byte BCDC header
- then either:
  - calls firmware-signalling header parsing on the `data_offset << 2` bytes, or
  - blindly skips those bytes if firmware signalling is not being used

## Why `init_done` matters on BCDC

Linux has a protocol object with an optional `init_done` callback.

Actual attach order (combining `brcmf_attach` and `brcmf_bus_started`) is:
1. create primary interface (ifidx=0, bsscfgidx=0)
2. set bus state to `BRCMF_BUS_UP`
3. bus-specific preinit
4. common preinit commands (MAC, revinfo, firmware version, country)
5. feature attach
6. protocol `init_done`
7. configure primary interface on protocol (`proto_add_if`)
8. cfg80211 attach
9. netdev attach

The primary interface must exist before `init_done` because firmware-signalling attach fetches interface 0. Bus state must be UP before any FWIL traffic in common preinit commands.

For BCDC, `init_done` is implemented and is not a stub. It attaches firmware signalling.

Behavior:
- `brcmf_proto_bcdc_init_done()` calls `brcmf_fws_attach()`
- the returned firmware-signalling context is stored in the BCDC private state

This is the main Linux answer to the question, "what happens in BCDC init_done for SDIO?"

It is the point where Linux creates the firmware-signalling object. Whether full TLV/credit bring-up follows depends on configuration: it is active only when the bus forces queueing (`always_use_fws_queue`) or `fcmode` is non-zero. On the default SDIO path neither condition holds, so the object is created in reduced mode (`avoid_queueing=true`) without TLV initialization.

## Firmware signalling attach sequence

Linux firmware-signalling attach does the following.

### 1. Allocate state and decide whether queueing is active

It allocates a large control structure that contains:
- packet hanger for packets awaiting txstatus
- per-destination/interface state
- per-fifo credits
- delayed/suppressed queues
- workqueue for deferred dequeue

It reads the configured host flow-control mode.

Modes:
- none
- implied credit
- explicit credit

If:
- the bus does not force firmware-signalling queues (`always_use_fws_queue` is false), and
- configured flow-control mode is none (the default for SDIO),
then Linux returns early, setting only `avoid_queueing = true`.

This early-return path skips all remaining steps: no workqueue is created, no event handlers are registered, no `tlv` iovar is sent, and no `ampdu_hostreorder` or `wlfc_mode` is configured. The firmware-signalling object exists but carries no active protocol.

On the default SDIO path this early return is taken. USB is the bus type that sets `always_use_fws_queue = true`.

### 2. Register firmware event handlers

Linux registers handlers for:
- FIFO credit map event
- BCMC credit support event

These events feed the host-side credit model.

### 3. Build the `tlv` iovar bitmask

This step is only reached when queueing is active (not the default SDIO path).

Linux starts with:
- RSSI signals enabled

If firmware-signalled flow control is active, Linux also enables:
- XON/XOFF signals
- credit status signals
- host proptxstatus active
- host RX reorder active

On the default SDIO path (`fcmode=NONE`, no forced queueing) the early return in step 1 is taken and the `tlv` iovar is never sent.

### 4. Send `tlv` iovar

Linux sets the `tlv` iovar on interface 0.

If this fails:
- driver initialization continues
- firmware-signalling mode is downgraded to none
- `fw_signals` is marked false

Therefore:
- the iovar is important
- Linux tolerates unsupported firmware
- but when supported, this is the mechanism used to request BDC v2 TLV signalling

### 5. Try to enable AMPDU host reorder

Linux sends:
- `ampdu_hostreorder = 1`

Failure is logged but not fatal.

This aligns with field evidence that some firmware does not support it.

### 6. Try to enable WLFC sequence reuse mode

Linux queries `wlfc_mode`.
If supported, it may enable sequence reuse.
This affects the layout of the PKTTAG TLV and TXSTATUS parsing.

### 7. Initialize host-side structures

Linux initializes:
- packet hanger
- catch-all MAC descriptor
- per-destination/interface packet queues
- dequeue worker

## Meaning of firmware signalling in practice

Firmware signalling is not one bit. It is a host/firmware protocol carried in TLVs inserted between the BCDC header and payload.

Defined TLV types include:
- MAC_OPEN
- MAC_CLOSE
- MAC_REQUEST_CREDIT
- TXSTATUS
- PKTTAG
- MACDESC_ADD
- MACDESC_DEL
- RSSI
- INTERFACE_OPEN
- INTERFACE_CLOSE
- FIFO_CREDITBACK
- PENDING_TRAFFIC_BMP
- MAC_REQUEST_PACKET
- HOST_REORDER_RXPKTS
- TRANS_ID
- COMP_TXSTATUS
- FILLER

Three parts matter most for the blocker analysis.

### PKTTAG on host-to-firmware data packets

When queueing/signalling is active, Linux prepends a PKTTAG TLV to outgoing data packets.

The tag carries a 32-bit host packet identifier with fields for:
- generation
- status/flags
- FIFO/AC
- hanger slot
- free-running counter

Optionally it also carries a reused sequence value.

That tag is how Linux matches later TXSTATUS indications to the original transmitted skb.

### TXSTATUS and COMP_TXSTATUS from firmware

Firmware later returns TX status via signalling TLVs.
Linux uses these to:
- release packets from the hanger
- return credits
- identify suppressed packets
- finalize original skb completion

### FIFO credit map and creditback

The `FIFO_CREDIT_MAP` event handler is registered whenever queueing is active (both implied-credit and explicit-credit modes). It sets `creditmap_received` and updates per-fifo credit state; `brcmf_fws_fc_active()` requires `creditmap_received` before returning true. Only FIFO creditback signalling is restricted to explicit-credit mode.

## BCDC header handling and firmware signalling hooks

### Receive path

BCDC receive header handling does this:
1. Validate BCDC version.
2. Find the destination interface from the BCDC header.
3. Store packet priority.
4. Strip the 4-byte BCDC header.
5. If firmware signalling is enabled for this path:
   - parse and consume `data_offset << 2` bytes of TLVs
6. Otherwise:
   - simply skip `data_offset << 2` bytes
7. Deliver the remaining payload.

For receive data packets, Linux then lets the firmware-signalling layer decide whether the packet is actually a reorder indication instead of a normal payload.

### Transmit path

BCDC transmit queueing does this:
- if firmware-signalling queueing is inactive, transmit directly
- otherwise pass the skb into the firmware-signalling layer

The firmware-signalling layer may:
- assign a hanger slot
- choose an AC/FIFO
- prepend signalling TLVs
- queue/delay/suppress the packet until credits and firmware state allow it
- eventually call the lower bus transmit routine with a non-zero BCDC data offset

So in Linux, BCDC data transmission on SDIO is not just "prepend four bytes and send" once firmware signalling is active.

## Association path in Linux cfg80211

### High-level sequence

For a normal STA connect request Linux does, in order:

1. Choose the channel hint if present.
2. Choose the BSSID hint if present.
3. Extract WPA or RSN IE from the connect request and set the `wpaie` iovar when applicable.
4. Apply additional assoc-request vendor IEs.
5. Mark the interface as CONNECTING.
6. Record channel/chanspec if supplied.
7. Configure WPA version.
8. Configure authentication type.
9. Configure wsec mode.
10. Configure key-management / wpa_auth.
11. Configure shared-key state if needed.
12. Optionally enable firmware supplicant and install PMK for offloaded modes.
13. Build extended join parameters.
14. Try the `join` iovar.
15. If `join` fails, fall back to `BRCMF_C_SET_SSID` with basic join parameters.

### Security configuration details

Authentication type is set with `BRCMF_C_SET_AUTH`.
Infrastructure mode is set earlier via `BRCMF_C_SET_INFRA` when the interface type is station.

For WPA/WPA2/SAE flows, Linux programs:
- `wsec`
- `wpa_auth`
- sometimes `wpaie`
- optionally `sup_wpa`
- PMK if firmware supplicant/offload is used

For the primary non-P2P interface, Linux always calls the `wpaie` iovar after searching for a WPA or RSN IE. If neither is found (open network), `ie` is `NULL` and `ie_len` is 0, so the call sets `wpaie` to empty. The SAE firmware-supplicant path also issues an additional explicit `wpaie` clear for a separate reason.

### Join command fallback behavior

Linux first tries the `join` iovar with extended parameters:
- SSID
- target BSSID or broadcast BSSID
- optional single chanspec constraint
- join-scan dwell/probe timing values

If `join` fails, Linux falls back to `BRCMF_C_SET_SSID` using simpler join parameters.

Therefore, a report that `join` fails and Linux uses `SET_SSID` instead is consistent with Linux behavior.

That behavior alone is not evidence of a bug.

## How Linux decides connect success or failure

Linux does not treat the `SET_SSID` command return value as the final association result.

It waits for firmware events.

### Events registered for connect state

The cfg80211 layer registers handlers for:
- LINK
- DEAUTH_IND
- DEAUTH
- DISASSOC_IND
- ASSOC_IND
- REASSOC_IND
- ROAM
- SET_SSID
- PSK_SUP
- others unrelated to STA connect state

`AUTH` is not registered anywhere in this source tree. Plain `ASSOC` and `REASSOC` are not registered either; the source uses `ASSOC_IND` and `REASSOC_IND`.

### Link-up decision

Linux considers connection complete when:
- `SET_SSID` succeeds for non-firmware-supplicant cases, or
- both association success and firmware-supplicant success have been observed for offloaded-secure cases, or
- a `ROAM` event with `E_STATUS_SUCCESS` arrives when the interface is not yet marked connected (`brcmf_notify_roaming_status` calls `brcmf_bss_connect_done(..., true)` in this case)

### Non-network / failure decision

Linux treats these as connection failure:
- `LINK` event with status NO_NETWORKS
- `SET_SSID` event with non-success status
- `PSK_SUP` event with non-success status

### Link-down decision

Linux treats these as link-down:
- DEAUTH
- DEAUTH_IND
- DISASSOC_IND
- LINK without link flag

The success/failure contract is determined by `SET_SSID` event status, `LINK` event flags, `PSK_SUP` event status, and `ROAM` event status (for the not-yet-connected case). Firmware may report an internal AUTH timeout that surfaces as a failed `SET_SSID` event; `AUTH` itself is not a registered event handler in this source tree.

## What Linux actually proves about the blocker

From the Linux behavior above, several conclusions are solid.

### 1. `join` returning failure and fallback to `SET_SSID` is normal

This does not isolate the bug.

### 2. BCDC `init_done` is real and SDIO-relevant

Linux attaches firmware signalling in BCDC `init_done` before cfg80211 attach completes.

A clean-room SDIO implementation that has no protocol object, no `init_done`, and no firmware-signalling attach is not equivalent to Linux.

### 3. BCDC `init_done` runs on SDIO, but full firmware-signalling bring-up does not by default

Linux always runs `brcmf_fws_attach()` from BCDC `init_done`. On the default SDIO configuration (`fcmode=NONE`, `always_use_fws_queue` not set), this creates a firmware-signalling object in reduced mode and returns early — without creating a workqueue, registering credit-map event handlers, sending the `tlv` iovar, or enabling BDCv2 TLV signalling.

Full firmware-signalling bring-up (steps 2–7 in the attach sequence above) runs only when queueing is forced, which on Linux is the USB path.

The BCDC transmit/receive paths check for the signalling object, but on default SDIO the `avoid_queueing` flag routes traffic directly without TLV processing.

### 4. `tlv` iovar is not sent on the default SDIO path

On the default SDIO configuration, Linux takes the early return in `brcmf_fws_attach()` and never sends the `tlv` iovar. Claiming Linux sends a non-zero `tlv` bitmask for default SDIO is inaccurate.

The `tlv` bitmask — starting with RSSI signalling, extended with credit/flow signals when `fcmode` is non-zero — is only sent when queueing is active.

### 5. SDPCM transmit credit enforcement is independent of firmware signalling

Linux enforces `tx_max` in the SDIO layer regardless of higher-level signalling choices.

So there are at least two missing pieces that can independently break association:
- no SDPCM transmit-window enforcement
- no BCDC firmware-signalling attach/processing

### 6. Mailbox handling is part of normal runtime, not an optional diagnostic path

If mailbox data is present after boot and the host never reads/acks it, the runtime is not Linux-equivalent.

## Likely failure mechanisms consistent with Linux behavior

The clean-room report says:
- firmware boots
- scan works
- ioctls work
- `SET_SSID` is accepted
- firmware later reports AUTH timeout
- the implementation lacks BCDC `init_done` / fwsignal
- mailbox handling is incomplete
- `tx_max` is recorded but not enforced

A critical reading yields several plausible blocker mechanisms.

### Mechanism A: incomplete BCDC protocol bring-up

Linux always runs BCDC `init_done`, which creates a firmware-signalling object. On default SDIO the object runs in reduced `avoid_queueing` mode — no TLV processing, no credit signalling. A driver that skips `init_done` entirely differs from Linux, but the significance for default SDIO is narrower than if the full queueing/TLV path were active.

Objection a skeptic should raise:
- "Maybe management frames do not require fwsignal because they are firmware-generated."

Counterpoint:
- On default SDIO, Linux does not enable BDCv2 TLV signalling or host proptxstatus. The firmware-signalling object is created with `avoid_queueing=true`. Omitting `init_done` entirely is still not Linux-equivalent, but the critical missing piece is not the full USB-style TLV bring-up.

### Mechanism B: transmit window violation

If the host transmits control or data frames when `tx_seq` has advanced beyond `tx_max`, firmware behavior is undefined from the host's perspective.

Objection:
- "But scans and events work, so the transmit side must be mostly fine."

Counterpoint:
- scan requests are sparse control exchanges. Association is a tighter sequence with command traffic, event handling, and immediate follow-up activity. A latent transmit-window bug can remain hidden until then.

### Mechanism C: mailbox protocol incompleteness

If mailbox data is pending and the host never consumes/acks it, some firmware state transitions may not complete the way Linux expects.

Objection:
- "Frame indication already tells us when data is available."

Counterpoint:
- Linux explicitly processes mailbox data for firmware-ready, NAK recovery, halt detection, and old-style flow-control compatibility. Ignoring it is not Linux-equivalent.

### Mechanism D: wrong runtime scheduling model

Linux runs control TX, RX, mailbox, and data TX in one DPC engine. A design that instead mixes ad hoc polling, synchronous control writes, and unrelated receive workers can produce race conditions not present in Linux.

Objection:
- "If access to function 2 is serialized, that should be enough."

Counterpoint:
- serialization prevents only one class of races. It does not recreate Linux's ordering guarantees between mailbox processing, rx header updates, tx window updates, and control frame emission.

## What is not supported by the Linux evidence

Several claims are weaker than they may appear.

### "Linux requires `ampdu_hostreorder=1` for association"

Not supported.
Linux attempts it, but failure is explicitly tolerated.

### "Linux requires a separate explicit `wpaie` clear step for open networks on CYW43455"

Not supported as an independent step. The primary non-P2P connect path always calls the `wpaie` iovar; with no WPA/RSN IE (open network) it passes `NULL/0` implicitly as part of the normal connect sequence, not as a dedicated clearing step. Treating this as a distinct required action misrepresents the source.

### "Explicit channel set before join is necessary"

Not supported.
Linux includes an optional chanspec in join parameters when a channel hint exists, but the primary join path is still `join`/`SET_SSID`, not a separate mandatory `set channel` step.

## Clean-room requirements derived from Linux behavior

To match Linux closely enough for this problem space, an implementation needs all of the following.

### BCDC protocol layer

- 16-byte BCDC control message format with request IDs
- 4-byte BCDC data header with interface index and data-offset semantics
- correct receive-side stripping of BCDC header and data-offset region
- correct fallback from `join` iovar to `SET_SSID` in STA connect flow

### Protocol attach ordering

1. create primary interface (ifidx=0, bsscfgidx=0)
2. set bus state to `BRCMF_BUS_UP`
3. bus-specific preinit
4. common preinit commands
5. feature attach
6. BCDC `init_done`
7. configure primary interface on protocol (`proto_add_if`)
8. cfg80211 attach
9. netdev attach

### Firmware-signalling attach

Linux always calls `brcmf_fws_attach()` from BCDC `init_done`.

On the default SDIO path (`fcmode=NONE`, `always_use_fws_queue` not set), the attach returns early after setting `avoid_queueing=true`. No workqueue, no event handler registration, no `tlv` iovar, no `ampdu_hostreorder`, no `wlfc_mode` query.

A full firmware-signalling bring-up (needed for USB or when `fcmode` is configured) additionally:
- allocates the full host signalling state (hanger, queues, workqueue)
- registers credit-map and BCMC-credit event handlers
- sets the `tlv` iovar with the appropriate feature bitmask
- attempts `ampdu_hostreorder=1`, tolerating failure
- queries and, if supported, configures `wlfc_mode`
- wires BCDC TX/RX through the signalling header push/pull path

### Runtime processing

- parse signalling TLVs on receive when present
- maintain txstatus / hanger bookkeeping if signalling is active
- process FIFO credit map events whenever queueing is active (both implied and explicit credit modes); process FIFO creditback only in explicit credit mode
- integrate mailbox, RX, and TX in one runtime engine

### Connect path

- set `wpaie` from request IE when applicable
- set auth / wsec / wpa_auth in the same sequence class Linux uses
- build extended join parameters including BSSID and optional chanspec
- try `join`, then fall back to `SET_SSID`
- wait for firmware events to determine success/failure

## Bottom line

Linux does not support the idea that the SDIO path is complete once firmware boot, scan, and ioctls work.

For BCDC over SDIO on the default configuration, Linux relies on:
- SDPCM transport with enforced transmit window
- mailbox-driven runtime handling
- BCDC protocol attach with `init_done` (creating the firmware-signalling object, though in reduced `avoid_queueing` mode)

Full firmware-signalling bring-up (TLV/credit/queueing) is not part of the default SDIO path; it applies to USB and explicitly configured deployments where `fcmode` is non-zero or `always_use_fws_queue` is set.

Any one of those being absent can produce a system that looks alive yet times out at authentication.
