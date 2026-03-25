# SDIO bus and runtime behavior in Linux brcmfmac

## Scope

This document describes the Linux SDIO transport used by brcmfmac for Broadcom/Cypress FullMAC chips such as BCM43455/CYW43455. It focuses on the parts that determine whether control traffic, management traffic, and data traffic can move after firmware boot.

The intended reader is implementing a clean-room SDIO driver and does not have the Linux code.

## Architecture summary

Linux splits the SDIO implementation into three layers:

1. SDIO host/card access layer
   - Enables SDIO functions
   - Sets block sizes
   - Provides CMD52/CMD53 accessors
   - Manages backplane window registers for function-1 memory access
   - Reads and writes the function-2 frame FIFO

2. SDPCM transport layer
   - Wraps every frame in an SDPCM header
   - Carries three relevant logical channels:
     - channel 0: control
     - channel 1: event
     - channel 2: data
   - Tracks host transmit sequence and firmware transmit window
   - Processes mailbox interrupts and frame indications

3. BCDC protocol layer on top of SDPCM
   - Encodes control requests/responses
   - Encodes per-packet data headers
   - Optionally inserts or parses firmware-signalling TLVs between the BCDC header and payload

A critical point: Linux does not treat SDIO as just a raw pipe. Runtime correctness depends on mailbox processing, SDPCM transmit window handling, and BCDC firmware-signalling initialization.

## SDIO functions and block sizes

Linux enables function 1 first, then function 2.

Function roles:
- Function 1:
  - CCCR/FBR access
  - miscellaneous SDIO core registers
  - backplane memory/register access through the window registers
- Function 2:
  - frame FIFO used for SDPCM traffic

Configured block sizes:
- function 1: 64 bytes
- function 2: usually 512 bytes
- exceptions exist for some chips:
  - 4373: 256
  - 435x family: 256
  - 4329: 128

For BCM43455/CYW43455, Linux uses function-2 block size 512 bytes.

This is not a cosmetic choice. The transport is designed around block-aligned frame transfers, with some reads using exact frame length rounded to bus requirements.

## Backplane access through function 1

Backplane accesses use a 32 KB window selected by three function-1 registers:
- SBADDRLOW
- SBADDRMID
- SBADDRHIGH

Behavior:
- The host caches the current 32 KB window base.
- Before a backplane access, if the target address lies outside the cached window, the host writes the three window bytes.
- The low 15 bits of the target address become the offset within the selected window.
- A separate flag marks 32-bit access width.

This mechanism is used for:
- SDIO core registers in the backplane address space
- chipcommon and other cores during chip setup
- firmware RAM download and verification
- mailbox registers

## Function-2 FIFO access

Function 2 is used in fixed-address FIFO mode for frame traffic.

Linux uses CMD53 reads/writes in fixed-address FIFO mode against the ChipCommon core base address. The backplane window is programmed for the ChipCommon base; the actual CMD53 offset is derived as `cc_base & SBSDIO_SB_OFT_ADDR_MASK` with `SBSDIO_SB_ACCESS_2_4B_FLAG` ORed in for 32-bit access. This is not the SDIO core base address. The logical interpretation is FIFO traffic, not random-access memory.

The bus layer supports:
- single-buffer read/write
- scatter-gather transfers
- glommed receive chains

The important semantic point is that function-2 traffic is serialized by the SDPCM runtime model. Linux does not permit arbitrary concurrent access patterns that would race control traffic, receive traffic, and transmit traffic against each other.

## Clock and sleep control

Linux explicitly manages SDIO/backplane clock state.

Clock states:
- none
- SD-only
- pending
- available

Two mechanisms matter:

1. CHIPCLKCSR register
   - used to request ALP or HT clock
   - used to observe ALP/HT availability

2. KSO sleep control for chips with save/restore support
   - uses SLEEPCSR KSO bit
   - polls until the write is reflected back
   - on wake, requires both KSO and DEVON bits

The DPC path ensures the bus is awake before processing pending work.

This matters because frame traffic and mailbox processing are defined against an awake device with a live backplane clock. A driver that boots firmware correctly but does not maintain the runtime clock discipline can fail later in ways that look like protocol bugs.

## SDPCM frame format

Every SDIO frame uses an SDPCM header.

Normal frame layout:
- hardware header: 4 bytes
  - length: 16-bit little-endian
  - checksum: bitwise inverse of length
- software header: 8 bytes
  - byte 0: sequence number
  - byte 1: channel in low nibble (bits 3:0), flags in high nibble (bits 7:4)
  - byte 2: next-frame length in 16-byte units for receive path
  - byte 3: data offset in 4-byte units
  - byte 4: flow-control bitmap from firmware to host
  - byte 5: maximum transmit sequence accepted by firmware
  - bytes 6-7: reserved

Transmit glom adds an 8-byte hardware extension between the hardware and software headers.

Logical channels:
- 0 control
- 1 event
- 2 data
- 3 glom descriptor/superframe
- 15 test/debug

Receive-side parser checks:
- hardware length/checksum consistency
- minimum header size
- valid channel for frame type
- valid data offset, which must be within frame bounds and at least the header length
- receive sequence continuity
- receive-side next-frame length sanity
- flow-control bitmap update
- transmit-window update from the firmware-provided max sequence field

## Transmit sequence window: mandatory SDPCM flow control

Linux maintains two counters:
- `tx_seq`: next host SDPCM sequence number to use
- `tx_max`: highest sequence number the firmware currently allows

Transmit eligibility tests are simple but critical.

For data frames:
- data may be sent only if `(tx_max - tx_seq - reserved)` is non-zero and does not have bit 7 set
- Linux reserves two credits for control frames when a control frame is pending

For control frames:
- a control frame may be sent only if `(tx_max - tx_seq)` is non-zero and does not have bit 7 set

Interpretation:
- the subtraction is performed in 8-bit sequence space
- bit 7 set means the host is beyond the permitted half-window and must not transmit
- this is the SDPCM transmit credit/window mechanism

Linux updates `tx_max` from every receive header. It is not informational. It gates all host transmission.

A clean-room implementation that records the field but does not enforce it is not SDPCM-correct.

## Mailbox and interrupt model

The SDIO core exposes interrupt status bits and mailbox data.

Important interrupt bits:
- host mailbox software bits
- frame indication
- flow-control state and flow-control change
- chip active
- various framing/error bits

Linux host mask of interest is effectively:
- all to-host mailbox software bits
- chip-active

Mailbox semantic bits in to-host mailbox data:
- NAK handled
- device ready
- firmware ready
- firmware halted
- flow-control bitmap data for old firmware variants

Linux behavior when processing host mailbox:
- read `tohostmailboxdata`
- acknowledge via `tosbmailbox` with interrupt-ack bit
- if firmware halted bit is set, trigger crash handling
- if NAK handled is set, clear rxskip and schedule frame processing
- if device ready or firmware ready is set, record SDPCM protocol version and fetch console pointer
- if old mailbox flow-control update is present, update per-priority flow-control bitmap

Two consequences matter:

1. Mailbox processing is not optional
   - firmware-ready signalling is observed here
   - NAK recovery is observed here
   - crash/halt is observed here

2. Frame indication is not the whole runtime protocol
   - mailbox and frame traffic are coupled
   - the DPC loop handles both together

## DPC runtime loop

Linux uses a deferred procedure call loop as the central SDIO runtime engine.

The loop does, in order:

1. Ensure pending HT clock transition is resolved if needed.
2. Wake the bus / ensure backplane clock availability.
3. If an interrupt is pending, read and acknowledge interrupt status.
4. Merge any previously deferred interrupt bits.
5. If flow-control-change bit is present:
   - acknowledge it
   - re-read interrupt status
   - recompute the flow-control state conservatively
6. If host-mailbox-interrupt bit is present:
   - process mailbox data
   - mailbox processing can synthesize additional frame-indication work
7. Drop the host lock.
8. Handle diagnostic interrupt bits.
9. If rxskip is active, suppress frame indication.
10. If frame indication is set and clocks are available:
    - read up to `rxbound` frames
11. Re-queue any still-pending interrupt bits.
12. If a control frame is pending and transmit window allows it:
    - send the control frame
    - wake waiters
13. If data queue is non-empty, firmware is not flow-controlling, and transmit window allows it:
    - send queued data, bounded by `txbound`, or by `txminmax` if receive work remains
14. If errors occurred or the bus state is no longer DATA:
    - halt further operation and fail pending control traffic
15. Otherwise, if more work remains:
    - retrigger the DPC

This loop is the runtime contract. Linux does not split control, receive, mailbox, and data scheduling into unrelated polling tasks.

## Receive path

### Frame indication and read count

On frame indication, Linux reads up to `rxbound` frames per DPC iteration. The default bound is 50.

### Header-first parsing

The driver first reads enough header bytes to determine:
- total frame length
- channel
- data offset
- next frame length
- host flow-control bitmap
- transmit window update (`tx_max`)

### Channel dispatch

After SDPCM parsing:
- channel 0 control frame
  - saved into a dedicated receive-control buffer
  - waiting control-response code is awakened
- channel 1 event frame
  - passed to the common receive path as an event
- channel 2 data frame
  - passed to the common receive path as data
- channel 3 glom descriptor/superframe
  - parsed and then used to pull a chain of subframes

### Glom receive

Linux supports receive glomming.

High-level behavior:
- a glom descriptor describes subframe lengths
- the host allocates a chain of buffers for the superframe
- function 2 reads the entire superframe into the chain
- each subframe is validated with SDPCM parsing rules
- each validated subframe is stripped to payload and dispatched as event or data

Even if a new implementation initially omits glom, the normal receive path still must implement the same SDPCM header semantics, especially flow-control and transmit-window updates.

## Control path over SDPCM channel 0

Control traffic is synchronous at the API boundary but asynchronous on the bus.

Transmit side:
- caller places the control frame buffer and length into shared bus state
- sets a pending flag
- triggers DPC
- waits on a completion condition with a timeout
- DPC sends the control frame only when transmit window permits

Receive side:
- control responses arrive on SDPCM channel 0
- the frame payload is copied into the dedicated control-response buffer
- the waiting thread is awakened

Important details:
- Linux reserves transmit window for control traffic even when data is queued
- Linux does not bypass the DPC for control traffic
- control and data both consume SDPCM transmit sequence numbers

## Data path scheduling and queueing

Linux keeps a transmit packet queue in the SDIO bus layer.

Per-packet dequeue is constrained by:
- host-side per-priority flow-control bitmap from firmware
- SDPCM transmit window (`data_ok`)
- DPC `txbound` scheduling limit

If transmit queue length exceeds a high watermark, the driver blocks upper network queues. It re-enables them below a low watermark.

This is separate from SDPCM sequence-window control. Both apply.

## Relationship between SDPCM flow control and BCDC firmware signalling

There are two distinct flow-control domains.

1. SDPCM transport window
   - exposed in every receive header as `tx_max`
   - mandatory for all SDPCM traffic, including control traffic

2. BCDC firmware signalling / WLFC / proptxstatus
   - optional at the protocol feature level, but used by Linux for BCDC over SDIO/USB
   - carries per-packet and per-fifo signalling in TLV metadata
   - coordinates packet queueing, txstatus, and credit return above the raw SDPCM transport

Confusing these two leads to bad diagnoses. A driver can implement SDPCM framing and still fail because BCDC firmware signalling was not initialized. It can also fail because `tx_max` was ignored even if TLV signalling exists.

## Error handling relevant to runtime stability

Linux has explicit recovery for receive and transmit framing failures.

Receive failure handling can:
- abort function 2 read
- terminate current receive frame
- optionally send NAK to request retransmission
- set `rxskip` until firmware reports the NAK was handled via mailbox

Transmit failure handling can:
- abort function 2 write
- terminate current write frame
- poll write-frame byte counters until the FIFO is flushed

This matters because repeated malformed or out-of-window traffic can leave the SDIO frame engine in a broken state if the host does not perform the matching termination sequence.

## Bus state transitions

The SDIO device state exposed upward is:
- DOWN
- DATA
- NOMEDIUM

Transitions to DATA cause the common bus state to move to UP.
Transitions away from DATA cause the common bus state to move to DOWN.

Upper layers will queue or reject network traffic based on that shared bus state, but this does not replace the lower-level SDPCM and firmware-signalling constraints.

## Facts directly relevant to the authentication blocker

For an implementation targeting CYW43455 on SDIO, Linux behavior establishes the following facts:

1. Linux enforces the SDPCM transmit window before sending both control and data traffic.
2. Linux processes mailbox interrupts as part of the normal runtime loop, not as optional diagnostics.
3. Linux sends control traffic through the same DPC engine that handles mailbox, RX, and data TX.
4. Linux always creates a firmware-signalling object in BCDC `init_done`, but full TLV/credit bring-up occurs only when queueing is enabled — either the bus sets `always_use_fws_queue`, or `fcmode` is non-zero. On the default SDIO path (`fcmode=NONE`, no forced queueing) Linux creates the object in reduced mode (`avoid_queueing=true`) and does not send the `tlv` iovar or enable BDCv2 TLV signalling.
5. Linux does not treat successful firmware boot, successful scan, and successful ioctls as proof that SDIO runtime is complete.
6. Linux uses a single integrated runtime model; a polling-only receive loop without equivalent mailbox and credit handling is not behaviorally equivalent.

## What a critical reader should object to

A skeptical reader should reject these simplifications:

- "If ioctl works, SDIO transport is complete."
  - False. Control-response exchange can work while mailbox, TX window, or BCDC signalling is still incomplete.

- "Management frames do not depend on the normal TX runtime because they come from firmware."
  - In Linux's BCDC/SDIO design, the firmware-signalling and txstatus model is specifically used to coordinate host/firmware packet handling. You cannot assume management traffic is unaffected by missing protocol initialization.

- "The max-sequence field is probably advisory because scans and events work without it."
  - False. Linux gates transmission on it.

- "Mailbox data pending after boot can be ignored if frame indication works."
  - False. Linux reads and acknowledges mailbox data as part of normal startup/runtime handling.

## Clean-room implementation checklist

A transport implementation equivalent to Linux needs, at minimum:

- function-1 backplane window management
- function-2 FIFO transfer path
- SDPCM framing for control, event, and data channels
- receive-side parser that updates:
  - per-priority host flow-control bitmap
  - `tx_max`
- enforcement of the SDPCM transmit window for:
  - control frames
  - data frames
- mailbox read/ack path for to-host mailbox data
- integrated runtime loop that combines:
  - interrupt status processing
  - mailbox handling
  - RX processing
  - control TX
  - data TX
- proper frame-abort/terminate handling on transfer errors

Without those pieces, a driver may look functional during boot and scan, yet still fail at first association.
