# SDIO Bus Layer

## Overview

The SDIO bus layer handles:
- Backplane access through SDIO function 1 (CMD52/CMD53)
- Frame data transfer through SDIO function 2
- SDPCM framing for all host–firmware communication
- Clock and power management
- Firmware download into chip RAM
- Deferred processing context (DPC) for RX and TX

## Hardware model

Broadcom FullMAC SDIO chips expose two SDIO functions:

| Function | Block size | Purpose |
|----------|-----------|---------|
| F1 | 64 bytes | Register/backplane access (CMD52/CMD53) |
| F2 | Chip-specific | Frame data transfer |

F2 block size overrides by SDIO device ID:
- BCM4329: 128
- BCM4354, BCM4356, BCM4359: 256
- BCM/Cypress 4373: 256
- Default (including BCM43455): 512

## Backplane access

### Address windowing

The SDIO bus uses a 32-bit backplane address space, but the SDIO interface only exposes a smaller address window. To access a specific backplane address:

1. Compute the target 32-bit address from the core base plus register offset.
2. Mask the address to bits 31:15 (the window base). If it differs from the current window, reprogram the three window registers. The window base is shifted right by 8, then written byte-by-byte to three consecutive registers:
   - `SBSDIO_FUNC1_SBADDRLOW` (`0x1000A`): gets bits 15:8 of the address (1 byte)
   - `SBSDIO_FUNC1_SBADDRMID` (`0x1000B`): gets bits 23:16
   - `SBSDIO_FUNC1_SBADDRHIGH` (`0x1000C`): gets bits 31:24
3. Access the register using the lower 15 bits of the address as the F1 offset.

### Register access

- **Byte access**: CMD52 reads/writes to F1. Used for control registers.
- **Word access**: CMD53 block or byte mode to F1 at 4-byte aligned offsets.
- All word accesses must be 4-byte aligned; misaligned accesses produce undefined results.

### Backplane clock management

Before accessing backplane registers, the host must ensure the appropriate clock is available. The clock control/status register (`SDIO_FUNC1_CHIPCLKCSR`, F1 register `0x1000E`) supports these request and status bits:

| Value | Name | Purpose |
|-------|------|---------|
| 0x01 | `SBSDIO_FORCE_ALP` | Force ALP clock on |
| 0x02 | `SBSDIO_FORCE_HT` | Force HT clock on |
| 0x08 | `SBSDIO_ALP_AVAIL_REQ` | Request ALP clock |
| 0x10 | `SBSDIO_HT_AVAIL_REQ` | Request HT clock |
| 0x20 | `SBSDIO_FORCE_HW_CLKREQ_OFF` | Squelch clock requests from HW |
| 0x40 | `SBSDIO_ALP_AVAIL` | ALP clock available (status, read-only) |
| 0x80 | `SBSDIO_HT_AVAIL` | HT clock available (status, read-only) |

The driver selects between `HT_AVAIL_REQ` and `ALP_AVAIL_REQ` depending on context (e.g., `alp_only` flag during early init). Some code paths use `FORCE_HT` instead of `HT_AVAIL_REQ`.

Typical sequence:
1. Write `HT_AVAIL_REQ` (or `ALP_AVAIL_REQ` for early init) to `CHIPCLKCSR`.
2. Poll until the corresponding availability bit (`HT_AVAIL` or `ALP_AVAIL`) is set, with a timeout.
3. After the access window, clear the request/force bits to allow the chip to return to low power.

## SDPCM framing

All data and control messages between host and firmware are encapsulated in SDPCM frames. A frame consists of:

### Frame header (12 bytes)

| Offset | Size | Field |
|--------|------|-------|
| 0 | 2 | Frame length (LE) |
| 2 | 2 | Frame length complement (~length, for validation) |
| 4 | 1 | Sequence number |
| 5 | 1 | Channel (low 4 bits); bit 7 = glom descriptor flag |
| 6 | 1 | Next frame length (for glom) |
| 7 | 1 | Data offset (from start of frame to payload) |
| 8 | 1 | Flow control (firmware → host) |
| 9 | 1 | Max sequence number allowed (firmware → host) |
| 10 | 2 | Reserved/padding |

When TX aggregation (`txglom`) is enabled, an 8-byte HW extension header is inserted between bytes 4–11 (between the HW header and SW header), making the total header 20 bytes:

| Offset | Size | Field |
|--------|------|-------|
| 0 | 4 | `(frame_len - hdr_offset) | (last_frame << 24)` |
| 4 | 4 | `(tail_padding << 16)` |

### Channel types

| Channel | Value | Purpose |
|---------|-------|---------|
| Control | 0 | IOCTL request/response |
| Event | 1 | Firmware event messages |
| Data | 2 | Ethernet data frames |
| Glom | 3 | Frame aggregation descriptor |

### Frame validation

On reception, the host validates:
1. The frame length and its complement match (`length ^ complement == 0xFFFF`).
2. The data offset does not exceed the frame length.
3. The sequence number is as expected (mismatches are logged but not rejected; the expected counter resets to the received value).

## DPC (Deferred Processing Context)

The SDIO bus uses a dedicated kernel thread for all bus I/O. The DPC thread:

1. Checks for pending interrupts (either from SDIO interrupt or polled).
2. Reads the interrupt status register.
3. Processes mailbox interrupts (firmware-to-host signaling).
4. Checks for frame-available status on F2.
5. Reads available frames (RX path).
6. Transmits pending frames (TX path).
7. Re-enables interrupts if needed.

The DPC is triggered by:
- SDIO interrupt callback
- Timer-based polling (when using poll mode)
- TX request from upper layers

## Firmware download

### Sequence

1. Identify the chip using backplane enumeration.
2. Ensure the ARM core is halted (`CPUHALT` in the core's IOCTL register).
3. Write firmware binary to chip RAM starting at `rambase`.
4. Write NVRAM to the end of RAM (`rambase + ramsize - nvram_len`), with NVRAM length encoded in the last 4 bytes.
5. Reset and release the ARM core with the reset vector from the first word of the firmware image.
6. Wait for F2 to become ready (firmware sets an F2-ready bit when initialization completes).

### NVRAM encoding

NVRAM is written as raw key=value pairs (NUL-terminated), zero-padded so that `(nvram_len + 1)` rounds up to a 4-byte boundary. The 4-byte length token is appended after the padded data. The token encodes the padded length in 32-bit words:

```
words = padded_length / 4
token = (~words << 16) | (words & 0xFFFF)
```

The token is stored as a 32-bit little-endian value. Total NVRAM blob size = padded_length + 4.

## TX path

1. Upper layer calls bus `txdata` or `txctl`.
2. Frame is prepended with an SDPCM header specifying the appropriate channel.
3. For data frames, the BCDC header sits between the SDPCM header and the Ethernet payload.
4. The frame is queued in the bus TX queue.
5. The DPC thread dequeues and transmits via CMD53 to F2.
6. After successful F2 write, advance the SDPCM sequence number.

### Flow control

Firmware signals available TX credits via the max-sequence field in received SDPCM headers. The host tracks outstanding frames and stops transmitting when the sequence number would exceed the firmware's max sequence.

## RX path

1. The DPC thread detects pending data via an F2 interrupt or by reading the frame-available status.
2. Read the frame header (first 4 bytes) to learn the total frame length.
3. Read the full frame via CMD53 from F2.
4. Validate the SDPCM header.
5. Extract the channel to determine if the payload is control, event, or data.
6. Strip the SDPCM header (data-offset bytes from the start).
7. Pass the payload to the protocol layer (BCDC) for further header processing.

### Glom (frame aggregation)

When the glom channel is used, the firmware sends a descriptor indicating multiple frames are aggregated into a single SDIO transfer. The host:

1. Reads the glom descriptor to learn per-frame lengths.
2. Reads all frames in a single large CMD53 transfer.
3. Splits the received data into individual frames using the per-frame lengths.
4. Processes each sub-frame independently.

## Power management

### Sleep/wake

The chip can enter a low-power sleep state. Before any bus access:

1. Check if the chip is awake by reading the `ALPAV` bit in `CHIPCLKCSR`.
2. If not awake, write `FORCE_HT` and wait for `HT_AVAIL`.
3. After the access window, allow the chip to sleep by clearing `FORCE_HT`.

### Keep-alive

The host uses a watchdog timer to periodically check bus activity. If idle for a configured duration, the host allows the chip to enter deep sleep.

## SDIO device table

Devices are identified by SDIO vendor `0x02D0` (Broadcom). Each device ID maps to a chip model and firmware name. The driver registers as an SDIO function driver for these IDs.
