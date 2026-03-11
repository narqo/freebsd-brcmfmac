# PCIe Bus Layer

## Overview

The PCIe bus layer handles:
- Hardware initialization and reset
- Firmware download into device RAM via TCM
- DMA ring setup for the msgbuf protocol
- Interrupt handling (MSI, threaded)
- Power management (D3 suspend/resume)
- Firmware console log reading

## Hardware resources

### BAR mappings

| BAR | Mapped via | Size | Content |
|-----|-----------|------|---------|
| BAR0 | `regs` | 32 KB | PCIe core registers, chip common registers |
| BAR1 (PCI resource 2) | `tcm` | Variable | TCM (Tightly Coupled Memory) — firmware RAM |

BAR0 is a window into the chip's address space. The host must program `PCIE_BAR0_WINDOW` (config register `0x80`) to select which core's register block is visible through the first 4 KB of BAR0.

BAR1 directly maps firmware RAM. Its size is chip-dependent. If the BAR1 size or address is zero, the device cannot be used.

### BAR0 window management

To access registers of a specific core (e.g., ChipCommon, PCIe2):

1. Look up the core's base address via the chip enumeration.
2. Write that base address to PCI config register `0x80`.
3. Read it back to confirm; retry once on mismatch.
4. Access registers at `regs + (register_offset & 0xFFF)`.

For backplane addresses that span beyond a 4 KB window, mask the lower 12 bits to get the intra-window offset.

## Shared RAM protocol

After firmware boots, it writes a 32-bit address into the last 4 bytes of RAM (`rambase + ramsize - 4`). This address points to a shared info structure in TCM that the host reads to discover protocol version, ring locations, mailbox addresses, and other parameters.

### Shared info structure layout

The shared info block at `tcm_base_address` contains:

| Offset | Size | Field |
|--------|------|-------|
| 0 | 4 | Flags (low byte = protocol version) |
| 20 | 4 | Console address |
| 34 | 2 | Max RX buffer post count |
| 36 | 4 | RX data offset |
| 40 | 4 | H2D mailbox data address |
| 44 | 4 | D2H mailbox data address |
| 48 | 4 | Ring info address |
| 52 | 4 | DMA scratch buffer length |
| 56 | 8 | DMA scratch buffer address (lo/hi) |
| 64 | 4 | DMA ring update buffer length |
| 68 | 8 | DMA ring update buffer address (lo/hi) |

### Shared flags

| Bit(s) | Meaning |
|--------|---------|
| `0x00FF` | Protocol version (supported: 5–7) |
| `0x4000` | H2D split |
| `0x8000` | D2H split |
| `0x10000` | DMA index support |
| `0x100000` | DMA 2-byte indices |
| `0x10000000` | Host-ready doorbell via mailbox 1 |

### Protocol version

Minimum supported: 5. Maximum supported: 7.

Version 7 changes the item sizes for TX-complete and RX-complete rings (see chapter 03).

### Console structure

The console address (offset 20 in shared info) points to a firmware console descriptor in TCM:

| Offset | Size | Field |
|--------|------|-------|
| 8 | 4 | Buffer address (TCM) |
| 12 | 4 | Buffer size |
| 16 | 4 | Write index |

The buffer is a circular character buffer in TCM. The host maintains its own read index (starting at 0). On each read: fetch the write index, copy characters from `buf_addr + read_idx` up to the write index, wrapping at `bufsize`.

## Ring info structure

Located at the ring info address from shared RAM. This structure is read from TCM as a packed binary block:

| Offset | Size | Field |
|--------|------|-------|
| 0 | 4 | Ring memory base (TCM address of ring descriptors) |
| 4 | 4 | H2D write index pointer (TCM) |
| 8 | 4 | H2D read index pointer (TCM) |
| 12 | 4 | D2H write index pointer (TCM) |
| 16 | 4 | D2H read index pointer (TCM) |
| 20 | 8 | H2D write index host address (for DMA indices) |
| 28 | 8 | H2D read index host address |
| 36 | 8 | D2H write index host address |
| 44 | 8 | D2H read index host address |
| 52 | 2 | Max flow rings |
| 54 | 2 | Max submission rings (version >= 6) |
| 56 | 2 | Max completion rings (version >= 6) |

For version < 6, `max_submission_rings` equals `max_flowrings`, and actual flow ring count is `max_submission_rings - 2` (subtracting the two H2D common rings). Max completion rings defaults to 3.

Max flow rings is capped at 512.

### Ring descriptor entries

Each ring descriptor in TCM is 16 bytes:

| Offset | Size | Field |
|--------|------|-------|
| 0 | 4 | Reserved (not written by host during init) |
| 4 | 2 | Max items |
| 6 | 2 | Item size |
| 8 | 8 | DMA base address (lo/hi) |

The host writes the max items, item size, and DMA base address into TCM for each ring during initialization.

## Index management

Ring read/write pointers can be managed in two modes:

### TCM indices (fallback)

When DMA index support is absent, read and write pointers reside in TCM at addresses obtained from the ring info structure. The host reads/writes 16-bit values via MMIO.

The per-ring TCM offset advances by 4 bytes (not 2) per ring because the firmware uses 32-bit aligned slots.

### DMA (host memory) indices

When the shared flags indicate DMA index support:

1. Host allocates a contiguous DMA buffer sized as `(max_submission_rings + max_completion_rings) * idx_size * 2`, where `idx_size` is 2 (if `DMA_2B_IDX` set) or 4.
2. The buffer is partitioned into four regions at ascending addresses:

| Region | Size |
|--------|------|
| H2D write indices | `max_submissionrings * idx_size` |
| H2D read indices | `max_submissionrings * idx_size` |
| D2H write indices | `max_completionrings * idx_size` |
| D2H read indices | `max_completionrings * idx_size` |

Both H2D regions use `max_submissionrings` (not `max_completionrings`).

3. Host addresses for each region are written back into the ring info structure in TCM.
4. Index reads/writes go to host memory instead of TCM.

When using TCM indices (no DMA), the per-ring index stride is `sizeof(u32) = 4` even though the actual index values are 16-bit.

## DMA ring initialization

For each of the 5 common rings (2 H2D + 3 D2H):

1. Allocate a coherent DMA buffer sized `max_items * item_size`.
2. Write the DMA buffer address, max items, and item size into the ring's TCM descriptor.
3. Initialize the `commonring` abstraction with depth, item size, and buffer pointer.
4. Register ring callbacks for doorbell, read/write pointer update.
5. Assign per-ring read and write index addresses.

For flow rings: pre-allocate an array of ring control structures. Each gets its index addresses assigned. DMA buffers for flow rings are allocated lazily when the ring is created.

### Common ring parameters

| Ring | Max items | Item size (v < 7) | Item size (v >= 7) |
|------|-----------|--------------------|---------------------|
| Control Submit (H2D) | 64 | 40 | 40 |
| RX Post Submit (H2D) | 1024 | 32 | 32 |
| Control Complete (D2H) | 64 | 24 | 24 |
| TX Complete (D2H) | 1024 | 16 | 24 |
| RX Complete (D2H) | 1024 | 32 | 40 |

Flow rings: max 512 items, item size 48.

## Scratch and ring-update DMA buffers

Two additional DMA buffers are allocated and their addresses written into the shared RAM area:

- **Scratch buffer**: 8 bytes. Address written at shared offset 56, length at offset 52.
- **Ring update buffer**: 1024 bytes. Address written at shared offset 68, length at offset 64.

## Interrupts

### Register sets

Two register sets exist, selected by PCIe core revision:

| Field | Default (rev < 64) | 64-bit (rev >= 64) |
|-------|-------------------|--------------------|
| IntMask | `0x24` | `0xC14` |
| MailboxInt | `0x48` | `0xC30` |
| MailboxMask | `0x4C` | `0xC34` |
| H2D Mailbox 0 | `0x140` | `0xA20` |
| H2D Mailbox 1 | `0x144` | `0xA24` |

All register offsets are relative to BAR0 (with the PCIe2 core selected).

### Interrupt bits

For rev < 64, D2H doorbell interrupts occupy bits 16–23 of the mailbox interrupt register. For rev >= 64, they occupy bits 0–15.

FN0 interrupts (used for mailbox data) are in bits 8–9 for rev < 64, and not present for rev >= 64.

### Interrupt flow

1. **Hard IRQ handler**: Read mailbox-int register. If non-zero, disable interrupts and return `IRQ_WAKE_THREAD`.
2. **Threaded handler**:
   a. Read and clear mailbox-int status.
   b. If FN0 bits set: handle mailbox data (D3 ACK, deep sleep, firmware halt).
   c. If D2H doorbell bits set and state is UP: trigger `msgbuf_rx_trigger`.
   d. Read firmware console.
   e. Re-enable interrupts if state is UP.

MSI is enabled before requesting the threaded IRQ.

### Host-ready doorbell

If the shared flags include `HOSTRDY_DB1`, the host writes 1 to H2D Mailbox 1 after initialization to signal readiness.

## Mailbox communication

### Host-to-device mailbox

The host writes a 32-bit command word to the H2D mailbox TCM address, then triggers the device by writing 1 to PCI config register `0x98`.

For PCIe core rev <= 13, the trigger write is sent twice (hardware workaround).

Before writing, the host polls the mailbox location until it reads zero (firmware has consumed the previous command), with a 1-second timeout (100 iterations × 10 ms).

| Command | Value |
|---------|-------|
| D3 inform | `0x00000001` |
| Deep-sleep ACK | `0x00000002` |
| D0 inform (in use) | `0x00000008` |
| D0 inform | `0x00000010` |

### Device-to-host mailbox

| Command | Value | Action |
|---------|-------|--------|
| D3 ACK | `0x00000001` | Wake the D3 wait queue |
| Deep-sleep enter request | `0x00000002` | Reply with `HOST_DS_ACK` |
| Deep-sleep exit note | `0x00000004` | Log only |
| Firmware halt | `0x10000000` | Report firmware crash |

## Firmware download

### Sequence

1. **Enter download state**: For BCM43602, zero-out ARM CR4 bank PDA registers (banks 5 and 7) to make RAM writable.
2. **Copy firmware**: Write firmware binary to TCM at `rambase` using `memcpy_toio`.
3. **Capture reset vector**: The first 4 bytes of the firmware image are the ARM reset vector.
4. **Clear shared-RAM signature**: Write 0 to `rambase + ramsize - 4`.
5. **Copy NVRAM**: Write NVRAM data to the end of RAM (`rambase + ramsize - nvram_len`). This may overwrite the zero written in step 4 if `nvram_len >= 4`.
6. **Random seed** (for chips with `fw_seed` flag): Write an 8-byte footer (`{length_le32, magic=0xfeedc0de}`) immediately before NVRAM, then write 256 bytes of random data immediately before the footer. Ascending RAM layout: `[random_seed: 256 bytes][footer: 8 bytes][NVRAM: nvram_len bytes]`.
7. **Exit download state**: For BCM43602, reset the internal-memory core. Then write the saved reset vector to TCM offset 0 (`tcm + 0`, the very beginning of BAR1, which may differ from `rambase`).
8. **Wait for firmware init**: Save the current value at `rambase + ramsize - 4` (which may be NVRAM data, not zero). Poll every 50 ms for up to 5 seconds until the value changes. Firmware writes the shared-RAM address there when ready.
9. **Validate**: The shared-RAM address must fall within `[rambase, rambase + ramsize)`.
10. **Parse shared info**: Read the shared RAM structure.

### RAM size adjustment

Some firmwares embed a RAM size override in the image header. At offset 0x6C, a 32-bit magic value `0x534d4152` ("SMAR") marks the presence of the override. The actual 32-bit RAM size follows at offset 0x70. If the magic matches, the chip's `ramsize` is updated before download.

## Device reset

1. Select PCIe2 core via BAR0 window.
2. Disable ASPM by clearing bits 0–1 of `LINK_STATUS_CTRL` (PCI config `0xBC`), saving the original value.
3. Select ChipCommon core via BAR0 window.
4. Write 4 to the watchdog register, then sleep 100 ms.
5. Re-select PCIe2 core, restore original ASPM value.
5. For PCIe core rev <= 13: re-read and re-write specific PCI configuration offsets through the indirect config-address/config-data registers (`CONFIGADDR` at `0x120`, `CONFIGDATA` at `0x124`). For each offset, write the offset to `CONFIGADDR`, read from `CONFIGDATA`, write the value back to `CONFIGDATA`. Offsets:

| Config register offset |
|----------------------|
| 0x004 |
| 0x04C |
| 0x058 |
| 0x05C |
| 0x060 |
| 0x064 |
| 0x0DC |
| 0x228 |
| 0x248 |
| 0x4E0 |
| 0x4F4 |

## Power management

### D3 entry (suspend)

1. Stop console timer.
2. Set bus state to DOWN.
3. Send `H2D_HOST_D3_INFORM` via mailbox.
4. Wait up to 2 seconds for `D2H_DEV_D3_ACK`.
5. On timeout, restore bus state to UP and return error.
6. Set internal state to DOWN.

### D3 exit (resume)

1. Check if the device is still up by reading the interrupt mask register.
2. If non-zero (hot resume): send `H2D_HOST_D0_INFORM`, restore state, re-enable interrupts, send host-ready.
3. If zero (cold resume): detach the chip, remove the PCIe device, and re-probe from scratch.

## OTP reading

For chips that support it (4355, 4364, 4377, 4378, 4387), the driver reads OTP data from the chip to extract board identification parameters (module, vendor, version). These are used in firmware file name construction for Apple platforms.

OTP is read from a core-specific register range (ChipCommon or GCI), as 16-bit words via BAR0 indirect access. The OTP data is parsed as TLV entries; the `SYS_VENDOR` type (`0x15`) contains board parameters in a "key=value" string format within a 4-byte-headered payload.

## Firmware file selection

Firmware files are selected by chip ID and revision bitmask. Each entry maps a `(chip_id, revision_mask)` pair to a firmware name template. The bus layer constructs requests for up to 4 files:

| Index | Extension | Type | Required |
|-------|-----------|------|----------|
| 0 | `.bin` | Binary firmware | Yes |
| 1 | `.txt` | NVRAM | No |
| 2 | `.clm_blob` | CLM regulatory data | No |
| 3 | `.txcap_blob` | TX cap data | No |

Board-type-specific NVRAM variants are tried first (e.g., `brcmfmac4350c2-pcie.board_type.txt`).

## PCI device table

Devices are identified by PCI vendor `0x14e4` (Broadcom) with PCI class `NETWORK_OTHER`. Each PCI device ID maps to a firmware vendor (WCC, BCA, CYW) and optionally enables the random-seed feature for firmware download.
