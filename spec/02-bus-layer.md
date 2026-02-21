# PCIe Bus Layer

## Overview

The PCIe bus layer (`pcie.c`) handles:
- Hardware initialization and reset
- Firmware download
- DMA ring setup for msgbuf protocol
- Interrupt handling
- Memory-mapped I/O to chip

## Hardware resources

### BAR mappings

| BAR | Size | Content |
|-----|------|---------|
| BAR0 | 32KB | PCIe core registers, chip common |
| BAR1 | Variable | TCM (Tightly Coupled Memory) - firmware RAM |

```c
struct brcmf_pciedev_info {
    void __iomem *regs;          // BAR0 - registers
    void __iomem *tcm;           // BAR1 - TCM (firmware memory)
    u32 ram_base;                // RAM base in TCM
    u32 ram_size;                // RAM size
    struct brcmf_chip *ci;       // Chip info
    ...
};
```

### Register access

```c
// BAR0 register I/O
u32 brcmf_pcie_read_reg32(devinfo, reg_offset);
void brcmf_pcie_write_reg32(devinfo, reg_offset, value);

// TCM (firmware memory) I/O
u8  brcmf_pcie_read_tcm8(devinfo, mem_offset);
u16 brcmf_pcie_read_tcm16(devinfo, mem_offset);
u32 brcmf_pcie_read_tcm32(devinfo, mem_offset);
void brcmf_pcie_write_tcm16(devinfo, mem_offset, value);
void brcmf_pcie_write_tcm32(devinfo, mem_offset, value);
```

## Chip core addressing

BCM chips have multiple cores accessible via backplane. BAR0 window selects which core is visible:

```c
void brcmf_pcie_select_core(devinfo, coreid) {
    struct brcmf_core *core = brcmf_chip_get_core(devinfo->ci, coreid);
    pci_write_config_dword(pdev, BRCMF_PCIE_BAR0_WINDOW, core->base);
}
```

Common cores:
- `BCMA_CORE_PCIE2` (0x83c) - PCIe interface
- `BCMA_CORE_CHIPCOMMON` (0x800) - Chip control, OTP
- `BCMA_CORE_ARM_CR4` (0x83e) - CPU core
- `BCMA_CORE_INTERNAL_MEM` (0x80e) - Internal SRAM

## Firmware download

### Sequence

1. Enter download state (halt CPU)
2. Copy firmware binary to TCM at `ram_base`
3. Save reset vector from first 4 bytes of firmware
4. Clear last 4 bytes of RAM (shared RAM address placeholder)
5. Copy NVRAM to end of RAM (`rambase + ramsize - nvram_len`)
6. If `fwseed`: write random seed footer + random data just before NVRAM
7. Exit download state (release CPU reset, using reset vector)
8. Poll for shared RAM address (firmware writes it to last 4 bytes when ready)

```c
int brcmf_pcie_download_fw_nvram(devinfo, fw, nvram, nvram_len) {
    // Halt ARM
    brcmf_pcie_enter_download_state(devinfo);

    // Copy firmware to TCM
    memcpy_toio(devinfo->tcm + devinfo->ci->rambase, fw->data, fw->size);

    // Store reset vector
    resetintr = get_unaligned_le32(fw->data);

    // Clear shared RAM address location
    brcmf_pcie_write_ram32(devinfo, devinfo->ci->ramsize - 4, 0);

    // Copy NVRAM to end of RAM
    address = devinfo->ci->rambase + devinfo->ci->ramsize - nvram_len;
    memcpy_toio(devinfo->tcm + address, nvram, nvram_len);

    // Read current value before starting ARM (may be non-zero garbage)
    sharedram_addr_written = brcmf_pcie_read_ram32(devinfo, ramsize - 4);

    // Start ARM
    brcmf_pcie_exit_download_state(devinfo, resetintr);

    // Wait for firmware to change the shared RAM address
    sharedram_addr = sharedram_addr_written;
    loop_counter = BRCMF_PCIE_FW_UP_TIMEOUT / 50;
    while ((sharedram_addr == sharedram_addr_written) && loop_counter--) {
        msleep(50);
        sharedram_addr = brcmf_pcie_read_ram32(devinfo, ramsize - 4);
    }

    // Validate: must be within RAM range
    return brcmf_pcie_init_share_ram_info(devinfo, sharedram_addr);
}
```

### Shared RAM structure

After firmware boots, it writes a shared RAM address to the last 4 bytes of RAM. This points to the shared info structure:

```c
// Offsets from shared RAM base (firmware-defined)
#define BRCMF_SHARED_CONSOLE_ADDR_OFFSET       20
#define BRCMF_SHARED_MAX_RXBUFPOST_OFFSET      34
#define BRCMF_SHARED_RX_DATAOFFSET_OFFSET      36
#define BRCMF_SHARED_HTOD_MB_DATA_ADDR_OFFSET  40
#define BRCMF_SHARED_DTOH_MB_DATA_ADDR_OFFSET  44
#define BRCMF_SHARED_RING_INFO_ADDR_OFFSET     48
#define BRCMF_SHARED_RING_BASE_OFFSET          52
#define BRCMF_SHARED_DMA_SCRATCH_LEN_OFFSET    52
#define BRCMF_SHARED_DMA_SCRATCH_ADDR_OFFSET   56
#define BRCMF_SHARED_DMA_RINGUPD_LEN_OFFSET    64
#define BRCMF_SHARED_DMA_RINGUPD_ADDR_OFFSET   68
```

---
**BCM4350 note**

Firmware v7.35.180.133 uses shared version 5. The `DMA_INDEX` flag is typically set, using 16-bit indices (`DMA_2B_IDX`). The `HOSTRDY_DB1` flag is set, requiring a write to `h2d_mailbox_1` after ring setup.

---

First word contains version and flags:
```c
#define BRCMF_PCIE_MIN_SHARED_VERSION      5
#define BRCMF_PCIE_MAX_SHARED_VERSION      7     // BRCMF_PCIE_SHARED_VERSION_7
#define BRCMF_PCIE_SHARED_VERSION_MASK     0x00FF
#define BRCMF_PCIE_SHARED_DMA_INDEX        0x10000    // DMA index supported
#define BRCMF_PCIE_SHARED_DMA_2B_IDX       0x100000   // Use 16-bit indices
#define BRCMF_PCIE_SHARED_HOSTRDY_DB1      0x10000000 // Use doorbell 1 for host ready

#define BRCMF_PCIE_FLAGS_HTOD_SPLIT        0x4000
#define BRCMF_PCIE_FLAGS_DTOH_SPLIT        0x8000
```

`max_rxbufpost` is read from TCM at offset 34 (16-bit). If zero, defaults to `BRCMF_DEF_MAX_RXBUFPOST` (255).

Notes:
- The Linux implementation treats `BRCMF_SHARED_RING_BASE_OFFSET` and `BRCMF_SHARED_DMA_SCRATCH_LEN_OFFSET` as aliases at offset 52. Keep both names to match the code.
- `BRCMF_PCIE_SHARED_DMA_INDEX` and `BRCMF_PCIE_SHARED_DMA_2B_IDX` select host-memory index mode and 16-bit index size; in this mode the driver allocates an index buffer, writes host addresses into `brcmf_pcie_dhi_ringinfo`, and writes the updated ringinfo back to TCM.
- `max_flowrings`/`max_submissionrings`/`max_completionrings` semantics depend on shared version (v6+ uses the explicit fields; older versions derive them from `max_flowrings`).

### Scratch and ring-update buffers

After reading shared info, the driver allocates DMA-coherent buffers and writes their addresses to TCM:

```c
#define BRCMF_DMA_D2H_SCRATCH_BUF_LEN     8
#define BRCMF_DMA_D2H_RINGUPD_BUF_LEN     1024
```

The scratch buffer address goes at `BRCMF_SHARED_DMA_SCRATCH_ADDR_OFFSET` (56) and the ringupd buffer at `BRCMF_SHARED_DMA_RINGUPD_ADDR_OFFSET` (68). The lengths are written at offsets 52 and 64 respectively.

### Host ready notification

After ring setup, if `BRCMF_PCIE_SHARED_HOSTRDY_DB1` is set in shared flags, the driver writes 1 to `h2d_mailbox_1` to signal host readiness. If the flag is not set, no host-ready write occurs. (`h2d_mailbox_0` is used for ring doorbell, not host-ready.)

## DMA ring setup

### Ring info structure (firmware-provided)

```c
struct brcmf_pcie_dhi_ringinfo {
    __le32 ringmem;                          // TCM address of ring memory descriptors
    __le32 h2d_w_idx_ptr;                    // H2D write index pointers
    __le32 h2d_r_idx_ptr;                    // H2D read index pointers
    __le32 d2h_w_idx_ptr;                    // D2H write index pointers
    __le32 d2h_r_idx_ptr;                    // D2H read index pointers
    struct msgbuf_buf_addr h2d_w_idx_hostaddr; // Host memory for H2D write indices
    struct msgbuf_buf_addr h2d_r_idx_hostaddr;
    struct msgbuf_buf_addr d2h_w_idx_hostaddr;
    struct msgbuf_buf_addr d2h_r_idx_hostaddr;
    __le16 max_flowrings;                    // Max flow rings
    __le16 max_submissionrings;              // Max H2D rings
    __le16 max_completionrings;              // Max D2H rings
};
```

### Ring info version handling

For shared version >= 6, `max_submissionrings`, `max_flowrings`, and `max_completionrings` are read directly from the ringinfo structure. For version < 6:
```c
max_submissionrings = ringinfo.max_flowrings;  // overloaded field
max_flowrings = max_submissionrings - BRCMF_NROF_H2D_COMMON_MSGRINGS;
max_completionrings = BRCMF_NROF_D2H_COMMON_MSGRINGS;
```

### DMA index mode

When `BRCMF_PCIE_SHARED_DMA_INDEX` is set in shared flags, the driver allocates a single DMA-coherent buffer for all ring indices and writes its sub-region addresses into the `ringinfo` host address fields. The buffer layout is:
```
h2d_w_idx[max_submissionrings] | h2d_r_idx[max_submissionrings] |
d2h_w_idx[max_completionrings] | d2h_r_idx[max_completionrings]
```
Each index is `dma_idx_sz` bytes (2 for `DMA_2B_IDX`, 4 otherwise). The updated ringinfo is written back to TCM. In this mode, `read_ptr`/`write_ptr` access host memory instead of TCM.

When DMA index mode is not available, indices are stored in TCM. Each index slot in TCM is 4 bytes wide (`sizeof(u32)`), but only the lower 16 bits are used.

### Ring allocation

Each ring needs:
1. DMA buffer (host memory, DMA-accessible)
2. TCM descriptor (ring base address, size)
3. Index locations (read/write pointers)

```c
struct brcmf_pcie_ringbuf {
    struct brcmf_commonring commonring;
    dma_addr_t dma_handle;
    u32 w_idx_addr;                          // Write index address
    u32 r_idx_addr;                          // Read index address
    struct brcmf_pciedev_info *devinfo;
    u8 id;
};
```

Ring memory layout in TCM per ring:
```c
#define BRCMF_RING_MEM_BASE_ADDR_OFFSET    8   // DMA buffer address (64-bit)
#define BRCMF_RING_MAX_ITEM_OFFSET         4   // Max items
#define BRCMF_RING_LEN_ITEMS_OFFSET        6   // Item size
#define BRCMF_RING_MEM_SZ                 16   // Total descriptor size
```

### Common rings

| ID | Direction | Purpose | Max items |
|----|-----------|---------|-----------|
| 0 | H2D | Control submit | 64 |
| 1 | H2D | RX buffer post | 1024 |
| 2 | D2H | Control complete | 64 |
| 3 | D2H | TX complete | 1024 |
| 4 | D2H | RX complete | 1024 |

Additional flow rings (H2D) are created dynamically for TX data. Flow ring depth is `BRCMF_H2D_TXFLOWRING_MAX_ITEM` (512) with item size `BRCMF_H2D_TXFLOWRING_ITEMSIZE` (48).

### Item size selection

Ring item sizes depend on shared version (from TCM):
- Version < 7: TX complete = 16, RX complete = 32
- Version >= 7: TX complete = 24, RX complete = 40

Control submit (40), RX post (32), and control complete (24) are the same across all versions.

## Interrupt handling

### Register locations

For core rev < 64:
```c
#define BRCMF_PCIE_PCIE2REG_INTMASK          0x24
#define BRCMF_PCIE_PCIE2REG_MAILBOXINT       0x48
#define BRCMF_PCIE_PCIE2REG_MAILBOXMASK      0x4C
#define BRCMF_PCIE_PCIE2REG_H2D_MAILBOX_0    0x140
#define BRCMF_PCIE_PCIE2REG_H2D_MAILBOX_1    0x144
```

For core rev >= 64 (newer chips):
```c
#define BRCMF_PCIE_64_PCIE2REG_INTMASK       0xC14
#define BRCMF_PCIE_64_PCIE2REG_MAILBOXINT    0xC30
#define BRCMF_PCIE_64_PCIE2REG_MAILBOXMASK   0xC34
#define BRCMF_PCIE_64_PCIE2REG_H2D_MAILBOX_0 0xA20
#define BRCMF_PCIE_64_PCIE2REG_H2D_MAILBOX_1 0xA24
```

### Interrupt bits

```c
// Mailbox interrupt bits (D2H doorbell)
#define BRCMF_PCIE_MB_INT_D2H0_DB0   0x10000
#define BRCMF_PCIE_MB_INT_D2H0_DB1   0x20000
// ... up to D2H3
#define BRCMF_PCIE_MB_INT_FN0_0      0x0100
#define BRCMF_PCIE_MB_INT_FN0_1      0x0200
```

### Register abstraction

Register offsets differ between core rev < 64 and >= 64. The driver uses a `brcmf_pcie_reginfo` struct to abstract this:

```c
struct brcmf_pcie_reginfo {
    u32 intmask;
    u32 mailboxint;
    u32 mailboxmask;
    u32 h2d_mailbox_0;
    u32 h2d_mailbox_1;
    u32 int_d2h_db;        // combined mask for all D2H doorbell bits
    u32 int_fn0;           // FN0 interrupt mask (0 for rev >= 64)
};
```

Selected at probe time based on core revision.

---
**BCM4350 note**

Core revision is < 64, so the driver uses the legacy register offsets (INTMASK=0x24, MAILBOXINT=0x48, etc.). The rev >= 64 offsets are not needed for this chip.

---

### ISR flow

```c
irqreturn_t brcmf_pcie_quick_check_isr(int irq, void *arg) {
    // Check if interrupt is for us
    if (brcmf_pcie_read_reg32(devinfo, mailboxint)) {
        brcmf_pcie_intr_disable(devinfo);
        return IRQ_WAKE_THREAD;
    }
    return IRQ_NONE;
}

irqreturn_t brcmf_pcie_isr_thread(int irq, void *arg) {
    status = brcmf_pcie_read_reg32(devinfo, mailboxint);
    brcmf_pcie_write_reg32(devinfo, mailboxint, status);  // ACK

    if (status & int_fn0)
        brcmf_pcie_handle_mb_data(devinfo);  // Mailbox messages

    if (status & int_d2h_db)
        brcmf_proto_msgbuf_rx_trigger(dev);  // Process D2H rings

    brcmf_pcie_intr_enable(devinfo);
    return IRQ_HANDLED;
}
```

### Doorbell (H2D notification)

To notify firmware of new H2D messages:
```c
void brcmf_pcie_ring_mb_ring_bell(void *ctx) {
    brcmf_pcie_write_reg32(devinfo, h2d_mailbox_0, 1);
}
```

## Mailbox data

Firmware-to-host mailbox for power management:

```c
#define BRCMF_D2H_DEV_D3_ACK        0x00000001   // D3 acknowledged
#define BRCMF_D2H_DEV_DS_ENTER_REQ  0x00000002   // Deep sleep request
#define BRCMF_D2H_DEV_DS_EXIT_NOTE  0x00000004   // Deep sleep exit
#define BRCMF_D2H_DEV_FWHALT        0x10000000   // Firmware halted

#define BRCMF_H2D_HOST_D3_INFORM    0x00000001   // Entering D3
#define BRCMF_H2D_HOST_DS_ACK       0x00000002   // Deep sleep ACK
#define BRCMF_H2D_HOST_D0_INFORM    0x00000010   // Back to D0
```

Location in TCM (from shared info):
- `htod_mb_data_addr`: Host writes here
- `dtoh_mb_data_addr`: Firmware writes here

## Console log (debug)

Firmware has a circular console buffer. Driver can poll it for debug messages:

```c
struct brcmf_pcie_console {
    u32 base_addr;       // Console structure base
    u32 buf_addr;        // Buffer address
    u32 bufsize;         // Buffer size
    u32 read_idx;        // Host read position
};
```

Read loop:
```c
void brcmf_pcie_bus_console_read(devinfo, bool error) {
    addr = console->base_addr + BRCMF_CONSOLE_WRITEIDX_OFFSET;
    newidx = brcmf_pcie_read_tcm32(devinfo, addr);

    while (newidx != console->read_idx) {
        ch = brcmf_pcie_read_tcm8(devinfo, console->buf_addr + console->read_idx);
        console->read_idx = (console->read_idx + 1) % console->bufsize;
        // Accumulate and print lines
    }
}
```
