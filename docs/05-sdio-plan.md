# SDIO Support Plan (BCM43455, Raspberry Pi 4)

## Hardware

- Chip: BCM4345 (CYW43455), chip ID `0x4345`, SDIO interface
- SDIO vendor: `0x02D0` (Broadcom), device: `0xA9A6`
- Host: BCM2835 Arasan SDHCI controller at `0x7e300000`
- Firmware: `/boot/firmware/brcmfmac43455-sdio.bin` (609 KB)
- NVRAM: `/boot/firmware/brcmfmac43455-sdio.txt` (2 KB)

## Boot prerequisites

Resolved during investigation (14 Mar 2026):

BCM43455 WiFi chip (SDIO) is enumerated on RPi4 under FreeBSD, unblocking developing a brcmfmac WiFi driver.

1. **config.txt**: Remove `dtoverlay=mmc` to enable `mmcnr@7e300000`
   instead of `mmc@7e300000` (wrong pinctrl).
2. **SDIO module**: `sdio_load="YES"` in `/boot/loader.conf`.
3. **mmc-pwrseq**: Kernel rebuilt with `mmc-pwrseq-simple` driver.
   DT overlay `wlan-pwrseq.dtbo` handles WL_REG_ON via firmware GPIO.

## Architecture: bus abstraction

The current driver is PCIe-only. Every file except `pcie.c` and
`msgbuf.c` is bus-agnostic at the firmware interface level. The
SDIO variant needs a different bus layer and protocol layer.

### What's reusable (unchanged)

| File | Role |
|------|------|
| `cfg.c` | net80211 integration, VAP, state machine |
| `cfg.h` | Shared definitions, event codes, structures |
| `scan.c` | Scan result parsing, escan, chanspec |
| `security.c` | WPA/key management |
| `debug.c` | Debug output helpers |
| `debug.h` | BRCMF_DBG macro |

### What needs abstraction

**`fwil.c`** calls `brcmf_msgbuf_ioctl()` directly. Must go through
a bus-agnostic function pointer:

```c
struct brcmf_bus_ops {
    int (*ioctl)(struct brcmf_softc *sc, uint32_t cmd,
                 void *buf, uint32_t len, uint32_t *resp_len);
    int (*tx)(struct brcmf_softc *sc, struct mbuf *m);
    void (*cleanup)(struct brcmf_softc *sc);
};
```

**`cfg.c`** VAP transmit calls `brcmf_msgbuf_tx()` directly.

**`core.c`** EROM read uses `brcmf_bp_read32()` (PCIe BAR0 window).
The EROM parser itself (`brcmf_find_core`) already takes a callback
function pointer. SDIO provides its own read callback through
backplane window access.

### What's PCIe-only (keep as-is)

| File | Role |
|------|------|
| `pcie.c` | BAR mapping, DMA, IRQ, firmware download, watchdog |
| `msgbuf.c` | DMA ring protocol, ring doorbell, D2H processing |
| `main.c` | PCI probe/attach, device ID table |

### New files for SDIO

| File | Role |
|------|------|
| `sdio.c` | SDIO bus layer: backplane access via CMD52/CMD53, firmware download, clock management, DPC thread |
| `sdpcm.c` | SDPCM framing + BCDC ioctl protocol, data TX/RX, event delivery |

## FreeBSD SDIO API

The SDIO stack (`sdio.ko`) provides the `sdiob` bus. Child drivers
attach to `sdiob` and are matched by SDIO vendor+device ID. The API
(from `sdio_subr.h` and `sdio_if.m`):

### Bus methods (`sdio_if.m`)

```c
/* CMD52: single byte */
int sdio_read_direct(device_t dev, uint8_t fn, uint32_t addr, uint8_t *val);
int sdio_write_direct(device_t dev, uint8_t fn, uint32_t addr, uint8_t val);

/* CMD53: multi-byte block/byte transfer */
int sdio_read_extended(device_t dev, uint8_t fn, uint32_t addr,
    uint32_t size, uint8_t *buffer, bool incaddr);
int sdio_write_extended(device_t dev, uint8_t fn, uint32_t addr,
    uint32_t size, uint8_t *buffer, bool incaddr);
```

### Helper functions (`sdio_subr.h`)

```c
int sdio_enable_func(struct sdio_func *);
int sdio_disable_func(struct sdio_func *);
int sdio_set_block_size(struct sdio_func *, uint16_t);

/* Typed register access (built on read/write_direct/extended) */
uint8_t sdio_read_1(struct sdio_func *, uint32_t addr, int *err);
void sdio_write_1(struct sdio_func *, uint32_t addr, uint8_t val, int *err);
uint32_t sdio_read_4(struct sdio_func *, uint32_t addr, int *err);
void sdio_write_4(struct sdio_func *, uint32_t addr, uint32_t val, int *err);
```

### Device identification (`sdiob.h`)

```c
SDIOB_ACCESSOR(vendor, VENDOR, uint16_t)
SDIOB_ACCESSOR(device, DEVICE, uint16_t)
SDIOB_ACCESSOR(funcnum, FUNCNUM, uint8_t)
SDIOB_ACCESSOR(function, FUNCTION, struct sdio_func *)
```

The driver probes by checking `sdio_get_vendor(dev) == 0x02D0` and
`sdio_get_device(dev) == 0x4345`.

## SDIO bus layer (`sdio.c`)

### Backplane access

Three address registers select the 32KB window into the backplane:

| Register | Address | Bits |
|----------|---------|------|
| `SBADDRLOW` | `0x1000A` | addr[15:8] |
| `SBADDRMID` | `0x1000B` | addr[23:16] |
| `SBADDRHIGH` | `0x1000C` | addr[31:24] |

To access backplane address `A`:
1. Compute window = `A & 0xFFFF8000`
2. If window differs from current, write the three registers via CMD52
3. Read/write at F1 offset `A & 0x7FFF`

Word accesses (32-bit) use CMD53 with 4-byte aligned addresses.

### Clock management

Before any backplane access, request the clock via `CHIPCLKCSR`
(F1 register `0x1000E`):
- Early init: write `ALP_AVAIL_REQ` (0x08), poll for `ALP_AVAIL` (0x40)
- Normal operation: write `HT_AVAIL_REQ` (0x10), poll for `HT_AVAIL` (0x80)

### Firmware download

1. Enumerate cores via EROM (same DMP format, read through backplane)
2. Halt ARM core (`CPUHALT` via wrapper IOCTL register)
3. Write firmware to RAM at `ram_base` via CMD53 block writes to F1
4. Write NVRAM to `ram_base + ram_size - nvram_len`
5. Reset ARM core, clear CPUHALT
6. Wait for F2 ready (firmware sets F2 ready bit in CCCR)

### Interrupt handling

SDIO in-band interrupt on Function 1. The interrupt handler:
1. Read interrupt status via CMD52
2. Check for frame-available on F2
3. Read frames via CMD53
4. Process SDPCM headers, dispatch to control/event/data handlers

All I/O happens in a DPC thread context (not interrupt context) since
SDIO CMD52/CMD53 can sleep.

## SDPCM + BCDC protocol (`sdpcm.c`)

### SDPCM frame header (12 bytes)

| Offset | Size | Field |
|--------|------|-------|
| 0 | 2 | Frame length (LE) |
| 2 | 2 | Frame length complement (~length) |
| 4 | 1 | Sequence number |
| 5 | 1 | Channel (bits 3:0) |
| 6 | 1 | Next frame length |
| 7 | 1 | Data offset |
| 8 | 1 | Flow control |
| 9 | 1 | Max sequence number |
| 10 | 2 | Reserved |

Channels: 0=control, 1=event, 2=data, 3=glom.

### BCDC command header (16 bytes)

| Offset | Size | Field |
|--------|------|-------|
| 0 | 4 | cmd (LE) |
| 4 | 4 | len (LE) |
| 8 | 4 | flags (LE): bit 1=SET, bits 15:12=ifidx, bits 31:16=reqid |
| 12 | 4 | status (LE) |

### BCDC data header (4 bytes)

| Offset | Size | Field |
|--------|------|-------|
| 0 | 1 | flags (version=2 in bits 7:4) |
| 1 | 1 | priority (bits 2:0) |
| 2 | 1 | flags2 (ifidx in bits 3:0) |
| 3 | 1 | data_offset (4-byte units) |

### IOCTL flow

**Request:**
1. Build 16-byte BCDC header with cmd, len, flags (SET bit, reqid)
2. Append payload
3. Wrap in SDPCM frame on channel 0 (control)
4. Write to F2 via CMD53

**Response:**
1. Read frame from F2
2. Validate SDPCM header
3. Strip SDPCM, parse BCDC header
4. Match reqid, extract status and payload

### Data TX

1. Prepend 4-byte BCDC data header to Ethernet frame
2. Wrap in SDPCM frame on channel 2 (data)
3. Write to F2

### Data/Event RX

1. Read frame from F2
2. Validate SDPCM header, extract channel
3. Strip SDPCM header (data_offset bytes)
4. Channel 1 (event): parse event structure, dispatch
5. Channel 2 (data): strip 4-byte BCDC data header, deliver to net80211

### Flow control

Firmware reports max TX sequence number in SDPCM header of received
frames. Host stops transmitting when its sequence number would exceed
the firmware's limit.

## Chip specifics (BCM43455)

From the spec and Linux driver chip tables:

- Chip ID: `0x4345`
- ARM core: CR4 (same as BCM4350)
- RAM base: determined at runtime from ARM core bank info
- RAM size: determined at runtime from ARM core bank info
- SDIO device ID: `0x4345`
- io_type: likely D11N (C_GET_VERSION will confirm)
- HT caps: 1SS, MCS 0-7, 20/40 MHz
- No VHT

## Build system

Single module with both PCIe and SDIO bus backends. Each backend
registers its own `DRIVER_MODULE` on a different parent bus (`pci`
vs `sdiob`); only the matching one probes at runtime.

```makefile
KMOD = if_brcmfmac
SRCS = main.c pcie.c msgbuf.c \
       sdio.c sdpcm.c \
       core.c cfg.c scan.c security.c fwil.c debug.c
```

Build constraint: the current build host is amd64. SDIO headers
(`dev/sdio/`) may not be present there. Options:
- Build on the RPi4 itself (slow but works once `/usr/src` is present)
- Cross-compile on a FreeBSD aarch64 builder
- Conditionally compile SDIO sources with `#ifdef` or Makefile guard

## Milestones

### M-S1: Bus ops abstraction (DONE)

Decouple upper layers from PCIe-specific protocol calls.

- [x] Add `struct brcmf_bus_ops` (`ioctl`, `tx`, `flowring_create`,
  `flowring_delete`, `cleanup`) to `brcmfmac.h`
- [x] Add `bus_ops` pointer to `brcmf_softc`
- [x] `fwil.c`: replace `brcmf_msgbuf_ioctl()` with `sc->bus_ops->ioctl()`
- [x] `cfg.c`: replace `brcmf_msgbuf_tx()` with `sc->bus_ops->tx()`
- [x] `cfg.c`: replace `brcmf_msgbuf_delete_flowring` /
  `brcmf_msgbuf_init_flowring` with `bus_ops->flowring_*`
- [x] `pcie.c`: set `sc->bus_ops` to static `brcmf_pcie_bus_ops`
- [x] Verify: PCIe driver builds, loads, associates on BCM4350
  (WPA2, DHCP, 5/5 ping 192.168.188.1, avg 4.2ms, 0% loss)

### M-S2: SDIO bus layer (`sdio.c`)

Backplane access, core enumeration, firmware download, F2 ready.
Requires kernel SDHCI fix for testing.

- [ ] Backplane window management (CMD52 to `0x1000A/B/C`)
- [ ] `brcmf_sdio_bp_read32` / `brcmf_sdio_bp_write32`
- [ ] Clock enable (`CHIPCLKCSR` at F1 `0x1000E`)
- [ ] EROM enumeration via `brcmf_find_core()` with SDIO read callback
- [ ] Firmware download: halt ARM, CMD53 block writes, NVRAM, release
- [ ] F2 ready poll
- [ ] Done: `kldload` prints chip ID, firmware version, MAC address

### M-S3: SDPCM + BCDC protocol (`sdpcm.c`)

Control and data protocol over SDIO F2.

- [ ] SDPCM frame encode/decode (12-byte header, channel, seq, flow)
- [ ] BCDC command header (16 bytes): ioctl request/response
- [ ] `brcmf_sdpcm_ioctl()` → `bus_ops->ioctl`
- [ ] BCDC data header (4 bytes): TX/RX Ethernet frames
- [ ] `brcmf_sdpcm_tx()` → `bus_ops->tx`
- [ ] DPC thread: interrupt status, RX dispatch, TX drain
- [ ] Event channel → `brcmf_link_event` / `brcmf_escan_result`
- [ ] Flow control (max sequence tracking)
- [ ] Done: firmware ioctls work (`ver`, `cur_etheraddr`)

### M-S4: SDIO probe/attach in `main.c`

Add SDIO probe/attach alongside existing PCI probe/attach. Both
register via `DRIVER_MODULE` in the same module against different
parent buses (`pci` and `sdiob`).

- [ ] `main.c`: add `brcmf_sdio_probe`, `brcmf_sdio_attach`,
  `brcmf_sdio_detach`
- [ ] `main.c`: `DRIVER_MODULE(if_brcmfmac, sdiob, ...)`
- [ ] Probe: vendor `0x02D0`, device `0xA9A6`
- [ ] Attach: enable F1/F2, set block sizes, call `brcmf_sdio_attach`
  then `brcmf_cfg_attach`
- [ ] Detach: teardown
- [ ] Update Makefile with SDIO sources
- [ ] Done: `kldload` attaches and creates `brcmfmac0` device on SDIO

### M-S5: net80211 for BCM43455

Adjust capabilities, scan, associate.

- [ ] `brcmf_getradiocaps`: chip-specific channel/mode selection
  (1SS HT, no VHT for BCM43455)
- [ ] HT caps: 1SS MCS 0-7, skip VHT cap setup
- [ ] `ifconfig wlan0 create` + `ifconfig wlan0 list scan` works
- [ ] WPA2 association with wpa_supplicant
- [ ] DHCP, gateway ping, internet ping

### M-S6: Upstream SDHCI fix

- [ ] Submit `bcm2835_sdhci.c` `WR4()` patch to FreeBSD

## Blockers

None. SDHCI fix applied, kernel rebuilt, SDIO enumeration confirmed.

## Verified (15 Mar 2026)

SDIO probe test module confirmed:
- `sdiob0` attaches on `sdhci_bcm0`
- 4 SDIO functions enumerated (F0-F3)
- Vendor `0x02D0`, device `0xA9A6` on all functions
- Child driver probe works via `DRIVER_MODULE(..., sdiob, ...)`
- Firmware files present: `brcmfmac43455-sdio.bin` (609 KB),
  `brcmfmac43455-sdio.txt` (2 KB)
- Build toolchain works on RPi4 (`/usr/src` available)

## Risks

- FreeBSD `sdio.ko` is young code (2019, Björn Zeeb). May have
  bugs in CMD53 block transfer or interrupt delivery. No known
  FreeBSD SDIO WiFi driver exists as a reference.
