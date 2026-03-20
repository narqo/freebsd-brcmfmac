# M-S3/M-S5 Implementation Plan: SDPCM data path and net80211

Read docs/02-build-test.md for general guidance.
Read docs/05-sdio-plan.md for hardware details.
Read docs/10-investigations.md for previous investigations.

## Current state

M-S1 (bus ops), M-S2 (SDIO bus layer), M-S4 (probe/attach) are done.
Firmware boots, F2 becomes ready (IORdy=0x06 after HT clock + poll).
The SDPCM/BCDC protocol implementation exists in `sdpcm.c` but has
never successfully sent or received a frame over F2.

## Step 1: Complete M-S3 — first successful ioctl

Goal: `brcmf_fil_iovar_data_get(sc, "ver", ...)` returns the
firmware version string.

### 1a. Verify F2 write succeeds

Load the module. The existing code in `main.c` already attempts a
"ver" ioctl after `brcmf_sdio_attach`. Check dmesg for "firmware:"
(success) vs "firmware ver ioctl failed" (failure). If it fails,
check `/var/log/messages` for sdiob error details.

### 1b. Verify F2 read succeeds (ioctl response)

The ioctl sends an SDPCM control frame (F2 write), then polls for
a response (F2 reads in `brcmf_sdpcm_recv`). The recv path reads
512 bytes from F2 at the SDIO core's backplane address. If writes
work but reads don't return data, check:

- SDIO core intstatus for I_HMB_FRAME_IND (bit 6) — indicates
  firmware has a frame queued
- The recv address: currently uses backplane-windowed SDIO core
  address. Linux reads from address 0 (FIFO). May need to change
  `brcmf_sdpcm_recv` to use address 0 like `brcmf_sdpcm_send`.

### 1c. Handle SDPCM flow control

The firmware signals TX flow control via the SDPCM header's
`max_seq` field (byte 9 of the HW header). The driver must not
send when `tx_seq == max_seq`. Currently tracked in
`sc->sdpcm_max_seq` but not enforced in `brcmf_sdpcm_send`.

## Step 2: Wire up `brcmf_cfg_attach` in SDIO attach

After the "ver" ioctl succeeds, call `brcmf_cfg_attach(sc)` from
`brcmf_sdio_bus_attach` in `main.c`. This is the same call the
PCIe path uses in `pcie.c`. It handles:

- MAC address query
- net80211 ifattach
- Channel and rate capability setup
- VAP create/delete callbacks
- Scan infrastructure

The existing `cfg.c` is bus-agnostic — it calls through
`sc->bus_ops->ioctl` and `sc->bus_ops->tx`. No changes needed
in cfg.c for SDIO.

### 2a. BCM43455 capabilities

The cfg_attach code queries firmware capabilities. BCM43455
differences from BCM4350 (PCIe):

- 1 spatial stream (not 2)
- No VHT (HT only, MCS 0-7)
- 20/40 MHz channels
- `io_type` likely D11N (confirm via `C_GET_VERSION`)

The channel setup and HT capability code in `cfg.c` should handle
this automatically based on firmware responses. No special-casing
needed.

### 2b. Detach path

`brcmf_sdio_bus_detach` already calls `brcmf_cfg_detach(sc)`.
Verify that `cfg_attached` guard works correctly when
`brcmf_cfg_attach` succeeds (it was only tested for the failure
path on SDIO).

## Step 3: RX data path — interrupt or polling

The PCIe path uses a 10ms callout (`poll_callout`) that processes
D2H completion rings. SDIO needs an equivalent mechanism to read
incoming frames from F2.

### Option A: polling callout (recommended for initial bring-up)

Add a callout that runs every 10-20ms:
1. Check SDIO core intstatus for frame indication
2. Call `brcmf_sdpcm_recv` to read the frame
3. Dispatch based on channel: control → ioctl completion,
   event → `brcmf_sdpcm_process_event`, data →
   `brcmf_sdpcm_process_rx`

This matches how the PCIe path's `poll_callout` works. Simpler
than wiring up SDIO interrupts.

### Option B: SDIO interrupt-driven

Register an SDIO interrupt handler via `sdio_claim_irq`. The
BCM43455 asserts an in-band interrupt when frames are available.
Better latency but more complex (requires CCCR IENx setup and
sdiob interrupt integration). Defer to a later milestone.

### Where to put it

The RX processing belongs in `sdpcm.c`. Add:
- `brcmf_sdpcm_rx_callout` — callout handler
- `brcmf_sdpcm_init` — called from `brcmf_sdio_attach` after
  F2 is ready, starts the callout
- `brcmf_sdpcm_cleanup` — stops the callout (already exists
  as a stub)

## Step 4: Test scan and association

Once RX polling works:

1. `ifconfig wlan0 create wlandev brcmfmac0`
2. `ifconfig wlan0 up` — triggers `brcmf_parent` → firmware
   init sequence (same as PCIe)
3. `ifconfig wlan0 list scan` — verify scan results
4. `wpa_supplicant -Dbsd -iwlan0 -c/tmp/wpa_kolabox.conf -B`

The WiFi AP for testing is not on the RPi4's local network.
You will need to set up an AP reachable from the RPi4's location,
or use an open network for initial testing. The PCIe test uses
Kolabox (192.168.188.0/24) on the vm0 test host — that AP may
not be reachable from the RPi4.

## Step 5: TX data path

`brcmf_sdpcm_tx` already implements `bus_ops->tx`. It wraps
the mbuf in a BCDC header + SDPCM frame and writes to F2.
The `cfg.c` VAP transmit override (`brcmf_raw_xmit`) calls
`bus_ops->tx` directly.

Verify bidirectional data flow with ping after association.

## Key differences from PCIe path

| Aspect | PCIe (msgbuf) | SDIO (SDPCM+BCDC) |
|--------|---------------|-------------------|
| Ioctl | DMA ring + completion | SDPCM control channel |
| TX | Flow ring + DMA | SDPCM data channel |
| RX | Pre-posted buffers + completion ring | F2 read on interrupt/poll |
| Events | Embedded in RX completions | SDPCM event channel |
| Flow control | Flow ring create/delete | SDPCM max_seq |

The `cfg.c` code calls `bus_ops->flowring_create` and
`bus_ops->flowring_delete` on association. These are NULL for
SDIO bus_ops — verify cfg.c guards these with NULL checks
(it does: `if (sc->bus_ops->flowring_delete != NULL)`).

## Risks

- `brcmf_sdpcm_recv` may need address 0 (FIFO) instead of
  backplane-windowed address. Currently uses backplane address
  which works for F2 reads but may not return SDPCM frames.
- The BCDC data offset in RX frames may differ from what the
  PCIe path uses. The `rx_dataoffset` field in softc is set
  during PCIe init from shared memory — SDIO needs to discover
  it from the firmware or use a default (typically 0 for SDIO).
- The ioctl response matching in `brcmf_sdpcm_ioctl` currently
  processes event and data frames received while polling for the
  control response. If the RX callout is also running, there is
  a potential race. Protect with `ioctl_mtx` or disable the
  callout during ioctl polling.
