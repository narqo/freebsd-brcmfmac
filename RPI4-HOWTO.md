# RPi4 BCM43455 WiFi SDIO on FreeBSD

## Prerequisites

- Raspberry Pi 4 running FreeBSD 15.0 (USB boot via U-Boot EFI)
- FreeBSD source tree matching the running version
- Cross-compile host (amd64) or native build on RPi4

## Steps

### 1. Apply kernel patches

The patches are already applied in `freebsdsrc/` in this repo. For a
fresh source tree, apply them in order from the source tree root:

Patch 01 fixes `bcm2835_sdhci.c` to pass the correct device tree node
to `mmc_fdt_parse`, so `mmc-pwrseq` and regulator properties are found.

```sh
git apply patches/01-bcm2835-sdhci-fix-mmc-fdt-node.patch
```

Patch 02 adds a `platform_update_ios` method to the SDHCI interface,
called from the MMCCAM path, and implements it in the BCM2835 driver to
handle power sequencing via `mmc_fdt_set_power`.

```sh
git apply patches/02-sdhci-platform-update-ios.patch
```

Patch 03 configures the SDIO bus after enumeration: it raises the clock
to 25 MHz and switches the card and host to 4-bit bus width.

```sh
git apply patches/03-mmccam-sdio-set-fullspeed-clock-and-4bit-bus-width.patch
```

Patch 04 fixes the SDHCI interrupt-masking bug that caused Arasan PIO
transfers to hang hard. The controller can re-assert `SPACE_AVAIL` /
`DATA_AVAIL` after all PIO data has been moved but before `DATA_END`
arrives, or spuriously when no data transfer is in progress. Either
case can re-enter the ISR in a tight loop while holding `SDHCI_LOCK`
and starve the timeout callout. The patch masks those interrupts at the
relevant timeout/error/completion sites and restores them at the start
of the next command or data phase.

```sh
git apply patches/04-sdhci-mask-pio-intr-after-xfer.patch
```

### 2. Create the SDIO kernel profile

MMCCAM replaces the legacy MMC bus driver with a CAM-based stack that
supports SDIO device enumeration (CMD5). Without it, the kernel only
probes for SD/MMC cards.

This project keeps a single custom kernel profile, `SDIO`, in the
source tree. Reuse `KERNCONF=SDIO` for rebuilds instead of creating new
config names; changing the config file name creates a new objdir and
turns incremental rebuilds into near-full builds.

```sh
cat > sys/arm64/conf/SDIO <<EOF
include GENERIC
ident SDIO
options MMCCAM
device wlan
device wlan_ccmp
EOF
```

`device wlan` compiles net80211 into the kernel. The out-of-tree
`if_brcmfmac` driver depends on it (`MODULE_DEPEND wlan`), and
loading a separately-built `wlan.ko` requires an exact kernel version
match — any kernel rebuild breaks it.

`device wlan_ccmp` compiles the WPA2 CCMP cipher into the kernel. This
avoids a separate `wlan_ccmp.ko` version match requirement on the test
host; without it, WPA2 key installation can fail even when association
and the EAPOL exchange succeed.

### 3. Build kernel

```sh
make -j$(sysctl -n hw.ncpu) buildkernel KERNCONF=SDIO TARGET=arm64 TARGET_ARCH=aarch64
```

The canonical patched source tree in this repo is `freebsdsrc/`.
See `docs/20-rpi4-kernel-cross-compile.md` for the full cross-build workflow.

### 4. Build and install DT overlay

On a host with `dtc`:

```sh
dtc -@ -I dts -O dtb -o wlan-pwrseq.dtbo patches/wlan-pwrseq.dts
```

Copy `wlan-pwrseq.dtbo` to `/boot/efi/overlays/` on the RPi4.

### 5. Configure RPi4

In `/boot/efi/config.txt`, comment out `dtoverlay=mmc` if present.
That overlay swaps the Arasan controller to the SD card slot pins
(GPIO 48-53) and disables `mmcnr@7e300000` — the node with the
correct WiFi SDIO pins (GPIO 34-39). Without it, FreeBSD attaches
to `mmcnr` which is `status=okay` in the base DTB. Then add
`wlan-pwrseq` overlay:

```
#dtoverlay=mmc
dtoverlay=wlan-pwrseq
```

In `/boot/loader.conf`, add:

```
sdio_load="YES"
```

See `docs/21-rpi4-config.md` for full reference.

### 6. Install kernel and reboot

Back up the current kernel, install the new one, reboot.

### 7. Verify

```sh
camcontrol devlist
```

Expected output includes:

```
<SDIO card>  at scbus0 target 0 lun 0 (pass0,sdiob0)
```

Three SDIO functions are discovered. No WiFi driver is attached yet.
