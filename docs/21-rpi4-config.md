# RPi4 Test Host Configuration

## Current state (2026-03-21)

Kernel: `SDIO` (MMCCAM, current project patch set)

The source tree keeps a single custom config, `sys/arm64/conf/SDIO`, for
future rebuilds. That avoids creating a new objdir for every experiment.

Verified running kernel:

```text
FreeBSD 15.0-STABLE #0 9c49c393a81b-dirty: Sat Mar 21 23:49:11 CET 2026     v@freebsd-test-0:/usr/obj/usr/src/arm64.aarch64/sys/SDIO
```

SDIO card enumerates: `<SDIO card> at scbus0 target 0 lun 0 (pass0,sdiob0)`

### Boot configuration

`/boot/loader.conf`:
```
hw.usb.template=3
umodem_load="YES"
boot_multicons="YES"
boot_serial="YES"
beastie_disable="YES"
loader_color="NO"
hw.sdhci.debug=1
boot_verbose=YES
sdio_load=YES
hw.mmc.debug=1
```

`/boot/efi/config.txt` (relevant lines):
```
[all]
#dtoverlay=mmc
dtoverlay=disable-bt

[pi4]
dtoverlay=wlan-pwrseq
```

`/boot/efi/overlays/wlan-pwrseq.dtbo`: compiled from `patches/wlan-pwrseq.dts`

### Kernel backups

- `/boot/kernel/` — current SDIO kernel
- `/boot/kernel.bak/` — stock GENERIC kernel

## Restore stock kernel

```sh
sudo cp -r /boot/kernel.bak/* /boot/kernel/
sudo reboot
```
