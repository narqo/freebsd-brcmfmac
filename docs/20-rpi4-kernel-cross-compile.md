# Cross-Compiling FreeBSD Kernel for RPi4

## Source trees

| Location | Purpose |
|----------|---------|
| `freebsdsrc/` (this repo, local machine) | canonical patched working copy |
| `v@192.168.40.185:~/src/freebsdsrc` | build host copy — kept in sync via rsync |

Base commit: `9c49c393a` (stable/15).

Do not use `/usr/src` on the build host.

The custom kernel config is kept in the source tree and synced to the build
host:

```
freebsdsrc/sys/arm64/conf/SDIO
v@192.168.40.185:~/src/freebsdsrc/sys/arm64/conf/SDIO
```

Contents:
```
include GENERIC
ident SDIO
options MMCCAM
device wlan
```

Keep a single custom `KERNCONF=SDIO` for iteration speed. If a temporary
marker is needed, change the `ident` line in `SDIO` and reuse the same
`KERNCONF`. Do not create new config file names for each experiment; that
creates a new objdir and turns incremental rebuilds into near-full rebuilds.

## Workflow

### 1. Edit locally

Make all source changes in `freebsdsrc/` in this repo. Never edit
directly on the build host.

### 2. Sync changed files to build host

After editing, rsync only the changed files. Example for `sdhci.c`:

```sh
rsync -av freebsdsrc/sys/dev/sdhci/sdhci.c \
    v@192.168.40.185:~/src/freebsdsrc/sys/dev/sdhci/
```

For multiple files across different directories, sync subtree:

```sh
rsync -av freebsdsrc/sys/ \
    v@192.168.40.185:~/src/freebsdsrc/sys/
```

### 3. Build on build host

```sh
ssh v@192.168.40.185 'cd /home/v/src/freebsdsrc && \
    make -j4 buildkernel KERNCONF=SDIO TARGET=arm64 TARGET_ARCH=aarch64'
```

Output kernel: `/usr/obj/home/v/src/freebsdsrc/arm64.aarch64/sys/SDIO/kernel`

Incremental rebuild (one .c file changed): ~8 seconds.

### 4. Deploy to RPi4

Build host can't reach RPi4 directly. Relay through the local machine.

```sh
# Package on build host
ssh v@192.168.40.185 '
    OBJDIR=/usr/obj/home/v/src/freebsdsrc/arm64.aarch64/sys/SDIO
    sudo rm -rf /tmp/kernel-pkg
    sudo mkdir -p /tmp/kernel-pkg/kernel
    sudo cp $OBJDIR/kernel /tmp/kernel-pkg/kernel/
    cd /tmp/kernel-pkg
    sudo tar czf /tmp/kernel-arm64.tar.gz kernel'

# Relay through local machine
scp v@192.168.40.185:/tmp/kernel-arm64.tar.gz /tmp/kernel-arm64.tar.gz
scp /tmp/kernel-arm64.tar.gz freebsd@192.168.20.106:/tmp/kernel-arm64.tar.gz

# Install and reboot on RPi4
ssh freebsd@192.168.20.106 '
    cd /tmp
    sudo tar xzf kernel-arm64.tar.gz
    sudo cp kernel/kernel /boot/kernel/kernel
    sudo reboot'
```

Stock kernel is backed up at `/boot/kernel.bak/` on the RPi4.

### 5. Verify

```sh
ssh freebsd@192.168.20.106 'sysctl -n kern.ident; uname -v'
```

Use both values:

- `kern.ident` tells you which kernel variant you intended to boot
- `uname -v` timestamp and `#N` distinguish rebuilds of that same variant

`#N` alone is not a reliable experiment marker.

## Keeping local and build host in sync

To reset both to a clean state and reapply all patches in-order:

```sh
# Local
git -C freebsdsrc/ checkout -- .
for p in patches/*.patch; do
    git -C freebsdsrc apply "$p"
done

# Sync to build host
rsync -av --exclude=.git/ --delete freebsdsrc/ v@192.168.40.185:~/src/freebsdsrc/
```
