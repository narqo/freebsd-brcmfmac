# Build and Test

## Overview

The project cannot be built locally - it requires FreeBSD 15 kernel headers.
Build happens on a remote FreeBSD host, testing on a separate VM with the target hardware.

## Hosts

| Host | Address | Purpose |
|------|---------|---------|
| Build host | varankinv@192.168.20.82 | Compile the kernel module |
| Test VM | root@192.168.200.10 | Load and test the module (has BCM4350 hardware) |

## Workflow

### 1. Sync code to build host

```sh
rsync -avz --exclude='*.ko' --exclude=.git/ --exclude=.jj/ --exclude=.claude/ \
    --exclude='.zig-*/' --exclude-from=.gitignore --delete \
    . varankinv@192.168.20.82:src/brcmfmac2/
```

### 2. Build on remote host

```sh
ssh -o ConnectTimeout=5 varankinv@192.168.20.82
cd src/brcmfmac2/
make clean; make
```

Verify the artifact exists:
```sh
ls -1 if_brcmfmac.ko
```

### 3. Ensure test VM is running

On the build host:
```sh
sudo vm list vm0
```

### 4. Upload artifact to test VM

From the build host:
```sh
scp if_brcmfmac.ko root@192.168.200.10:
```

### 5. Test on the VM

Connect to VM (via jump host):
```sh
ssh -o ConnectTimeout=5 -J varankinv@192.168.20.82 root@192.168.200.10
```

Check currently loaded modules:
```sh
kldstat | grep if_
```

Load the module:
```sh
kldload ./if_brcmfmac.ko
```

Check output:
```sh
dmesg | tail -50
```

Unload:
```sh
kldunload if_brcmfmac
```

## Quick one-liner

Sync, build, upload, and load:
```sh
rsync -avz --exclude='*.ko' --exclude=.git/ --exclude=.jj/ --exclude=.claude/ \
    --exclude='.zig-*/' --exclude-from=.gitignore --delete \
    . varankinv@192.168.20.82:src/brcmfmac2/ && \
ssh varankinv@192.168.20.82 'cd src/brcmfmac2 && make clean && make && scp if_brcmfmac.ko root@192.168.200.10:'
```

Then on the VM:
```sh
ssh -J varankinv@192.168.20.82 root@192.168.200.10 'kldunload if_brcmfmac 2>/dev/null; kldload ./if_brcmfmac.ko && dmesg | tail -50'
```

## Expected dmesg output

A successful load with default settings (debug=0) produces:

```
brcmfmac0: <Broadcom BCM4350 WiFi> mem 0xc0400000-0xc0407fff,0xc0000000-0xc03fffff at device 6.0 on pci0
brcmfmac0: chip=4350 rev=5 socitype=AXI
brcmfmac0: loaded firmware brcmfmac4350c2-pcie.bin (623304 bytes)
brcmfmac0: firmware: wl0: Nov 26 2015 03:48:57 version 7.35.180.133 (r602372) FWID 01-c45b39d6
brcmfmac0: MAC address f4:0f:24:2a:72:e3
```

If the chip is dead (returns 0xffffffff on BAR0), kldload hangs
indefinitely. See "Stuck chip recovery" below.

## Debug output

Two mechanisms for verbose output:

**bootverbose** — kernel-global, set at boot time. Enables
`ieee80211_announce` (rate/MCS capability dump). Set via `boot -v`
at the loader prompt or in `/boot/loader.conf`:
```
boot_verbose="YES"
```

**sysctl debug** — per-device, set at runtime after module load.
Enables EROM enumeration, ring info, buffer posting counts, flowring
creation, and other trace output:
```sh
sysctl dev.brcmfmac.0.debug=2
```

The sysctl only exists while the module is loaded and defaults to 0.

Both `bootverbose` and `debug >= 2` enable the same `BRCMF_DBG`
output. Use `bootverbose` when you need attach-time diagnostics
(EROM, rings, shared RAM); use the sysctl for runtime events
(flowring creation, scan skips, TX completion errors) without
rebooting.

## WiFi association test

```sh
# Create VAP and bring up interface
ifconfig wlan0 create wlandev brcmfmac0
ifconfig wlan0 up

# Start wpa_supplicant (config must exist on the VM)
wpa_supplicant -Dbsd -iwlan0 -c/tmp/wpa_sha256.conf -B

# Check association (wait ~10s)
wpa_cli status          # wpa_state=COMPLETED
ifconfig wlan0          # status: associated

# DHCP
dhclient wlan0

# Verify connectivity (must target WiFi subnet, see below)
ping -c 5 192.168.188.1
```

The wpa_supplicant config on the VM (`/tmp/wpa_sha256.conf`):
```
ctrl_interface=/var/run/wpa_supplicant
network={
    ssid="TestAP"
    psk="SuperSecret!Test1"
    key_mgmt=WPA-PSK-SHA256
    proto=RSN
    pairwise=CCMP
}
```

### Interface cycling test

```sh
# Single cycle
ifconfig wlan0 down; sleep 5; ifconfig wlan0 up
# Wait ~10s, check wpa_cli status

# Clean teardown
pkill wpa_supplicant
ifconfig wlan0 destroy
kldunload if_brcmfmac
```

Use >=5s gap between down/up on DFS channels. 2s gaps deadlock
with wpa_supplicant running (known issue).

## Stuck chip recovery

After a kernel panic or hung kldload, the BCM4350 may stop responding
(BAR0 reads return 0xffffffff). Symptoms:

- `kldload` hangs (waiting for firmware handshake)
- `kldunload` hangs (detach stuck on firmware ioctls)
- `kldstat` hangs (module list locked by stuck thread)

Recovery steps:

1. Reboot the VM from the build host:
   ```sh
   ssh varankinv@192.168.20.82 'sudo vm poweroff vm0; sleep 3; sudo vm start vm0'
   ```
2. If the chip still returns 0xffffffff after VM reboot, a **physical
   host power cycle** is required. QEMU PCI passthrough does not reset
   the physical device on VM reboot.

To check chip health after boot (before loading the module):
```sh
pciconf -r pci0:0:6:0 0x00    # should return device/vendor ID, not 0xffffffff
```

## Crash investigation

Kernel panics generate crash dumps in `/var/crash/` on the test VM. The VM auto-reboots
after a panic and `savecore` runs during boot to save the dump.

### Checking for crashes

```sh
# List crash dumps (sorted by time)
ls -lat /var/crash/*.txt* | head -5

# Check bounds file to see dump count
cat /var/crash/bounds
```

### Analyzing a crash

```sh
# View the crash summary (includes backtrace)
cat /var/crash/core.txt.0

# Find the panic message and backtrace
grep -A30 "Fatal trap" /var/crash/core.txt.0

# View crash metadata
cat /var/crash/info.0
```

### Key information in crash dumps

- `fault virtual address` - the bad pointer that caused the crash
- `current process` - kernel thread that crashed
- `KDB: stack backtrace` - call stack leading to the crash
- `#N ... at function+0xNN` - function names and offsets

### Common patterns

- Address `0xffff` or similar small values often indicate NULL pointer + offset
- `page not present` means accessing unmapped memory
- Look for our module functions (e.g., `brcmf_*`) in the backtrace

### Testing tips

When testing code that may crash:

1. Use short SSH timeouts (`-o ConnectTimeout=10`)
2. **Always use `timeout` parameter (30s) on bash tool calls** - prevents agent from hanging on VM crash
3. Run commands that may trigger crashes separately from status checks
4. After a potential crash, wait ~15 seconds for VM to reboot and savecore to complete
5. Check VM state from build host: `sudo vm list vm0`

### Verifying traffic goes over WiFi

The VM has two interfaces: `vtnet0` (ethernet, default route) and `wlan0` (WiFi).
The default route goes via vtnet0 — any test that doesn't account for this will
silently send traffic over ethernet instead of WiFi.

**Always verify the interface before testing:**
```sh
route get <target-ip>   # must show interface: wlan0
```

**For connectivity tests, target an IP in the `192.168.188.0/24` subnet** (the
WiFi AP's LAN). That subnet is only reachable via wlan0, so the kernel routes it
correctly regardless of the default route.

```sh
# Correct: target is in 192.168.188.0/24, routed via wlan0
ping -c 10 192.168.188.1

# Wrong: goes via vtnet0 (default route), not WiFi
ping -c 10 8.8.8.8
fetch http://example.com/
```

Note: `-S 192.168.188.103` (source address binding) does not force the packet
out via wlan0 — it only sets the source IP. The outgoing interface is still
determined by the routing table.

Example safe test pattern:
```sh
# Step 1: Load module (separate command)
ssh -o ConnectTimeout=30 ... 'kldload ./if_brcmfmac.ko && echo LOADED'

# Step 2: Configure (separate command)  
ssh -o ConnectTimeout=30 ... 'ifconfig wlan0 up && echo UP'

# Step 3: Check results (separate command)
ssh -o ConnectTimeout=30 ... 'ifconfig wlan0'
```
