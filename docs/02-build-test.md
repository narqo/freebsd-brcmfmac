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
