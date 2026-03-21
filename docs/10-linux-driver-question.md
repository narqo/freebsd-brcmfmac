# Question: SDIO F2 data write sequence in brcmfmac

I'm writing a brcmfmac SDIO driver for FreeBSD targeting BCM43455
(CYW43455) on Raspberry Pi 4. Firmware boots successfully, but
F2 CMD53 writes fail with an immediate R5 error. F2 reads work.

I'd like to understand how the Linux brcmfmac driver handles F2
data writes.

## What I need to know

1. What address and CMD53 mode (fixed vs incrementing) does the
   driver use for F2 data writes?

2. What is the complete sequence of operations between
   `sdio_enable_func(func2)` and the first F2 data write?
   (SDIO core register setup, CCCR configuration, delays, etc.)

3. How does the driver determine that F2 is ready to accept
   data after firmware boot?

## Hardware and observations

- Chip: BCM4345/CYW43455, revision 6, SDIO
- Firmware: brcmfmac43455-sdio.bin (609KB), boots successfully
  (sharedram marker valid)
- Host: Raspberry Pi 4, BCM2835 Arasan SDHCI, 4-bit bus, 25 MHz
- F1 CMD53 writes work (firmware download completes)
- F2 CMD53 reads work
- F2 CMD53 writes fail (R5 error, no timeout, immediate failure)
- SDIO core intstatus after firmware boot: 0xa0000000
