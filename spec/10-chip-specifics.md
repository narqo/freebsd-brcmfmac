# Chip-Specific Details

## Chip identification

The driver identifies chips by reading the chip ID and revision from the chip common core. Chip ID is a 16-bit value; revision is a 4-bit or 8-bit value depending on the enumeration method.

### Backplane enumeration

Broadcom chips use either SSB (Sonics Silicon Backplane) or AI (AMBA Interconnect) style enumeration:

- **AI (AMBA)**: Chips with `SOCI_AI`. An EROM table at a known address contains component descriptors for each core. Each descriptor provides core ID, revision, and base address. The driver walks the EROM to build its core list.
- **SSB**: Older chips. Cores are found at fixed offsets with an identification register.

The enumeration base address is chip-dependent. For most PCIe chips it is `0x18000000`. Some newer chips (4387) use different bases.

### Core types used

| Core ID | BCMA constant | Purpose |
|---------|---------------|---------|
| 0x800 | `BCMA_CORE_CHIPCOMMON` | System control, clock, OTP |
| 0x80E | `BCMA_CORE_INTERNAL_MEM` | Internal SRAM/SOCRAM |
| 0x812 | `BCMA_CORE_80211` | D11 MAC core |
| 0x827 | `BCMA_CORE_PMU` | Power Management Unit |
| 0x829 | `BCMA_CORE_SDIO_DEV` | SDIO device interface |
| 0x82A | `BCMA_CORE_ARM_CM3` | ARM Cortex-M3 CPU |
| 0x83C | `BCMA_CORE_PCIE2` | PCIe Gen2 core |
| 0x83E | `BCMA_CORE_ARM_CR4` | ARM Cortex-R4 CPU |
| 0x840 | `BCMA_CORE_GCI` | Global Control Interface |
| 0x847 | `BCMA_CORE_ARM_CA7` | ARM Cortex-A7 CPU |

### Core reset and enable

To reset a core:
1. Disable: write `REJECT | RESET` to the wrapper reset register. Wait for `REJECT` ack. Write `RESET`. Wait for `RESET` to assert.
2. Enable: clear `RESET`, set `CLOCK | FORCE_HW_CLK`, then clear `FORCE_HW_CLK`.

These operations use the AI wrapper registers at `core_base + 0x1000`.

## RAM configuration

### ARM CR4 chips (most PCIe chips including BCM4350)

RAM base and size are determined by reading ARM core bank info:
- Read bank count from `bankidx` register.
- For each bank, read `bankinfo` to get size.
- Retention RAM banks (flagged in `bankinfo`) contribute to `srsize`.
- `ramsize = sum of all bank sizes`; `srsize = sum of retention banks`.

### SOCRAM chips (older SDIO chips)

RAM is internal SRAM. Bank information is read from the SOCRAM core's `coreinfo` and `bankinfo` registers.

## Firmware selection

### PCIe firmware mapping

| Chip ID | Rev mask | Firmware base name |
|---------|----------|-------------------|
| 43602 | all | `brcmfmac43602-pcie` |
| 43465 | 0xFFFFFFF0 | `brcmfmac4366c-pcie` |
| 4350 | 0x000000FF | `brcmfmac4350c2-pcie` |
| 4350 | 0xFFFFFF00 | `brcmfmac4350-pcie` |
| 43525 | 0xFFFFFFF0 | `brcmfmac4365c-pcie` |
| 4355 | 0x000007FF | `brcmfmac4355-pcie` |
| 4355 | 0x00002000 | `brcmfmac54591-pcie` |
| 4355 | 0xFFFFF800 | `brcmfmac4355c1-pcie` |
| 4356 | all | `brcmfmac4356-pcie` |
| 43567 | all | `brcmfmac43570-pcie` |
| 43569 | all | `brcmfmac43570-pcie` |
| 43570 | all | `brcmfmac43570-pcie` |
| 4358 | all | `brcmfmac4358-pcie` |
| 4359 | 0x000001FF | `brcmfmac4359-pcie` |
| 4359 | 0xFFFFFE00 | `brcmfmac4359c-pcie` |
| 4364 | 0x0000000F | `brcmfmac4364b2-pcie` |
| 4364 | 0xFFFFFFF0 | `brcmfmac4364b3-pcie` |
| 4365 | 0x0000000F | `brcmfmac4365b-pcie` |
| 4365 | 0xFFFFFFF0 | `brcmfmac4365c-pcie` |
| 4366 | 0x0000000F | `brcmfmac4366b-pcie` |
| 4366 | 0xFFFFFFF0 | `brcmfmac4366c-pcie` |
| 43664 | 0xFFFFFFF0 | `brcmfmac4366c-pcie` |
| 43666 | 0xFFFFFFF0 | `brcmfmac4366c-pcie` |
| 4371 | all | `brcmfmac4371-pcie` |
| 43752 | all | `brcmfmac43752-pcie` |
| 4377 | all | `brcmfmac4377b3-pcie` |
| 4378 | 0x0000000F | `brcmfmac4378b1-pcie` |
| 4378 | 0xFFFFFFE0 | `brcmfmac4378b3-pcie` |
| 4387 | all | `brcmfmac4387c2-pcie` |

Each entry produces file requests for `.bin`, `.txt` (NVRAM), `.clm_blob`, and `.txcap_blob`.

### SDIO firmware mapping

Similar mapping from `(chip_id, revision_mask)` to firmware base name. SDIO firmware uses the `-sdio` suffix instead of `-pcie`.

### Board-type NVRAM

The firmware loading system tries board-type-specific NVRAM files first:
1. `<base>.<board_type>.txt`
2. `<base>.txt`

Board type comes from device tree, ACPI, or OTP data.

## BCM4350 specifics

- **Chip ID**: `0x4350`
- **Bus**: PCIe
- **Protocol**: msgbuf
- **PCI Device ID**: `0x43a3`
- **ARM core**: CR4
- **Firmware**: `brcmfmac4350c2-pcie.bin` (revisions 0–7)
- **Firmware vendor**: WCC
- **Random seed**: not required (`fw_seed = false`)

## BCM43455 specifics

- **Chip ID**: `0x4345` (BCM4345/6 family)
- **Bus**: SDIO
- **Protocol**: BCDC + fwsignal
- **SDIO Device ID**: `0x4345`
- **F2 block size**: 512 (default)
- **Firmware**: `brcmfmac43455-sdio.bin`

## OTP (One-Time Programmable) memory

Chips that support OTP (4355, 4364, 4377, 4378, 4387) contain board identification data:

| Chip | Core | OTP base | Word count |
|------|------|----------|------------|
| 4355 | ChipCommon | 0x8c0 | 0xb2 |
| 4364 | ChipCommon | 0x8c0 | 0x1a0 |
| 4377/4378 | GCI | 0x1120 | 0x170 |
| 4387 | GCI | 0x113c | 0x170 |

OTP data is parsed as TLV: type (1 byte), length (1 byte), value (variable). The `SYS_VENDOR` type (0x15) contains a 4-byte header followed by two NUL-terminated strings (chip params and board params). Board params use space-separated `key=value` pairs with single-letter keys:
- `M=`: module identifier
- `V=`: vendor identifier
- `m=`: version identifier

## Firmware vendor identification

Each PCI device maps to a firmware vendor:
- **WCC**: Broadcom Wireless Connectivity Combo (most chips)
- **BCA**: Broadcom Connectivity Alliance (4365, 4366 family)
- **CYW**: Cypress/Infineon (43596, 54591)

The vendor determines which vendor-specific ops module is loaded for event remapping and optional feature extensions.
