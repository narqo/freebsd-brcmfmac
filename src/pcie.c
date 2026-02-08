#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bus.h>
#include <sys/firmware.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/rman.h>

#include <machine/bus.h>

#include <dev/pci/pcireg.h>
#include <dev/pci/pcivar.h>

#include "brcmfmac.h"

MALLOC_DEFINE(M_BRCMFMAC, "brcmfmac", "Broadcom FullMAC WiFi driver");

/* SI_ENUM_BASE - chip enumeration base address */
#define SI_ENUM_BASE 0x18000000

/* BAR0 window register in PCI config space */
#define BRCMF_PCIE_BAR0_WINDOW 0x80

/* BCM4350 RAM info */
#define BCM4350_RAM_BASE 0x180000
#define BCM4350_RAM_SIZE 0xC0000 /* 768KB */

/* BCMA core control/status registers (offset from wrapper base) */
#define BCMA_IOCTL     0x0408
#define BCMA_IOST      0x0500
#define BCMA_RESET_CTL 0x0800
#define BCMA_RESET_ST  0x0804

/* BCMA_IOCTL bits */
#define BCMA_IOCTL_CLK	   0x0001
#define BCMA_IOCTL_FGC	   0x0002
#define BCMA_IOCTL_CPUHALT 0x0020

/* D11 core IOCTL bits */
#define D11_BCMA_IOCTL_PHYCLOCKEN 0x0004
#define D11_BCMA_IOCTL_PHYRESET	  0x0008

/* BCMA_RESET_CTL bits */
#define BCMA_RESET_CTL_RESET 0x0001

/* Core IDs (12-bit DMP part numbers from EROM) */
#define BCMA_CORE_CHIPCOMMON 0x800
#define BCMA_CORE_SOCRAM     0x80e
#define BCMA_CORE_80211	     0x812
#define BCMA_CORE_ARM_CR4    0x83e
#define BCMA_CORE_PCIE2	     0x83c

/* ChipCommon register offsets */
#define CC_WATCHDOG 0x80

/* PCIe BAR0 register offsets (after selecting PCIE2 core) */
#define BRCMF_PCIE_PCIE2REG_INTMASK	    0x24
#define BRCMF_PCIE_PCIE2REG_MAILBOXINT	    0x48
#define BRCMF_PCIE_PCIE2REG_MAILBOXMASK    0x4C
#define BRCMF_PCIE_PCIE2REG_CONFIGADDR	    0x120
#define BRCMF_PCIE_PCIE2REG_CONFIGDATA	    0x124
#define BRCMF_PCIE_PCIE2REG_H2D_MAILBOX_0  0x140
#define BRCMF_PCIE_PCIE2REG_H2D_MAILBOX_1  0x144

/* PCIe link control */
#define BRCMF_PCIE_REG_LINK_STATUS_CTRL	     0xBC
#define BRCMF_PCIE_LINK_STATUS_CTRL_ASPM_ENAB 3

/* Shared RAM structure offsets */
#define BRCMF_PCIE_SHARED_VERSION_MASK	       0x00FF
#define BRCMF_PCIE_MIN_SHARED_VERSION	       5
#define BRCMF_PCIE_MAX_SHARED_VERSION	       7
#define BRCMF_PCIE_SHARED_DMA_INDEX	       0x10000
#define BRCMF_PCIE_SHARED_DMA_2B_IDX	       0x100000
#define BRCMF_PCIE_SHARED_HOSTRDY_DB1	       0x10000000

#define BRCMF_SHARED_MAX_RXBUFPOST_OFFSET     34
#define BRCMF_SHARED_RX_DATAOFFSET_OFFSET     36
#define BRCMF_SHARED_HTOD_MB_DATA_ADDR_OFFSET 40
#define BRCMF_SHARED_DTOH_MB_DATA_ADDR_OFFSET 44
#define BRCMF_SHARED_RING_INFO_ADDR_OFFSET    48
#define BRCMF_SHARED_DMA_SCRATCH_LEN_OFFSET   52
#define BRCMF_SHARED_DMA_SCRATCH_ADDR_OFFSET  56
#define BRCMF_SHARED_DMA_RINGUPD_LEN_OFFSET   64
#define BRCMF_SHARED_DMA_RINGUPD_ADDR_OFFSET  68

#define BRCMF_DEF_MAX_RXBUFPOST 255

/* Ring info structure offsets */
#define BRCMF_RING_RINGMEM_OFFSET	  0
#define BRCMF_RING_H2D_W_IDX_PTR_OFFSET	  4
#define BRCMF_RING_H2D_R_IDX_PTR_OFFSET	  8
#define BRCMF_RING_D2H_W_IDX_PTR_OFFSET	  12
#define BRCMF_RING_D2H_R_IDX_PTR_OFFSET	  16
#define BRCMF_RING_H2D_W_HOSTADDR_OFFSET  20
#define BRCMF_RING_H2D_R_HOSTADDR_OFFSET  28
#define BRCMF_RING_D2H_W_HOSTADDR_OFFSET  36
#define BRCMF_RING_D2H_R_HOSTADDR_OFFSET  44
#define BRCMF_RING_MAX_FLOWRINGS_OFFSET	  52
#define BRCMF_RING_MAX_SUBMISSION_OFFSET  54
#define BRCMF_RING_MAX_COMPLETION_OFFSET  56

/* Ring memory descriptor offsets (per ring, 16 bytes each) */
#define BRCMF_RING_MEM_BASE_ADDR_OFFSET	 8
#define BRCMF_RING_MAX_ITEM_OFFSET	 4
#define BRCMF_RING_LEN_ITEMS_OFFSET	 6
#define BRCMF_RING_MEM_SZ		 16

/* Ring sizes (items) */
#define BRCMF_H2D_MSGRING_CONTROL_SUBMIT_MAX_ITEM    64
#define BRCMF_H2D_MSGRING_RXPOST_SUBMIT_MAX_ITEM	    1024
#define BRCMF_D2H_MSGRING_CONTROL_COMPLETE_MAX_ITEM  64
#define BRCMF_D2H_MSGRING_TX_COMPLETE_MAX_ITEM	    1024
#define BRCMF_D2H_MSGRING_RX_COMPLETE_MAX_ITEM	    1024

/* Ring item sizes */
#define BRCMF_H2D_MSGRING_CONTROL_SUBMIT_ITEMSIZE    40
#define BRCMF_H2D_MSGRING_RXPOST_SUBMIT_ITEMSIZE	    32
#define BRCMF_D2H_MSGRING_CONTROL_COMPLETE_ITEMSIZE  24
#define BRCMF_D2H_MSGRING_TX_COMPLETE_ITEMSIZE_PRE_V7 16
#define BRCMF_D2H_MSGRING_RX_COMPLETE_ITEMSIZE_PRE_V7 32
#define BRCMF_D2H_MSGRING_TX_COMPLETE_ITEMSIZE	    24
#define BRCMF_D2H_MSGRING_RX_COMPLETE_ITEMSIZE	    40

/* DMA buffer sizes */
#define BRCMF_DMA_D2H_SCRATCH_BUF_LEN	8
#define BRCMF_DMA_D2H_RINGUPD_BUF_LEN	1024

/* Firmware polling */
#define BRCMF_FW_READY_TIMEOUT_MS 5000
#define BRCMF_FW_READY_POLL_MS	  50

/* Firmware names */
#define BRCMF_FW_NAME	  "brcmfmac4350-pcie.bin"
#define BRCMF_FW_NAME_C2 "brcmfmac4350c2-pcie.bin"
#define BRCMF_NVRAM_NAME    "brcmfmac4350-pcie.txt"
#define BRCMF_NVRAM_NAME_C2 "brcmfmac4350c2-pcie.txt"

/*
 * BAR0 register access
 */
static uint32_t
brcmf_reg_read(struct brcmf_softc *sc, uint32_t off)
{
	return (bus_space_read_4(sc->reg_bst, sc->reg_bsh, off));
}

static void
brcmf_reg_write(struct brcmf_softc *sc, uint32_t off, uint32_t val)
{
	bus_space_write_4(sc->reg_bst, sc->reg_bsh, off, val);
}

/*
 * TCM (BAR2) access
 */
static uint32_t
brcmf_tcm_read32(struct brcmf_softc *sc, uint32_t off)
{
	return (bus_space_read_4(sc->tcm_bst, sc->tcm_bsh, off));
}

static uint16_t
brcmf_tcm_read16(struct brcmf_softc *sc, uint32_t off)
{
	return (bus_space_read_2(sc->tcm_bst, sc->tcm_bsh, off));
}

static void
brcmf_tcm_write16(struct brcmf_softc *sc, uint32_t off, uint16_t val)
{
	bus_space_write_2(sc->tcm_bst, sc->tcm_bsh, off, val);
}

static void
brcmf_tcm_write32(struct brcmf_softc *sc, uint32_t off, uint32_t val)
{
	bus_space_write_4(sc->tcm_bst, sc->tcm_bsh, off, val);
}

static void
brcmf_tcm_write64(struct brcmf_softc *sc, uint32_t off, uint64_t val)
{
	brcmf_tcm_write32(sc, off, (uint32_t)(val & 0xffffffff));
	brcmf_tcm_write32(sc, off + 4, (uint32_t)(val >> 32));
}

static void
brcmf_tcm_copy(struct brcmf_softc *sc, uint32_t off, const void *data,
    size_t len)
{
	bus_space_write_region_1(sc->tcm_bst, sc->tcm_bsh, off, data, len);
}

/*
 * RAM access (TCM + ram_base offset)
 */
static uint32_t
brcmf_ram_read32(struct brcmf_softc *sc, uint32_t off)
{
	return (brcmf_tcm_read32(sc, sc->ram_base + off));
}

static void
brcmf_ram_write32(struct brcmf_softc *sc, uint32_t off, uint32_t val)
{
	brcmf_tcm_write32(sc, sc->ram_base + off, val);
}

/*
 * Backplane access via BAR0 window.
 *
 * BAR0 provides a 4KB window into the backplane. We set the window base
 * in PCI config space and read/write within that window.
 */
static uint32_t
brcmf_bp_read32(struct brcmf_softc *sc, uint32_t addr)
{
	uint32_t window = addr & 0xfffff000;
	uint32_t offset = addr & 0x00000fff;

	pci_write_config(sc->dev, BRCMF_PCIE_BAR0_WINDOW, window, 4);
	brcmf_reg_read(sc, 0); /* flush */

	return (brcmf_reg_read(sc, offset));
}

static void
brcmf_bp_write32(struct brcmf_softc *sc, uint32_t addr, uint32_t val)
{
	uint32_t window = addr & 0xfffff000;
	uint32_t offset = addr & 0x00000fff;

	pci_write_config(sc->dev, BRCMF_PCIE_BAR0_WINDOW, window, 4);
	brcmf_reg_read(sc, 0); /* flush */

	brcmf_reg_write(sc, offset, val);
	brcmf_reg_read(sc, 0); /* flush */
}

/*
 * EROM read callback for Zig core enumeration
 */
static uint32_t
brcmf_erom_read(void *ctx, uint32_t offset)
{
	return (brcmf_bp_read32(ctx, offset));
}

/*
 * Enumerate cores via EROM
 */
static int
brcmf_enumerate_cores(struct brcmf_softc *sc)
{
	uint32_t erombase;

	/* Set window to ChipCommon and read EROM base */
	pci_write_config(sc->dev, BRCMF_PCIE_BAR0_WINDOW, SI_ENUM_BASE, 4);
	brcmf_reg_read(sc, 0);

	erombase = brcmf_reg_read(sc, 0xfc);
	printf("brcmfmac: EROM base=0x%x\n", erombase);

	/* Find ARM CR4 core */
	sc->armcore = brcmf_find_core(erombase, brcmf_erom_read, sc,
	    BCMA_CORE_ARM_CR4);
	if (sc->armcore.id == 0) {
		device_printf(sc->dev, "ARM CR4 core not found\n");
		return (ENODEV);
	}
	printf("brcmfmac: ARM CR4: id=0x%x rev=%u base=0x%x wrap=0x%x\n",
	    sc->armcore.id, sc->armcore.rev, sc->armcore.base,
	    sc->armcore.wrapbase);

	/* Find SOCRAM/internal memory core (optional for CR4 chips) */
	sc->ramcore = brcmf_find_core(erombase, brcmf_erom_read, sc,
	    BCMA_CORE_SOCRAM);
	if (sc->ramcore.id != 0) {
		printf("brcmfmac: SOCRAM: id=0x%x rev=%u base=0x%x wrap=0x%x\n",
		    sc->ramcore.id, sc->ramcore.rev, sc->ramcore.base,
		    sc->ramcore.wrapbase);
	}

	/* Find D11 (802.11) core */
	sc->d11core = brcmf_find_core(erombase, brcmf_erom_read, sc,
	    BCMA_CORE_80211);
	if (sc->d11core.id != 0) {
		printf("brcmfmac: D11: id=0x%x rev=%u base=0x%x wrap=0x%x\n",
		    sc->d11core.id, sc->d11core.rev, sc->d11core.base,
		    sc->d11core.wrapbase);
	}

	/* Find PCIe2 core */
	sc->pciecore = brcmf_find_core(erombase, brcmf_erom_read, sc,
	    BCMA_CORE_PCIE2);
	if (sc->pciecore.id == 0) {
		device_printf(sc->dev, "PCIe core not found\n");
		return (ENODEV);
	}
	printf("brcmfmac: PCIe2: id=0x%x rev=%u base=0x%x wrap=0x%x\n",
	    sc->pciecore.id, sc->pciecore.rev, sc->pciecore.base,
	    sc->pciecore.wrapbase);

	return (0);
}

/*
 * Select a core by setting BAR0 window to its base address.
 */
static void
brcmf_pcie_select_core(struct brcmf_softc *sc, struct brcmf_coreinfo *core)
{
	pci_write_config(sc->dev, BRCMF_PCIE_BAR0_WINDOW, core->base, 4);
	brcmf_reg_read(sc, 0); /* flush */
}

/*
 * Watchdog reset: triggers ChipCommon watchdog to reset the whole chip.
 * For PCIe core rev <= 13, config registers must be touched after reset.
 */
static void
brcmf_pcie_reset_device(struct brcmf_softc *sc)
{
	static const uint16_t cfg_offset[] = {
		0x04,  /* STATUS_CMD */
		0x4C,  /* PM_CSR */
		0x58,  /* MSI_CAP */
		0x5C,  /* MSI_ADDR_L */
		0x60,  /* MSI_ADDR_H */
		0x64,  /* MSI_DATA */
		0xDC,  /* LINK_STATUS_CTRL2 */
		0x228, /* RBAR_CTRL */
		0x248, /* PML1_SUB_CTRL1 */
		0x4E0, /* REG_BAR2_CONFIG */
		0x4F4, /* REG_BAR3_CONFIG */
	};
	uint32_t lsc, val;
	int i;

	/* Disable ASPM */
	brcmf_pcie_select_core(sc, &sc->pciecore);

	lsc = pci_read_config(sc->dev, BRCMF_PCIE_REG_LINK_STATUS_CTRL, 4);
	val = lsc & ~BRCMF_PCIE_LINK_STATUS_CTRL_ASPM_ENAB;
	pci_write_config(sc->dev, BRCMF_PCIE_REG_LINK_STATUS_CTRL, val, 4);

	/* Watchdog reset via ChipCommon */
	pci_write_config(sc->dev, BRCMF_PCIE_BAR0_WINDOW, SI_ENUM_BASE, 4);
	brcmf_reg_read(sc, 0);
	brcmf_reg_write(sc, CC_WATCHDOG, 4);
	pause_sbt("brcmrst", mstosbt(100), 0, 0);

	/* Restore ASPM */
	brcmf_pcie_select_core(sc, &sc->pciecore);
	pci_write_config(sc->dev, BRCMF_PCIE_REG_LINK_STATUS_CTRL, lsc, 4);

	/* Touch config registers for rev <= 13 */
	if (sc->pciecore.rev <= 13) {
		for (i = 0; i < (int)nitems(cfg_offset); i++) {
			brcmf_reg_write(sc, BRCMF_PCIE_PCIE2REG_CONFIGADDR,
			    cfg_offset[i]);
			val = brcmf_reg_read(sc,
			    BRCMF_PCIE_PCIE2REG_CONFIGDATA);
			brcmf_reg_write(sc, BRCMF_PCIE_PCIE2REG_CONFIGDATA,
			    val);
		}
	}

	/* Clear mailbox interrupt */
	val = brcmf_reg_read(sc, BRCMF_PCIE_PCIE2REG_MAILBOXINT);
	if (val != 0xffffffff)
		brcmf_reg_write(sc, BRCMF_PCIE_PCIE2REG_MAILBOXINT, val);

	/* Re-enable bus master after chip reset */
	pci_enable_busmaster(sc->dev);
}

/*
 * Check if core is in reset
 */
static bool
brcmf_core_in_reset(struct brcmf_softc *sc, struct brcmf_coreinfo *core)
{
	uint32_t val;

	val = brcmf_bp_read32(sc, core->wrapbase + BCMA_RESET_CTL);
	return ((val & BCMA_RESET_CTL_RESET) != 0);
}

/*
 * Disable a core (put into reset).
 * Mirrors brcmf_chip_ai_coredisable from Linux.
 */
static void
brcmf_core_disable(struct brcmf_softc *sc, struct brcmf_coreinfo *core,
    uint32_t prereset, uint32_t reset)
{
	uint32_t val;
	int i;

	if (brcmf_core_in_reset(sc, core))
		goto in_reset_configure;

	/* Configure with prereset flags */
	brcmf_bp_write32(sc, core->wrapbase + BCMA_IOCTL,
	    prereset | BCMA_IOCTL_FGC | BCMA_IOCTL_CLK);
	brcmf_bp_read32(sc, core->wrapbase + BCMA_IOCTL);

	/* Put into reset */
	brcmf_bp_write32(sc, core->wrapbase + BCMA_RESET_CTL,
	    BCMA_RESET_CTL_RESET);
	DELAY(20);

	/* Wait for reset to take */
	for (i = 0; i < 300; i++) {
		val = brcmf_bp_read32(sc, core->wrapbase + BCMA_RESET_CTL);
		if (val == BCMA_RESET_CTL_RESET)
			break;
		DELAY(10);
	}

in_reset_configure:
	/* In-reset configure with reset flags */
	brcmf_bp_write32(sc, core->wrapbase + BCMA_IOCTL,
	    reset | BCMA_IOCTL_FGC | BCMA_IOCTL_CLK);
	brcmf_bp_read32(sc, core->wrapbase + BCMA_IOCTL);
}

/*
 * Reset a core (disable, then bring out of reset).
 * Mirrors brcmf_chip_ai_resetcore from Linux.
 */
static void
brcmf_core_reset(struct brcmf_softc *sc, struct brcmf_coreinfo *core,
    uint32_t prereset, uint32_t reset, uint32_t postreset)
{
	uint32_t val;
	int i;

	brcmf_core_disable(sc, core, prereset, reset);

	for (i = 0; i < 50; i++) {
		brcmf_bp_write32(sc, core->wrapbase + BCMA_RESET_CTL, 0);
		val = brcmf_bp_read32(sc, core->wrapbase + BCMA_RESET_CTL);
		if ((val & BCMA_RESET_CTL_RESET) == 0)
			break;
		DELAY(60);
	}

	if (val & BCMA_RESET_CTL_RESET) {
		printf("brcmfmac: core 0x%x reset timeout\n", core->id);
		return;
	}

	brcmf_bp_write32(sc, core->wrapbase + BCMA_IOCTL,
	    postreset | BCMA_IOCTL_CLK);
	brcmf_bp_read32(sc, core->wrapbase + BCMA_IOCTL);
}

/*
 * Enter firmware download state: halt ARM, disable D11.
 * Mirrors brcmf_chip_cr4_set_passive from Linux:
 *   1. disable_arm -> resetcore(arm, val, CPUHALT, CPUHALT)
 *   2. coredisable(d11, PHYRESET|PHYCLOCKEN, PHYCLOCKEN)
 */
static int
brcmf_enter_download(struct brcmf_softc *sc)
{
	uint32_t val;

	if (sc->armcore.wrapbase == 0) {
		device_printf(sc->dev, "no wrapper address for ARM core\n");
		return (EINVAL);
	}

	printf("brcmfmac: halting ARM at wrapper 0x%x\n", sc->armcore.wrapbase);

	/* Read current IOCTL and preserve only CPUHALT bit */
	val = brcmf_bp_read32(sc, sc->armcore.wrapbase + BCMA_IOCTL);
	val &= BCMA_IOCTL_CPUHALT;

	/* Reset ARM with CPUHALT set throughout */
	brcmf_core_reset(sc, &sc->armcore, val, BCMA_IOCTL_CPUHALT,
	    BCMA_IOCTL_CPUHALT);

	/* Disable D11 core to let firmware enable it */
	if (sc->d11core.id != 0 && sc->d11core.wrapbase != 0) {
		printf("brcmfmac: disabling D11 core\n");
		brcmf_core_disable(sc, &sc->d11core,
		    D11_BCMA_IOCTL_PHYRESET | D11_BCMA_IOCTL_PHYCLOCKEN,
		    D11_BCMA_IOCTL_PHYCLOCKEN);
	}

	return (0);
}

/*
 * Exit firmware download state: write reset vector and start ARM.
 * Mirrors brcmf_chip_cr4_set_active from Linux:
 *   1. activate(ctx, chip, rstvec) -> write rstvec to TCM[0]
 *   2. resetcore(arm, CPUHALT, 0, 0) -> halt, remove halt in reset, release
 */
static void
brcmf_exit_download(struct brcmf_softc *sc, uint32_t resetintr)
{
	printf("brcmfmac: writing reset vector 0x%x to TCM[0]\n", resetintr);
	brcmf_tcm_write32(sc, 0, resetintr);

	if (sc->armcore.wrapbase == 0) {
		device_printf(sc->dev,
		    "no wrapper address, cannot release ARM\n");
		return;
	}

	/*
	 * Reset ARM core: prereset=CPUHALT halts CPU during disable,
	 * reset=0 removes CPUHALT while in reset, postreset=0 releases
	 * with just CLK enabled -> CPU starts executing.
	 */
	brcmf_core_reset(sc, &sc->armcore, BCMA_IOCTL_CPUHALT, 0, 0);
	printf("brcmfmac: ARM released\n");
}

/*
 * Parse NVRAM text into binary format
 */
static void *
brcmf_nvram_parse(const void *data, size_t size, uint32_t *lenp)
{
	const char *src, *end, *line_end;
	char *dst, *buf;
	uint32_t len, pad;

	if (data == NULL || size == 0) {
		*lenp = 0;
		return (NULL);
	}

	buf = malloc(size + 8, M_BRCMFMAC, M_NOWAIT | M_ZERO);
	if (buf == NULL) {
		*lenp = 0;
		return (NULL);
	}

	src = data;
	end = src + size;
	dst = buf;

	while (src < end) {
		line_end = src;
		while (line_end < end && *line_end != '\n' && *line_end != '\r')
			line_end++;

		if (src < line_end && *src != '#') {
			while (src < line_end)
				*dst++ = *src++;
			*dst++ = '\0';
		}

		while (src < end && (*src == '\n' || *src == '\r'))
			src++;
		if (line_end < end)
			src = line_end + 1;
	}

	len = dst - buf;
	pad = (4 - (len & 3)) & 3;
	len += pad;
	while (pad--)
		*dst++ = '\0';

	/* Add NVRAM token */
	len += 4;
	*dst++ = len & 0xff;
	*dst++ = (len >> 8) & 0xff;
	*dst++ = ~len & 0xff;
	*dst++ = ~(len >> 8) & 0xff;

	*lenp = len;
	return (buf);
}

/*
 * Check firmware for embedded RAM size override.
 */
#define BRCMF_RAMSIZE_MAGIC  0x534d4152 /* "SMAR" */
#define BRCMF_RAMSIZE_OFFSET 0x6c

static void
brcmf_pcie_adjust_ramsize(struct brcmf_softc *sc, const void *data,
    size_t data_len)
{
	const uint32_t *field;
	uint32_t newsize;

	if (data_len < BRCMF_RAMSIZE_OFFSET + 8)
		return;

	field = (const uint32_t *)((const char *)data + BRCMF_RAMSIZE_OFFSET);
	if (le32toh(field[0]) != BRCMF_RAMSIZE_MAGIC)
		return;

	newsize = le32toh(field[1]);
	printf("brcmfmac: firmware requests ramsize 0x%x\n", newsize);
	sc->ram_size = newsize;
}

/*
 * Parse shared RAM info after firmware boots.
 */
static int
brcmf_pcie_init_shared(struct brcmf_softc *sc, uint32_t sharedram_addr)
{
	struct brcmf_pcie_shared_info *shared;
	uint32_t addr;

	shared = &sc->shared;
	shared->tcm_base_address = sharedram_addr;

	shared->flags = brcmf_tcm_read32(sc, sharedram_addr);
	shared->version = shared->flags & BRCMF_PCIE_SHARED_VERSION_MASK;

	printf("brcmfmac: shared version %u, flags 0x%x\n",
	    shared->version, shared->flags);

	if (shared->version > BRCMF_PCIE_MAX_SHARED_VERSION ||
	    shared->version < BRCMF_PCIE_MIN_SHARED_VERSION) {
		device_printf(sc->dev, "unsupported shared version %u\n",
		    shared->version);
		return (EINVAL);
	}

	if (shared->flags & BRCMF_PCIE_SHARED_DMA_INDEX) {
		if (shared->flags & BRCMF_PCIE_SHARED_DMA_2B_IDX)
			shared->dma_idx_sz = sizeof(uint16_t);
		else
			shared->dma_idx_sz = sizeof(uint32_t);
	}

	addr = sharedram_addr + BRCMF_SHARED_MAX_RXBUFPOST_OFFSET;
	shared->max_rxbufpost = brcmf_tcm_read16(sc, addr);
	if (shared->max_rxbufpost == 0)
		shared->max_rxbufpost = BRCMF_DEF_MAX_RXBUFPOST;

	addr = sharedram_addr + BRCMF_SHARED_RX_DATAOFFSET_OFFSET;
	shared->rx_dataoffset = brcmf_tcm_read32(sc, addr);

	addr = sharedram_addr + BRCMF_SHARED_HTOD_MB_DATA_ADDR_OFFSET;
	shared->htod_mb_data_addr = brcmf_tcm_read32(sc, addr);

	addr = sharedram_addr + BRCMF_SHARED_DTOH_MB_DATA_ADDR_OFFSET;
	shared->dtoh_mb_data_addr = brcmf_tcm_read32(sc, addr);

	addr = sharedram_addr + BRCMF_SHARED_RING_INFO_ADDR_OFFSET;
	shared->ring_info_addr = brcmf_tcm_read32(sc, addr);

	printf("brcmfmac: max_rxbufpost=%u rx_dataoffset=%u\n",
	    shared->max_rxbufpost, shared->rx_dataoffset);
	printf("brcmfmac: ring_info_addr=0x%x\n", shared->ring_info_addr);
	printf("brcmfmac: htod_mb=0x%x dtoh_mb=0x%x\n",
	    shared->htod_mb_data_addr, shared->dtoh_mb_data_addr);

	return (0);
}

/*
 * Signal host ready to firmware via doorbell 1.
 */
static void
brcmf_pcie_hostready(struct brcmf_softc *sc)
{
	if (sc->shared.flags & BRCMF_PCIE_SHARED_HOSTRDY_DB1) {
		brcmf_pcie_select_core(sc, &sc->pciecore);
		brcmf_reg_write(sc, BRCMF_PCIE_PCIE2REG_H2D_MAILBOX_1, 1);
	}
}

/*
 * DMA callback to get physical address
 */
static void
brcmf_dma_cb(void *arg, bus_dma_segment_t *segs, int nseg, int error)
{
	if (error == 0 && nseg == 1)
		*(bus_addr_t *)arg = segs[0].ds_addr;
	else
		*(bus_addr_t *)arg = 0;
}

/*
 * Allocate a DMA-coherent buffer.
 */
static int
brcmf_alloc_dma_buf(device_t dev, size_t size, bus_dma_tag_t *tag,
    bus_dmamap_t *map, void **buf, bus_addr_t *paddr)
{
	int error;

	error = bus_dma_tag_create(bus_get_dma_tag(dev),
	    4, 0,			/* alignment, boundary */
	    BUS_SPACE_MAXADDR,		/* lowaddr */
	    BUS_SPACE_MAXADDR,		/* highaddr */
	    NULL, NULL,			/* filter, filterarg */
	    size, 1, size,		/* maxsize, nsegments, maxsegsize */
	    BUS_DMA_COHERENT,		/* flags */
	    NULL, NULL,			/* lockfunc, lockarg */
	    tag);
	if (error != 0)
		return (error);

	error = bus_dmamem_alloc(*tag, buf, BUS_DMA_NOWAIT | BUS_DMA_ZERO, map);
	if (error != 0) {
		bus_dma_tag_destroy(*tag);
		*tag = NULL;
		return (error);
	}

	error = bus_dmamap_load(*tag, *map, *buf, size, brcmf_dma_cb, paddr,
	    BUS_DMA_NOWAIT);
	if (error != 0 || *paddr == 0) {
		bus_dmamem_free(*tag, *buf, *map);
		bus_dma_tag_destroy(*tag);
		*tag = NULL;
		*buf = NULL;
		return (error != 0 ? error : ENOMEM);
	}

	return (0);
}

/*
 * Free a DMA-coherent buffer.
 */
static void
brcmf_free_dma_buf(bus_dma_tag_t tag, bus_dmamap_t map, void *buf)
{
	if (tag == NULL)
		return;

	if (buf != NULL) {
		bus_dmamap_unload(tag, map);
		bus_dmamem_free(tag, buf, map);
	}
	bus_dma_tag_destroy(tag);
}

/*
 * Free a single ring buffer.
 */
static void
brcmf_ring_free(struct brcmf_pcie_ringbuf *ring)
{
	if (ring == NULL)
		return;

	brcmf_free_dma_buf(ring->dma_tag, ring->dma_map, ring->buf);
	free(ring, M_BRCMFMAC);
}

/*
 * Allocate a single ring buffer and write its descriptor to TCM.
 */
static struct brcmf_pcie_ringbuf *
brcmf_ring_alloc(struct brcmf_softc *sc, int id, uint16_t depth,
    uint16_t item_len, uint32_t ringmem_addr)
{
	struct brcmf_pcie_ringbuf *ring;
	uint32_t desc_addr;
	size_t size;
	int error;

	ring = malloc(sizeof(*ring), M_BRCMFMAC, M_NOWAIT | M_ZERO);
	if (ring == NULL)
		return (NULL);

	ring->id = id;
	ring->depth = depth;
	ring->item_len = item_len;
	size = (size_t)depth * item_len;

	error = brcmf_alloc_dma_buf(sc->dev, size, &ring->dma_tag,
	    &ring->dma_map, &ring->buf, &ring->dma_handle);
	if (error != 0) {
		free(ring, M_BRCMFMAC);
		return (NULL);
	}

	/* Write ring descriptor to TCM */
	desc_addr = ringmem_addr + id * BRCMF_RING_MEM_SZ;

	/* max_items at offset 4 (16-bit) */
	brcmf_tcm_write16(sc, desc_addr + BRCMF_RING_MAX_ITEM_OFFSET, depth);

	/* item_len at offset 6 (16-bit) */
	brcmf_tcm_write16(sc, desc_addr + BRCMF_RING_LEN_ITEMS_OFFSET, item_len);

	/* base_addr at offset 8 (64-bit) */
	brcmf_tcm_write32(sc, desc_addr + BRCMF_RING_MEM_BASE_ADDR_OFFSET,
	    (uint32_t)(ring->dma_handle & 0xffffffff));
	brcmf_tcm_write32(sc, desc_addr + BRCMF_RING_MEM_BASE_ADDR_OFFSET + 4,
	    (uint32_t)(ring->dma_handle >> 32));

	return (ring);
}

/*
 * Read ring info from TCM and set up ring addresses.
 */
static int
brcmf_pcie_init_ringinfo(struct brcmf_softc *sc)
{
	uint32_t addr = sc->shared.ring_info_addr;

	sc->ringmem_addr = brcmf_tcm_read32(sc, addr + BRCMF_RING_RINGMEM_OFFSET);
	sc->h2d_w_idx_addr = brcmf_tcm_read32(sc, addr + BRCMF_RING_H2D_W_IDX_PTR_OFFSET);
	sc->h2d_r_idx_addr = brcmf_tcm_read32(sc, addr + BRCMF_RING_H2D_R_IDX_PTR_OFFSET);
	sc->d2h_w_idx_addr = brcmf_tcm_read32(sc, addr + BRCMF_RING_D2H_W_IDX_PTR_OFFSET);
	sc->d2h_r_idx_addr = brcmf_tcm_read32(sc, addr + BRCMF_RING_D2H_R_IDX_PTR_OFFSET);

	if (sc->shared.version >= 6) {
		sc->max_flowrings = brcmf_tcm_read16(sc,
		    addr + BRCMF_RING_MAX_FLOWRINGS_OFFSET);
		sc->max_submissionrings = brcmf_tcm_read16(sc,
		    addr + BRCMF_RING_MAX_SUBMISSION_OFFSET);
		sc->max_completionrings = brcmf_tcm_read16(sc,
		    addr + BRCMF_RING_MAX_COMPLETION_OFFSET);
	} else {
		sc->max_submissionrings = brcmf_tcm_read16(sc,
		    addr + BRCMF_RING_MAX_FLOWRINGS_OFFSET);
		sc->max_flowrings = sc->max_submissionrings -
		    BRCMF_NROF_H2D_COMMON_MSGRINGS;
		sc->max_completionrings = BRCMF_NROF_D2H_COMMON_MSGRINGS;
	}

	printf("brcmfmac: ringmem=0x%x\n", sc->ringmem_addr);
	printf("brcmfmac: h2d_w_idx=0x%x h2d_r_idx=0x%x\n",
	    sc->h2d_w_idx_addr, sc->h2d_r_idx_addr);
	printf("brcmfmac: d2h_w_idx=0x%x d2h_r_idx=0x%x\n",
	    sc->d2h_w_idx_addr, sc->d2h_r_idx_addr);
	printf("brcmfmac: max_flowrings=%u max_submission=%u max_completion=%u\n",
	    sc->max_flowrings, sc->max_submissionrings, sc->max_completionrings);

	return (0);
}

/*
 * Allocate DMA index buffer when DMA_INDEX flag is set.
 */
static int
brcmf_pcie_alloc_idx_buf(struct brcmf_softc *sc)
{
	uint32_t sz, addr;
	uint64_t dma64;
	int error;

	if ((sc->shared.flags & BRCMF_PCIE_SHARED_DMA_INDEX) == 0)
		return (0);

	sz = sc->shared.dma_idx_sz *
	    (sc->max_submissionrings + sc->max_completionrings) * 2;
	sc->idx_buf_sz = sz;

	error = brcmf_alloc_dma_buf(sc->dev, sz, &sc->idx_dma_tag,
	    &sc->idx_dma_map, &sc->idx_buf, &sc->idx_buf_dma);
	if (error != 0) {
		device_printf(sc->dev, "failed to allocate DMA index buffer\n");
		return (error);
	}

	printf("brcmfmac: allocated DMA index buffer %u bytes at 0x%lx\n",
	    sz, (unsigned long)sc->idx_buf_dma);

	/*
	 * Layout: h2d_w[max_sub] | h2d_r[max_sub] | d2h_w[max_comp] | d2h_r[max_comp]
	 * Write host addresses back to TCM ring info structure.
	 */
	addr = sc->shared.ring_info_addr;
	dma64 = sc->idx_buf_dma;

	/* h2d_w_idx_hostaddr */
	brcmf_tcm_write64(sc, addr + BRCMF_RING_H2D_W_HOSTADDR_OFFSET, dma64);
	dma64 += sc->max_submissionrings * sc->shared.dma_idx_sz;

	/* h2d_r_idx_hostaddr */
	brcmf_tcm_write64(sc, addr + BRCMF_RING_H2D_R_HOSTADDR_OFFSET, dma64);
	dma64 += sc->max_submissionrings * sc->shared.dma_idx_sz;

	/* d2h_w_idx_hostaddr */
	brcmf_tcm_write64(sc, addr + BRCMF_RING_D2H_W_HOSTADDR_OFFSET, dma64);
	dma64 += sc->max_completionrings * sc->shared.dma_idx_sz;

	/* d2h_r_idx_hostaddr */
	brcmf_tcm_write64(sc, addr + BRCMF_RING_D2H_R_HOSTADDR_OFFSET, dma64);

	return (0);
}

/*
 * Allocate scratch and ring update DMA buffers, write addresses to TCM.
 */
static int
brcmf_pcie_alloc_scratch_buffers(struct brcmf_softc *sc)
{
	uint32_t addr;
	int error;

	/* Scratch buffer */
	error = brcmf_alloc_dma_buf(sc->dev, BRCMF_DMA_D2H_SCRATCH_BUF_LEN,
	    &sc->scratch_dma_tag, &sc->scratch_dma_map,
	    &sc->scratch_buf, &sc->scratch_dma);
	if (error != 0) {
		device_printf(sc->dev, "failed to allocate scratch buffer\n");
		return (error);
	}

	addr = sc->shared.tcm_base_address;
	brcmf_tcm_write32(sc, addr + BRCMF_SHARED_DMA_SCRATCH_LEN_OFFSET,
	    BRCMF_DMA_D2H_SCRATCH_BUF_LEN);
	brcmf_tcm_write64(sc, addr + BRCMF_SHARED_DMA_SCRATCH_ADDR_OFFSET,
	    sc->scratch_dma);

	printf("brcmfmac: scratch buffer at 0x%lx\n",
	    (unsigned long)sc->scratch_dma);

	/* Ring update buffer */
	error = brcmf_alloc_dma_buf(sc->dev, BRCMF_DMA_D2H_RINGUPD_BUF_LEN,
	    &sc->ringupd_dma_tag, &sc->ringupd_dma_map,
	    &sc->ringupd_buf, &sc->ringupd_dma);
	if (error != 0) {
		device_printf(sc->dev, "failed to allocate ringupd buffer\n");
		return (error);
	}

	brcmf_tcm_write32(sc, addr + BRCMF_SHARED_DMA_RINGUPD_LEN_OFFSET,
	    BRCMF_DMA_D2H_RINGUPD_BUF_LEN);
	brcmf_tcm_write64(sc, addr + BRCMF_SHARED_DMA_RINGUPD_ADDR_OFFSET,
	    sc->ringupd_dma);

	printf("brcmfmac: ringupd buffer at 0x%lx\n",
	    (unsigned long)sc->ringupd_dma);

	return (0);
}

/*
 * Allocate common rings (control submit, rxpost, control complete, tx complete, rx complete).
 */
static int
brcmf_pcie_alloc_common_rings(struct brcmf_softc *sc)
{
	static const struct {
		uint16_t depth;
		uint16_t item_len;
	} ring_info[BRCMF_NROF_COMMON_MSGRINGS] = {
		[BRCMF_H2D_MSGRING_CONTROL_SUBMIT] = {
		    BRCMF_H2D_MSGRING_CONTROL_SUBMIT_MAX_ITEM,
		    BRCMF_H2D_MSGRING_CONTROL_SUBMIT_ITEMSIZE },
		[BRCMF_H2D_MSGRING_RXPOST_SUBMIT] = {
		    BRCMF_H2D_MSGRING_RXPOST_SUBMIT_MAX_ITEM,
		    BRCMF_H2D_MSGRING_RXPOST_SUBMIT_ITEMSIZE },
		[BRCMF_D2H_MSGRING_CONTROL_COMPLETE] = {
		    BRCMF_D2H_MSGRING_CONTROL_COMPLETE_MAX_ITEM,
		    BRCMF_D2H_MSGRING_CONTROL_COMPLETE_ITEMSIZE },
		[BRCMF_D2H_MSGRING_TX_COMPLETE] = {
		    BRCMF_D2H_MSGRING_TX_COMPLETE_MAX_ITEM, 0 },
		[BRCMF_D2H_MSGRING_RX_COMPLETE] = {
		    BRCMF_D2H_MSGRING_RX_COMPLETE_MAX_ITEM, 0 },
	};
	uint16_t tx_itemsz, rx_itemsz;
	int i;

	/* Select item sizes based on shared version */
	if (sc->shared.version >= 7) {
		tx_itemsz = BRCMF_D2H_MSGRING_TX_COMPLETE_ITEMSIZE;
		rx_itemsz = BRCMF_D2H_MSGRING_RX_COMPLETE_ITEMSIZE;
	} else {
		tx_itemsz = BRCMF_D2H_MSGRING_TX_COMPLETE_ITEMSIZE_PRE_V7;
		rx_itemsz = BRCMF_D2H_MSGRING_RX_COMPLETE_ITEMSIZE_PRE_V7;
	}

	for (i = 0; i < BRCMF_NROF_COMMON_MSGRINGS; i++) {
		uint16_t depth, item_len;

		depth = ring_info[i].depth;
		item_len = ring_info[i].item_len;

		if (i == BRCMF_D2H_MSGRING_TX_COMPLETE)
			item_len = tx_itemsz;
		else if (i == BRCMF_D2H_MSGRING_RX_COMPLETE)
			item_len = rx_itemsz;

		sc->commonrings[i] = brcmf_ring_alloc(sc, i, depth, item_len,
		    sc->ringmem_addr);
		if (sc->commonrings[i] == NULL) {
			device_printf(sc->dev,
			    "failed to allocate common ring %d\n", i);
			return (ENOMEM);
		}

		/* Set up index addresses */
		if (i < BRCMF_NROF_H2D_COMMON_MSGRINGS) {
			/* H2D ring */
			sc->commonrings[i]->w_idx_addr = sc->h2d_w_idx_addr +
			    i * sizeof(uint32_t);
			sc->commonrings[i]->r_idx_addr = sc->h2d_r_idx_addr +
			    i * sizeof(uint32_t);
		} else {
			/* D2H ring */
			int d2h_idx = i - BRCMF_NROF_H2D_COMMON_MSGRINGS;
			sc->commonrings[i]->w_idx_addr = sc->d2h_w_idx_addr +
			    d2h_idx * sizeof(uint32_t);
			sc->commonrings[i]->r_idx_addr = sc->d2h_r_idx_addr +
			    d2h_idx * sizeof(uint32_t);
		}

		printf("brcmfmac: ring[%d]: depth=%u itemsz=%u dma=0x%lx w_idx=0x%x r_idx=0x%x\n",
		    i, depth, item_len,
		    (unsigned long)sc->commonrings[i]->dma_handle,
		    sc->commonrings[i]->w_idx_addr,
		    sc->commonrings[i]->r_idx_addr);
	}

	return (0);
}

/*
 * Set up DMA rings after firmware boots.
 */
static int
brcmf_pcie_setup_rings(struct brcmf_softc *sc)
{
	int error;

	error = brcmf_pcie_init_ringinfo(sc);
	if (error != 0)
		return (error);

	error = brcmf_pcie_alloc_idx_buf(sc);
	if (error != 0)
		return (error);

	error = brcmf_pcie_alloc_scratch_buffers(sc);
	if (error != 0)
		return (error);

	error = brcmf_pcie_alloc_common_rings(sc);
	if (error != 0)
		return (error);

	return (0);
}

/*
 * Free all DMA ring resources.
 */
static void
brcmf_pcie_free_rings(struct brcmf_softc *sc)
{
	int i;

	for (i = 0; i < BRCMF_NROF_COMMON_MSGRINGS; i++) {
		if (sc->commonrings[i] != NULL) {
			brcmf_ring_free(sc->commonrings[i]);
			sc->commonrings[i] = NULL;
		}
	}

	brcmf_free_dma_buf(sc->scratch_dma_tag, sc->scratch_dma_map,
	    sc->scratch_buf);
	sc->scratch_dma_tag = NULL;
	sc->scratch_buf = NULL;

	brcmf_free_dma_buf(sc->ringupd_dma_tag, sc->ringupd_dma_map,
	    sc->ringupd_buf);
	sc->ringupd_dma_tag = NULL;
	sc->ringupd_buf = NULL;

	brcmf_free_dma_buf(sc->idx_dma_tag, sc->idx_dma_map, sc->idx_buf);
	sc->idx_dma_tag = NULL;
	sc->idx_buf = NULL;
}

/*
 * Download firmware to device
 */
static int
brcmf_download_fw(struct brcmf_softc *sc, const struct firmware *fw)
{
	uint32_t sharedaddr, sharedaddr_written, resetintr;
	int error, i;

	if (fw->datasize < 4) {
		device_printf(sc->dev, "firmware too small\n");
		return (EINVAL);
	}

	if (fw->datasize > sc->ram_size) {
		device_printf(sc->dev, "firmware too large (%zu > %u)\n",
		    fw->datasize, sc->ram_size);
		return (EINVAL);
	}

	printf("brcmfmac: firmware size=%zu\n", fw->datasize);

	error = brcmf_enumerate_cores(sc);
	if (error != 0)
		return (error);

	/* Check if firmware overrides RAM size */
	brcmf_pcie_adjust_ramsize(sc, fw->data, fw->datasize);

	/* Reset chip before firmware download */
	printf("brcmfmac: resetting device\n");
	brcmf_pcie_reset_device(sc);

	/* Touch BAR2 config register (Linux brcmf_pcie_attach) */
	brcmf_pcie_select_core(sc, &sc->pciecore);
	brcmf_reg_write(sc, BRCMF_PCIE_PCIE2REG_CONFIGADDR, 0x4e0);
	{
		uint32_t barconfig;
		barconfig = brcmf_reg_read(sc, BRCMF_PCIE_PCIE2REG_CONFIGDATA);
		brcmf_reg_write(sc, BRCMF_PCIE_PCIE2REG_CONFIGDATA, barconfig);
	}

	error = brcmf_enter_download(sc);
	if (error != 0)
		return (error);

	/* Copy firmware to TCM */
	printf("brcmfmac: copying %zu bytes to TCM offset 0x%x\n", fw->datasize,
	    sc->ram_base);
	resetintr = *(const uint32_t *)fw->data;
	brcmf_tcm_copy(sc, sc->ram_base, fw->data, fw->datasize);

	/* Clear shared RAM address */
	brcmf_ram_write32(sc, sc->ram_size - 4, 0);

	/* Copy NVRAM to end of RAM */
	if (sc->nvram != NULL && sc->nvram_len > 0) {
		uint32_t nvram_addr = sc->ram_base + sc->ram_size -
		    sc->nvram_len;
		printf("brcmfmac: copying NVRAM (%u bytes) to offset 0x%x\n",
		    sc->nvram_len, nvram_addr);
		brcmf_tcm_copy(sc, nvram_addr, sc->nvram, sc->nvram_len);
	}

	/* Read back what we wrote so we can detect changes */
	sharedaddr_written = brcmf_ram_read32(sc, sc->ram_size - 4);

	/* Start ARM */
	brcmf_exit_download(sc, resetintr);

	/* Poll for firmware ready */
	printf("brcmfmac: waiting for firmware to boot...\n");
	sharedaddr = sharedaddr_written;
	for (i = 0; i < BRCMF_FW_READY_TIMEOUT_MS / BRCMF_FW_READY_POLL_MS;
	    i++) {
		pause_sbt("brcmfw", mstosbt(BRCMF_FW_READY_POLL_MS), 0, 0);
		sharedaddr = brcmf_ram_read32(sc, sc->ram_size - 4);
		if (i < 5 || (i % 10 == 0))
			printf("brcmfmac: poll[%d]: sharedaddr=0x%x\n", i,
			    sharedaddr);
		if (sharedaddr != sharedaddr_written)
			break;
	}

	if (sharedaddr == sharedaddr_written) {
		device_printf(sc->dev,
		    "firmware boot timeout, sharedaddr=0x%x\n", sharedaddr);
		return (ETIMEDOUT);
	}

	if (sharedaddr < sc->ram_base ||
	    sharedaddr >= sc->ram_base + sc->ram_size) {
		device_printf(sc->dev,
		    "invalid shared RAM address 0x%x\n", sharedaddr);
		return (EIO);
	}

	printf("brcmfmac: firmware booted, sharedaddr=0x%x\n", sharedaddr);

	/* Parse shared RAM info */
	error = brcmf_pcie_init_shared(sc, sharedaddr);
	if (error != 0)
		return (error);

	/* Set up DMA rings */
	error = brcmf_pcie_setup_rings(sc);
	if (error != 0)
		return (error);

	/* Signal host ready */
	brcmf_pcie_hostready(sc);

	printf("brcmfmac: DMA rings initialized\n");

	/* TODO: interrupt setup, msgbuf init */
	return (0);
}

int
brcmf_pcie_attach(device_t dev)
{
	struct brcmf_softc *sc;
	struct brcmf_chipinfo ci;
	const struct firmware *fw = NULL;
	const struct firmware *nvram = NULL;
	const char *fwname;
	uint32_t regdata;
	int error;

	sc = device_get_softc(dev);
	sc->dev = dev;

	pci_enable_busmaster(dev);

	/* Map BAR0 (registers) */
	sc->reg_rid = PCIR_BAR(0);
	sc->reg_res = bus_alloc_resource_any(dev, SYS_RES_MEMORY, &sc->reg_rid,
	    RF_ACTIVE);
	if (sc->reg_res == NULL) {
		device_printf(dev, "failed to map BAR0\n");
		return (ENXIO);
	}
	sc->reg_bst = rman_get_bustag(sc->reg_res);
	sc->reg_bsh = rman_get_bushandle(sc->reg_res);

	/* Map BAR2 (TCM) */
	sc->tcm_rid = PCIR_BAR(2);
	sc->tcm_res = bus_alloc_resource_any(dev, SYS_RES_MEMORY, &sc->tcm_rid,
	    RF_ACTIVE);
	if (sc->tcm_res == NULL) {
		device_printf(dev, "failed to map BAR2 (TCM)\n");
		error = ENXIO;
		goto fail;
	}
	sc->tcm_bst = rman_get_bustag(sc->tcm_res);
	sc->tcm_bsh = rman_get_bushandle(sc->tcm_res);

	/* Set BAR0 window to ChipCommon */
	pci_write_config(dev, BRCMF_PCIE_BAR0_WINDOW, SI_ENUM_BASE, 4);

	regdata = brcmf_reg_read(sc, 0);
	if (regdata == 0xffffffff) {
		device_printf(dev, "chip ID read failed\n");
		error = EIO;
		goto fail;
	}

	ci = brcmf_parse_chipid(regdata);
	sc->chip = ci.chip;
	sc->chiprev = ci.chiprev;

	device_printf(dev, "chip=%04x rev=%u socitype=%s\n", sc->chip,
	    sc->chiprev, brcmf_socitype_name(ci.socitype));

	if (!brcmf_chip_supported(sc->chip)) {
		device_printf(dev, "unsupported chip\n");
		error = ENODEV;
		goto fail;
	}

	sc->ram_base = BCM4350_RAM_BASE;
	sc->ram_size = BCM4350_RAM_SIZE;

	printf("brcmfmac: ram_base=0x%x ram_size=0x%x (%uKB)\n", sc->ram_base,
	    sc->ram_size, sc->ram_size / 1024);

	/* Revs 0-7 use C2 firmware, rev 8+ use base firmware */
	fwname = (sc->chiprev <= 7) ? BRCMF_FW_NAME_C2 : BRCMF_FW_NAME;

	fw = firmware_get(fwname);
	if (fw == NULL) {
		device_printf(dev, "failed to load firmware %s\n", fwname);
		error = ENOENT;
		goto fail;
	}
	printf("brcmfmac: loaded firmware %s (%zu bytes)\n", fwname,
	    fw->datasize);

	/* Try to load NVRAM (optional) */
	{
		const char *nvname;
		nvname = (sc->chiprev <= 7) ? BRCMF_NVRAM_NAME_C2 :
		    BRCMF_NVRAM_NAME;
		nvram = firmware_get(nvname);
		if (nvram != NULL) {
			printf("brcmfmac: loaded NVRAM %s (%zu bytes)\n",
			    nvname, nvram->datasize);
			sc->nvram = brcmf_nvram_parse(nvram->data,
			    nvram->datasize, &sc->nvram_len);
			if (sc->nvram != NULL)
				printf("brcmfmac: parsed NVRAM: %u bytes\n",
				    sc->nvram_len);
			firmware_put(nvram, FIRMWARE_UNLOAD);
		} else {
			printf("brcmfmac: NVRAM %s not found, "
			    "continuing without\n", nvname);
		}
	}

	error = brcmf_download_fw(sc, fw);
	firmware_put(fw, FIRMWARE_UNLOAD);

	if (error != 0)
		goto fail;

	return (0);

fail:
	brcmf_pcie_detach(dev);
	return (error);
}

int
brcmf_pcie_detach(device_t dev)
{
	struct brcmf_softc *sc;

	sc = device_get_softc(dev);

	brcmf_pcie_free_rings(sc);

	if (sc->nvram != NULL)
		free(sc->nvram, M_BRCMFMAC);

	if (sc->tcm_res != NULL)
		bus_release_resource(dev, SYS_RES_MEMORY, sc->tcm_rid,
		    sc->tcm_res);

	if (sc->reg_res != NULL)
		bus_release_resource(dev, SYS_RES_MEMORY, sc->reg_rid,
		    sc->reg_res);

	return (0);
}
