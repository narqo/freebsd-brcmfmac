// SPDX-License-Identifier: ISC
/*
 * Copyright (c) 2010-2022 Broadcom Corporation
 * Copyright (c) brcmfmac-freebsd contributors
 *
 * Based on the Linux brcmfmac driver.
 */

/* Chip core management: enumeration, reset, firmware download state */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bus.h>
#include <sys/kernel.h>

#include <dev/pci/pcivar.h>

#include "brcmfmac.h"

/* SI_ENUM_BASE - chip enumeration base address */
#define SI_ENUM_BASE 0x18000000

/* BAR0 window register in PCI config space */
#define BRCMF_PCIE_BAR0_WINDOW 0x80

/* BCMA core control/status registers (offset from wrapper base) */
#define BCMA_IOCTL     0x0408
#define BCMA_RESET_CTL 0x0800

/* BCMA_IOCTL bits */
#define BCMA_IOCTL_CLK	   0x0001
#define BCMA_IOCTL_FGC	   0x0002
#define BCMA_IOCTL_CPUHALT 0x0020

/* D11 core IOCTL bits */
#define D11_BCMA_IOCTL_PHYCLOCKEN 0x0004
#define D11_BCMA_IOCTL_PHYRESET	  0x0008

/* BCMA_RESET_CTL bits */
#define BCMA_RESET_CTL_RESET 0x0001

/* Chip ID fields */
#define CID_ID_MASK    0x0000ffff
#define CID_REV_MASK   0x000f0000
#define CID_REV_SHIFT  16
#define CID_TYPE_MASK  0xf0000000
#define CID_TYPE_SHIFT 28

#define SOCI_SB 0
#define SOCI_AI 1

#define BRCM_CC_4350_CHIP_ID 0x4350

/* Core IDs (12-bit DMP part numbers from EROM) */
#define BCMA_CORE_SOCRAM  0x80e
#define BCMA_CORE_80211   0x812
#define BCMA_CORE_ARM_CR4 0x83e
#define BCMA_CORE_PCIE2   0x83c

/* ChipCommon register offsets */
#define CC_WATCHDOG 0x80

/* PCIe register offsets */
#define BRCMF_PCIE_PCIE2REG_MAILBOXINT	   0x48
#define BRCMF_PCIE_PCIE2REG_CONFIGADDR	   0x120
#define BRCMF_PCIE_PCIE2REG_CONFIGDATA	   0x124
#define BRCMF_PCIE_REG_LINK_STATUS_CTRL	   0xBC
#define BRCMF_PCIE_LINK_STATUS_CTRL_ASPM_ENAB 3

/* DMP (Dotted Map Protocol) EROM descriptor format */
#define DMP_DESC_TYPE_MSK      0x0000000f
#define DMP_DESC_EMPTY         0x00000000
#define DMP_DESC_VALID         0x00000001
#define DMP_DESC_COMPONENT     0x00000001
#define DMP_DESC_MASTER_PORT   0x00000003
#define DMP_DESC_ADDRESS       0x00000005
#define DMP_DESC_ADDRSIZE_GT32 0x00000008
#define DMP_DESC_EOT           0x0000000f

#define DMP_COMP_PARTNUM   0x000fff00
#define DMP_COMP_PARTNUM_S 8

#define DMP_COMP_REVISION   0xff000000
#define DMP_COMP_REVISION_S 24
#define DMP_COMP_NUM_MWRAP  0x0007c000
#define DMP_COMP_NUM_MWRAP_S 14
#define DMP_COMP_NUM_SWRAP  0x00f80000
#define DMP_COMP_NUM_SWRAP_S 19

#define DMP_SLAVE_ADDR_BASE    0xfffff000
#define DMP_SLAVE_TYPE         0x000000c0
#define DMP_SLAVE_TYPE_S       6
#define DMP_SLAVE_TYPE_SLAVE   0
#define DMP_SLAVE_TYPE_BRIDGE  1
#define DMP_SLAVE_TYPE_SWRAP   2
#define DMP_SLAVE_TYPE_MWRAP   3
#define DMP_SLAVE_SIZE_TYPE    0x00000030
#define DMP_SLAVE_SIZE_TYPE_S  4
#define DMP_SLAVE_SIZE_4K      0
#define DMP_SLAVE_SIZE_8K      1
#define DMP_SLAVE_SIZE_DESC    3

struct brcmf_erom_scanner {
	uint32_t erom_addr;
	brcmf_erom_read_fn read_fn;
	void *ctx;
};

static uint32_t
brcmf_erom_get_desc(struct brcmf_erom_scanner *s)
{
	uint32_t val;

	val = s->read_fn(s->ctx, s->erom_addr);
	s->erom_addr += 4;
	return (val);
}

static void
brcmf_erom_backup(struct brcmf_erom_scanner *s)
{
	s->erom_addr -= 4;
}

static void
brcmf_erom_get_regaddr(struct brcmf_erom_scanner *s, uint32_t *base,
    uint32_t *wrap)
{
	uint32_t regbase, wrapbase, wraptype, val, desc_type;
	uint32_t stype, sztype;
	int safety, inner_safety;

	regbase = 0;
	wrapbase = 0;

	val = brcmf_erom_get_desc(s);
	desc_type = val & DMP_DESC_TYPE_MSK;

	if (desc_type == DMP_DESC_MASTER_PORT)
		wraptype = DMP_SLAVE_TYPE_MWRAP;
	else if ((desc_type & ~DMP_DESC_ADDRSIZE_GT32) == DMP_DESC_ADDRESS) {
		brcmf_erom_backup(s);
		wraptype = DMP_SLAVE_TYPE_SWRAP;
	} else {
		brcmf_erom_backup(s);
		*base = 0;
		*wrap = 0;
		return;
	}

	for (safety = 0; safety < 256; safety++) {
		for (inner_safety = 0; inner_safety < 256; inner_safety++) {
			val = brcmf_erom_get_desc(s);
			desc_type = val & DMP_DESC_TYPE_MSK;
			if (desc_type == DMP_DESC_EOT) {
				brcmf_erom_backup(s);
				*base = regbase;
				*wrap = wrapbase;
				return;
			}
			if ((desc_type & ~DMP_DESC_ADDRSIZE_GT32) == DMP_DESC_ADDRESS)
				break;
			if (desc_type == DMP_DESC_COMPONENT) {
				brcmf_erom_backup(s);
				*base = regbase;
				*wrap = wrapbase;
				return;
			}
		}

		if ((val & DMP_DESC_ADDRSIZE_GT32) != 0)
			(void)brcmf_erom_get_desc(s);

		sztype = (val & DMP_SLAVE_SIZE_TYPE) >> DMP_SLAVE_SIZE_TYPE_S;
		if (sztype == DMP_SLAVE_SIZE_DESC) {
			uint32_t szdesc;

			szdesc = brcmf_erom_get_desc(s);
			if ((szdesc & DMP_DESC_ADDRSIZE_GT32) != 0)
				(void)brcmf_erom_get_desc(s);
		}

		if (sztype != DMP_SLAVE_SIZE_4K && sztype != DMP_SLAVE_SIZE_8K)
			continue;

		stype = (val & DMP_SLAVE_TYPE) >> DMP_SLAVE_TYPE_S;
		if (regbase == 0 && stype == DMP_SLAVE_TYPE_SLAVE)
			regbase = val & DMP_SLAVE_ADDR_BASE;
		if (wrapbase == 0 && stype == wraptype)
			wrapbase = val & DMP_SLAVE_ADDR_BASE;

		if (regbase != 0 && wrapbase != 0)
			break;
	}

	*base = regbase;
	*wrap = wrapbase;
}

/*
 * EROM read callback for core enumeration.
 */
static uint32_t
brcmf_erom_read(void *ctx, uint32_t offset)
{
	return brcmf_bp_read32(ctx, offset);
}

struct brcmf_coreinfo
brcmf_find_core(uint32_t erom_base, brcmf_erom_read_fn read_fn, void *ctx,
    uint32_t target_coreid)
{
	struct brcmf_erom_scanner s;
	struct brcmf_coreinfo core;
	uint32_t desc_type, val, id, rev, nmw, nsw, base, wrap;

	s.erom_addr = erom_base;
	s.read_fn = read_fn;
	s.ctx = ctx;

	core.id = 0;
	core.rev = 0;
	core.base = 0;
	core.wrapbase = 0;

	desc_type = 0;
	while (desc_type != DMP_DESC_EOT) {
		val = brcmf_erom_get_desc(&s);
		if ((val & DMP_DESC_VALID) == 0)
			continue;

		desc_type = val & DMP_DESC_TYPE_MSK;
		if (desc_type == DMP_DESC_EMPTY || desc_type == DMP_DESC_EOT)
			continue;
		if (desc_type != DMP_DESC_COMPONENT)
			continue;

		id = (val & DMP_COMP_PARTNUM) >> DMP_COMP_PARTNUM_S;

		val = brcmf_erom_get_desc(&s);
		rev = (val & DMP_COMP_REVISION) >> DMP_COMP_REVISION_S;
		nmw = (val & DMP_COMP_NUM_MWRAP) >> DMP_COMP_NUM_MWRAP_S;
		nsw = (val & DMP_COMP_NUM_SWRAP) >> DMP_COMP_NUM_SWRAP_S;
		if (nmw + nsw == 0)
			continue;

		brcmf_erom_get_regaddr(&s, &base, &wrap);
		if (id == target_coreid) {
			core.id = id;
			core.rev = rev;
			core.base = base;
			core.wrapbase = wrap;
			return (core);
		}
	}

	return (core);
}

struct brcmf_chipinfo
brcmf_parse_chipid(uint32_t regdata)
{
	struct brcmf_chipinfo ci;

	ci.chip = regdata & CID_ID_MASK;
	ci.chiprev = (regdata & CID_REV_MASK) >> CID_REV_SHIFT;
	ci.socitype = (regdata & CID_TYPE_MASK) >> CID_TYPE_SHIFT;
	return (ci);
}

bool
brcmf_chip_supported(uint32_t chip)
{
	return (chip == BRCM_CC_4350_CHIP_ID);
}

const char *
brcmf_socitype_name(uint32_t socitype)
{
	switch (socitype) {
	case SOCI_SB:
		return ("SB");
	case SOCI_AI:
		return ("AXI");
	default:
		return ("unknown");
	}
}

/*
 * Enumerate cores via EROM.
 */
int
brcmf_chip_enumerate_cores(struct brcmf_softc *sc)
{
	uint32_t erombase;

	/* Set window to ChipCommon and read EROM base */
	pci_write_config(sc->dev, BRCMF_PCIE_BAR0_WINDOW, SI_ENUM_BASE, 4);
	brcmf_reg_read(sc, 0);

	erombase = brcmf_reg_read(sc, 0xfc);
	BRCMF_DBG(sc, "EROM base=0x%x\n", erombase);

	/* Find ARM CR4 core */
	sc->armcore = brcmf_find_core(erombase, brcmf_erom_read, sc,
	    BCMA_CORE_ARM_CR4);
	if (sc->armcore.id == 0) {
		device_printf(sc->dev, "ARM CR4 core not found\n");
		return (ENODEV);
	}
	BRCMF_DBG(sc, "ARM CR4: id=0x%x rev=%u base=0x%x wrap=0x%x\n",
	    sc->armcore.id, sc->armcore.rev, sc->armcore.base,
	    sc->armcore.wrapbase);

	/* Find SOCRAM/internal memory core (optional for CR4 chips) */
	sc->ramcore = brcmf_find_core(erombase, brcmf_erom_read, sc,
	    BCMA_CORE_SOCRAM);
	if (sc->ramcore.id != 0) {
		BRCMF_DBG(sc, "SOCRAM: id=0x%x rev=%u base=0x%x wrap=0x%x\n",
		    sc->ramcore.id, sc->ramcore.rev, sc->ramcore.base,
		    sc->ramcore.wrapbase);
	}

	/* Find D11 (802.11) core */
	sc->d11core = brcmf_find_core(erombase, brcmf_erom_read, sc,
	    BCMA_CORE_80211);
	if (sc->d11core.id != 0) {
		BRCMF_DBG(sc, "D11: id=0x%x rev=%u base=0x%x wrap=0x%x\n",
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
	BRCMF_DBG(sc, "PCIe2: id=0x%x rev=%u base=0x%x wrap=0x%x\n",
	    sc->pciecore.id, sc->pciecore.rev, sc->pciecore.base,
	    sc->pciecore.wrapbase);

	return (0);
}

/*
 * Check if core is in reset.
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
 *
 * A full reject handshake (spec 10-chip-specifics) would require
 * writing REJECT to the slave wrapper port and polling its status
 * register — registers not mapped in this driver. The simple
 * reset-without-reject works for CR4 cores during firmware download
 * because the ARM is halted and no transactions are in flight.
 */
static void
brcmf_core_disable(struct brcmf_softc *sc, struct brcmf_coreinfo *core,
    uint32_t prereset, uint32_t reset)
{
	uint32_t val;
	int i;

	if (brcmf_core_in_reset(sc, core))
		goto in_reset_configure;

	brcmf_bp_write32(sc, core->wrapbase + BCMA_IOCTL,
	    prereset | BCMA_IOCTL_FGC | BCMA_IOCTL_CLK);
	brcmf_bp_read32(sc, core->wrapbase + BCMA_IOCTL);

	brcmf_bp_write32(sc, core->wrapbase + BCMA_RESET_CTL,
	    BCMA_RESET_CTL_RESET);
	DELAY(20); /* reset crosses backplane clock domains */

	/* reset status bit updates asynchronously */
	for (i = 0; i < 300; i++) {
		val = brcmf_bp_read32(sc, core->wrapbase + BCMA_RESET_CTL);
		if (val == BCMA_RESET_CTL_RESET)
			break;
		DELAY(10);
	}

in_reset_configure:
	brcmf_bp_write32(sc, core->wrapbase + BCMA_IOCTL,
	    reset | BCMA_IOCTL_FGC | BCMA_IOCTL_CLK);
	brcmf_bp_read32(sc, core->wrapbase + BCMA_IOCTL);
}

/*
 * Reset a core (disable, then bring out of reset).
 */
static void
brcmf_core_reset(struct brcmf_softc *sc, struct brcmf_coreinfo *core,
    uint32_t prereset, uint32_t reset, uint32_t postreset)
{
	uint32_t val;
	int i;

	brcmf_core_disable(sc, core, prereset, reset);

	/* reset deassert may require multiple attempts */
	for (i = 0; i < 50; i++) {
		brcmf_bp_write32(sc, core->wrapbase + BCMA_RESET_CTL, 0);
		val = brcmf_bp_read32(sc, core->wrapbase + BCMA_RESET_CTL);
		if ((val & BCMA_RESET_CTL_RESET) == 0)
			break;
		DELAY(60);
	}

	if (val & BCMA_RESET_CTL_RESET) {
		device_printf(sc->dev, "core 0x%x reset timeout\n", core->id);
		return;
	}

	brcmf_bp_write32(sc, core->wrapbase + BCMA_IOCTL,
	    postreset | BCMA_IOCTL_CLK);
	brcmf_bp_read32(sc, core->wrapbase + BCMA_IOCTL);
}

/*
 * Watchdog reset: triggers ChipCommon watchdog to reset the whole chip.
 */
void
brcmf_chip_reset(struct brcmf_softc *sc)
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
	pause_sbt("brcmrst", mstosbt(100), 0, 0); /* watchdog fires in ~4 ticks */

	/* Restore ASPM */
	brcmf_pcie_select_core(sc, &sc->pciecore);
	pci_write_config(sc->dev, BRCMF_PCIE_REG_LINK_STATUS_CTRL, lsc, 4);

	/* Touch config registers for rev <= 13 */
	if (sc->pciecore.rev <= 13) {
		for (i = 0; i < (int)nitems(cfg_offset); i++) {
			brcmf_reg_write(sc, BRCMF_PCIE_PCIE2REG_CONFIGADDR,
			    cfg_offset[i]);
			val = brcmf_reg_read(sc, BRCMF_PCIE_PCIE2REG_CONFIGDATA);
			brcmf_reg_write(sc, BRCMF_PCIE_PCIE2REG_CONFIGDATA, val);
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
 * Enter firmware download state: halt ARM, disable D11.
 */
int
brcmf_chip_enter_download(struct brcmf_softc *sc)
{
	uint32_t val;

	if (sc->armcore.wrapbase == 0) {
		device_printf(sc->dev, "no wrapper address for ARM core\n");
		return (EINVAL);
	}

	BRCMF_DBG(sc, "halting ARM at wrapper 0x%x\n", sc->armcore.wrapbase);

	/* Read current IOCTL and preserve only CPUHALT bit */
	val = brcmf_bp_read32(sc, sc->armcore.wrapbase + BCMA_IOCTL);
	val &= BCMA_IOCTL_CPUHALT;

	/* Reset ARM with CPUHALT set throughout */
	brcmf_core_reset(sc, &sc->armcore, val, BCMA_IOCTL_CPUHALT,
	    BCMA_IOCTL_CPUHALT);

	/* Disable D11 core to let firmware enable it */
	if (sc->d11core.id != 0 && sc->d11core.wrapbase != 0) {
		BRCMF_DBG(sc, "disabling D11 core\n");
		brcmf_core_disable(sc, &sc->d11core,
		    D11_BCMA_IOCTL_PHYRESET | D11_BCMA_IOCTL_PHYCLOCKEN,
		    D11_BCMA_IOCTL_PHYCLOCKEN);
	}

	return (0);
}

/*
 * Exit firmware download state: write reset vector and start ARM.
 */
void
brcmf_chip_exit_download(struct brcmf_softc *sc, uint32_t resetintr)
{
	BRCMF_DBG(sc, "writing reset vector 0x%x to TCM[0]\n", resetintr);
	brcmf_tcm_write32(sc, 0, resetintr);

	if (sc->armcore.wrapbase == 0) {
		device_printf(sc->dev,
		    "no wrapper address, cannot release ARM\n");
		return;
	}

	brcmf_core_reset(sc, &sc->armcore, BCMA_IOCTL_CPUHALT, 0, 0);
	BRCMF_DBG(sc, "ARM released\n");
}
