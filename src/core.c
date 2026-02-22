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

/* Core IDs (12-bit DMP part numbers from EROM) */
#define BCMA_CORE_CHIPCOMMON 0x800
#define BCMA_CORE_SOCRAM     0x80e
#define BCMA_CORE_80211	     0x812
#define BCMA_CORE_ARM_CR4    0x83e
#define BCMA_CORE_PCIE2	     0x83c

/* ChipCommon register offsets */
#define CC_WATCHDOG 0x80

/* PCIe register offsets */
#define BRCMF_PCIE_PCIE2REG_MAILBOXINT	   0x48
#define BRCMF_PCIE_PCIE2REG_CONFIGADDR	   0x120
#define BRCMF_PCIE_PCIE2REG_CONFIGDATA	   0x124
#define BRCMF_PCIE_REG_LINK_STATUS_CTRL	   0xBC
#define BRCMF_PCIE_LINK_STATUS_CTRL_ASPM_ENAB 3

/*
 * EROM read callback for Zig core enumeration.
 */
static uint32_t
brcmf_erom_read(void *ctx, uint32_t offset)
{
	return brcmf_bp_read32(ctx, offset);
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
	pause_sbt("brcmrst", mstosbt(100), 0, 0);

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
 */
void
brcmf_chip_exit_download(struct brcmf_softc *sc, uint32_t resetintr)
{
	printf("brcmfmac: writing reset vector 0x%x to TCM[0]\n", resetintr);
	brcmf_tcm_write32(sc, 0, resetintr);

	if (sc->armcore.wrapbase == 0) {
		device_printf(sc->dev,
		    "no wrapper address, cannot release ARM\n");
		return;
	}

	brcmf_core_reset(sc, &sc->armcore, BCMA_IOCTL_CPUHALT, 0, 0);
	printf("brcmfmac: ARM released\n");
}
