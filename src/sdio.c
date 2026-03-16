// SPDX-License-Identifier: ISC
/*
 * Copyright (c) 2010-2022 Broadcom Corporation
 * Copyright (c) brcmfmac-freebsd contributors
 *
 * Based on the Linux brcmfmac driver.
 */

/* SDIO bus layer: backplane access, clock, core enumeration, firmware download */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bus.h>
#include <sys/firmware.h>
#include <sys/kernel.h>
#include <sys/malloc.h>

#include <dev/sdio/sdiob.h>
#include <dev/sdio/sdio_subr.h>

#include "sdio_if.h"

#include "brcmfmac.h"

/* SI_ENUM_BASE - chip enumeration base address */
#define SI_ENUM_BASE		0x18000000

/* SDIO Function 1 register addresses */
#define SBSDIO_FUNC1_SBADDRLOW	0x1000A
#define SBSDIO_FUNC1_SBADDRMID	0x1000B
#define SBSDIO_FUNC1_SBADDRHIGH	0x1000C
#define SBSDIO_FUNC1_CHIPCLKCSR	0x1000E

/* CHIPCLKCSR bits */
#define SBSDIO_FORCE_ALP		0x01
#define SBSDIO_FORCE_HT			0x02
#define SBSDIO_ALP_AVAIL_REQ		0x08
#define SBSDIO_HT_AVAIL_REQ		0x10
#define SBSDIO_FORCE_HW_CLKREQ_OFF	0x20
#define SBSDIO_ALP_AVAIL		0x40
#define SBSDIO_HT_AVAIL		0x80

/* Backplane window mask: bits 31:15 select the 32KB window */
#define SBSDIO_SB_OFT_ADDR_MASK		0x00007FFF
#define SBSDIO_SB_ACCESS_2_4B_FLAG	0x08000

/* F1 block size */
#define SDIO_F1_BLOCKSIZE	64

/* F2 block size (BCM43455 default) */
#define SDIO_F2_BLOCKSIZE	512

/* CCCR registers for F2 ready */
#define SDIO_CCCR_IORx		0x02
#define SDIO_CCCR_IOEx		0x04

/* Firmware names */
#define BRCMF_SDIO_FW_NAME	"brcmfmac43455-sdio.bin"
#define BRCMF_SDIO_NVRAM_NAME	"brcmfmac43455-sdio.txt"

/* Firmware ready timeout */
#define BRCMF_SDIO_F2_READY_TIMEOUT_MS	5000
#define BRCMF_SDIO_F2_READY_POLL_MS	10

/* Chip ID fields */
#define CID_ID_MASK	0x0000FFFF

/* BCMA wrapper register offsets */
#define BCMA_IOCTL		0x0408
#define BCMA_RESET_CTL		0x0800
#define BCMA_IOCTL_CLK		0x0001
#define BCMA_IOCTL_FGC		0x0002
#define BCMA_IOCTL_CPUHALT	0x0020
#define BCMA_RESET_CTL_RESET	0x0001

/* ChipCommon register offsets */
#define CC_EROMBASE		0xFC

/* SDIO device core (core ID 0x829) register offsets */
#define SD_REG_INTSTATUS	0x020
#define SD_REG_HOSTINTMASK	0x024
#define SD_REG_TOSBMAILBOXDATA	0x048

/* Protocol version for tosbmailboxdata */
#define SDPCM_PROT_VERSION	4
#define SMB_DATA_VERSION_SHIFT	16

/* BCMA core IDs */
#define BCMA_CORE_SDIO_DEV	0x829

/* F2 watermark and device control registers */
#define SBSDIO_WATERMARK		0x10008
#define SBSDIO_DEVICE_CTL		0x10009
#define SBSDIO_FUNC1_MESBUSYCTRL	0x1001D
#define SBSDIO_DEVCTL_F2WM_ENAB		0x10
#define SBSDIO_MESBUSYCTRL_ENAB		0x80

/* BCM43455-specific watermark values */
#define CY_43455_F2_WATERMARK		0x60
#define CY_43455_MES_WATERMARK		0x50

/* Host interrupt mask bits */
#define I_HMB_SW_MASK	0x000000F0
#define I_HMB_FC_CHANGE	0x00000020
#define I_HMB_FRAME_IND	0x00000040
#define I_HMB_HOST_INT	0x00000080

/*
 * Set backplane address window.
 */
void
brcmf_sdio_set_window(struct brcmf_softc *sc, uint32_t addr)
{
	uint32_t window = addr & ~SBSDIO_SB_OFT_ADDR_MASK;
	struct sdio_func *f1 = sc->sdio_func1;
	int err;

	if (window == sc->sdio_window)
		return;

	sdio_write_1(f1, SBSDIO_FUNC1_SBADDRLOW,
	    (window >> 8) & 0x80, &err);
	sdio_write_1(f1, SBSDIO_FUNC1_SBADDRMID,
	    (window >> 16) & 0xFF, &err);
	sdio_write_1(f1, SBSDIO_FUNC1_SBADDRHIGH,
	    (window >> 24) & 0xFF, &err);

	sc->sdio_window = window;
}

/*
 * Read 32-bit value from backplane address via F1.
 */
uint32_t
brcmf_sdio_bp_read32(struct brcmf_softc *sc, uint32_t addr)
{
	uint32_t offset;
	int err;

	brcmf_sdio_set_window(sc, addr);
	offset = (addr & SBSDIO_SB_OFT_ADDR_MASK) | SBSDIO_SB_ACCESS_2_4B_FLAG;
	return sdio_read_4(sc->sdio_func1, offset, &err);
}

/*
 * Write 32-bit value to backplane address via F1.
 */
void
brcmf_sdio_bp_write32(struct brcmf_softc *sc, uint32_t addr, uint32_t val)
{
	uint32_t offset;
	int err;

	brcmf_sdio_set_window(sc, addr);
	offset = (addr & SBSDIO_SB_OFT_ADDR_MASK) | SBSDIO_SB_ACCESS_2_4B_FLAG;
	sdio_write_4(sc->sdio_func1, offset, val, &err);
}

/*
 * Read callback for EROM parser.
 */
static uint32_t
brcmf_sdio_erom_read(void *ctx, uint32_t offset)
{
	return brcmf_sdio_bp_read32(ctx, offset);
}

/*
 * Request ALP clock (early init) or HT clock (normal operation).
 */
static int
brcmf_sdio_clk_enable(struct brcmf_softc *sc, int alp_only)
{
	struct sdio_func *f1 = sc->sdio_func1;
	uint8_t clkval, req, avail;
	int err, i;

	if (alp_only) {
		req = SBSDIO_ALP_AVAIL_REQ;
		avail = SBSDIO_ALP_AVAIL;
	} else {
		req = SBSDIO_HT_AVAIL_REQ | SBSDIO_FORCE_HT;
		avail = SBSDIO_HT_AVAIL;
	}

	sdio_write_1(f1, SBSDIO_FUNC1_CHIPCLKCSR, req, &err);
	if (err != 0)
		return (err);

	for (i = 0; i < 500; i++) {
		clkval = sdio_read_1(f1, SBSDIO_FUNC1_CHIPCLKCSR, &err);
		if (err != 0)
			return (err);
		if (clkval & avail)
			return (0);
		DELAY(1000);
	}

	device_printf(sc->dev, "clock enable timeout (clkval=0x%02x)\n",
	    clkval);
	return (ETIMEDOUT);
}

/*
 * Disable clocks — allow chip to sleep.
 */
static void
brcmf_sdio_clk_disable(struct brcmf_softc *sc)
{
	int err;

	sdio_write_1(sc->sdio_func1, SBSDIO_FUNC1_CHIPCLKCSR, 0, &err);
}

/*
 * Write a block of data to a backplane address via F1 CMD53.
 */
static int
brcmf_sdio_bp_write_block(struct brcmf_softc *sc, uint32_t addr,
    const void *data, size_t len)
{
	const uint8_t *src = data;
	uint32_t offset;
	size_t winsz, xfer;
	int error;

	while (len > 0) {
		brcmf_sdio_set_window(sc, addr);
		offset = (addr & SBSDIO_SB_OFT_ADDR_MASK) |
		    SBSDIO_SB_ACCESS_2_4B_FLAG;

		/* Bytes remaining in this 32KB window */
		winsz = (SBSDIO_SB_OFT_ADDR_MASK + 1) -
		    (addr & SBSDIO_SB_OFT_ADDR_MASK);
		if (winsz > len)
			winsz = len;

		/* Write up to 64 bytes at a time (F1 block size) */
		while (winsz > 0) {
			xfer = (winsz > SDIO_F1_BLOCKSIZE) ?
			    SDIO_F1_BLOCKSIZE : winsz;
			error = SDIO_WRITE_EXTENDED(
			    device_get_parent(sc->sdio_func1->dev),
			    sc->sdio_func1->fn, offset, xfer,
			    __DECONST(uint8_t *, src), true);
			if (error != 0)
				return (error);
			src += xfer;
			offset += xfer;
			addr += xfer;
			len -= xfer;
			winsz -= xfer;
		}
	}

	return (0);
}

/*
 * Check if core is in reset.
 */
static int
brcmf_sdio_core_in_reset(struct brcmf_softc *sc, struct brcmf_coreinfo *core)
{
	uint32_t val;

	val = brcmf_sdio_bp_read32(sc, core->wrapbase + BCMA_RESET_CTL);
	return ((val & BCMA_RESET_CTL_RESET) != 0);
}

/*
 * Disable a core (put into reset).
 */
static void
brcmf_sdio_core_disable(struct brcmf_softc *sc, struct brcmf_coreinfo *core,
    uint32_t prereset, uint32_t reset)
{
	uint32_t val;
	int i;

	if (brcmf_sdio_core_in_reset(sc, core))
		goto in_reset;

	brcmf_sdio_bp_write32(sc, core->wrapbase + BCMA_IOCTL,
	    prereset | BCMA_IOCTL_FGC | BCMA_IOCTL_CLK);
	brcmf_sdio_bp_read32(sc, core->wrapbase + BCMA_IOCTL);

	brcmf_sdio_bp_write32(sc, core->wrapbase + BCMA_RESET_CTL,
	    BCMA_RESET_CTL_RESET);
	DELAY(20);

	for (i = 0; i < 300; i++) {
		val = brcmf_sdio_bp_read32(sc,
		    core->wrapbase + BCMA_RESET_CTL);
		if (val == BCMA_RESET_CTL_RESET)
			break;
		DELAY(10);
	}

in_reset:
	brcmf_sdio_bp_write32(sc, core->wrapbase + BCMA_IOCTL,
	    reset | BCMA_IOCTL_FGC | BCMA_IOCTL_CLK);
	brcmf_sdio_bp_read32(sc, core->wrapbase + BCMA_IOCTL);
}

/*
 * Reset a core (disable, then bring out of reset).
 */
static void
brcmf_sdio_core_reset(struct brcmf_softc *sc, struct brcmf_coreinfo *core,
    uint32_t prereset, uint32_t reset, uint32_t postreset)
{
	uint32_t val;
	int i;

	brcmf_sdio_core_disable(sc, core, prereset, reset);

	for (i = 0; i < 50; i++) {
		brcmf_sdio_bp_write32(sc,
		    core->wrapbase + BCMA_RESET_CTL, 0);
		val = brcmf_sdio_bp_read32(sc,
		    core->wrapbase + BCMA_RESET_CTL);
		if ((val & BCMA_RESET_CTL_RESET) == 0)
			break;
		DELAY(60);
	}

	brcmf_sdio_bp_write32(sc, core->wrapbase + BCMA_IOCTL,
	    postreset | BCMA_IOCTL_CLK);
	brcmf_sdio_bp_read32(sc, core->wrapbase + BCMA_IOCTL);
}

/*
 * Enumerate chip cores via EROM and identify the chip.
 */
static int
brcmf_sdio_chip_identify(struct brcmf_softc *sc)
{
	uint32_t regdata, erombase;

	regdata = brcmf_sdio_bp_read32(sc, SI_ENUM_BASE);
	sc->chip = regdata & CID_ID_MASK;
	sc->chiprev = (regdata >> 16) & 0xF;

	device_printf(sc->dev, "chip=%04x rev=%u\n", sc->chip, sc->chiprev);

	erombase = brcmf_sdio_bp_read32(sc, SI_ENUM_BASE + CC_EROMBASE);

	sc->armcore = brcmf_find_core(erombase, brcmf_sdio_erom_read, sc,
	    0x83E /* BCMA_CORE_ARM_CR4 */);
	if (sc->armcore.id == 0) {
		/* Try ARM CM3 for older chips */
		sc->armcore = brcmf_find_core(erombase,
		    brcmf_sdio_erom_read, sc,
		    0x82A /* BCMA_CORE_ARM_CM3 */);
	}
	if (sc->armcore.id == 0) {
		device_printf(sc->dev, "ARM core not found\n");
		return (ENODEV);
	}

	sc->ramcore = brcmf_find_core(erombase, brcmf_sdio_erom_read, sc,
	    0x80E /* BCMA_CORE_SOCRAM */);

	sc->d11core = brcmf_find_core(erombase, brcmf_sdio_erom_read, sc,
	    0x812 /* BCMA_CORE_80211 */);

	sc->sdiocore = brcmf_find_core(erombase, brcmf_sdio_erom_read, sc,
	    BCMA_CORE_SDIO_DEV);
	if (sc->sdiocore.id == 0)
		device_printf(sc->dev, "SDIO device core not found\n");

	return (0);
}

/*
 * Determine RAM base and size from ARM core bank info.
 */
static int
brcmf_sdio_get_raminfo(struct brcmf_softc *sc)
{
	uint32_t nbanks, bankinfo, banksize, i;
	uint32_t corecap;

	if (sc->armcore.id == 0x83E) {
		/* ARM CR4: read bank info from ARM core */
		corecap = brcmf_sdio_bp_read32(sc,
		    sc->armcore.base + 0x04);
		nbanks = (corecap & 0x0F) + ((corecap >> 4) & 0x0F);

		sc->ram_size = 0;
		for (i = 0; i < nbanks; i++) {
			brcmf_sdio_bp_write32(sc,
			    sc->armcore.base + 0x40, i);
			bankinfo = brcmf_sdio_bp_read32(sc,
			    sc->armcore.base + 0x44);
			banksize = 8192;
			if (bankinfo & 0x200)
				banksize = 1024;
			banksize *= ((bankinfo & 0x7F) + 1);
			sc->ram_size += banksize;
		}

		sc->ram_base = 0x198000;
	} else if (sc->ramcore.id != 0) {
		/* SOCRAM: read from memory core */
		corecap = brcmf_sdio_bp_read32(sc,
		    sc->ramcore.base + 0x04);
		nbanks = (corecap >> 4) & 0xF;

		sc->ram_size = 0;
		for (i = 0; i < nbanks; i++) {
			brcmf_sdio_bp_write32(sc,
			    sc->ramcore.base + 0x10, i);
			bankinfo = brcmf_sdio_bp_read32(sc,
			    sc->ramcore.base + 0x14);
			banksize = 8192 * ((bankinfo & 0x3F) + 1);
			sc->ram_size += banksize;
		}

		sc->ram_base = 0;
	} else {
		device_printf(sc->dev, "cannot determine RAM info\n");
		return (ENODEV);
	}

	device_printf(sc->dev, "ram_base=0x%x ram_size=0x%x (%uKB)\n",
	    sc->ram_base, sc->ram_size, sc->ram_size / 1024);
	return (0);
}

/*
 * Download firmware and NVRAM to chip, boot firmware.
 */
static int
brcmf_sdio_download_fw(struct brcmf_softc *sc, const struct firmware *fw,
    void *nvram, uint32_t nvram_len)
{
	int error, i;

	if (fw->datasize > sc->ram_size) {
		device_printf(sc->dev, "firmware too large (%zu > %u)\n",
		    fw->datasize, sc->ram_size);
		return (EINVAL);
	}

	/* Enable SOCRAM if present (needed for RAM access on some chips) */
	if (sc->ramcore.id != 0 && sc->ramcore.wrapbase != 0)
		brcmf_sdio_core_reset(sc, &sc->ramcore, 0, 0, 0);

	/* Halt ARM */
	brcmf_sdio_core_disable(sc, &sc->armcore,
	    BCMA_IOCTL_CPUHALT, BCMA_IOCTL_CPUHALT);
	brcmf_sdio_core_reset(sc, &sc->armcore,
	    BCMA_IOCTL_CPUHALT, BCMA_IOCTL_CPUHALT, BCMA_IOCTL_CPUHALT);

	/* Disable D11 core to let firmware enable it */
	if (sc->d11core.id != 0 && sc->d11core.wrapbase != 0)
		brcmf_sdio_core_disable(sc, &sc->d11core, 0x08 | 0x04, 0x04);

	/* Clear shared RAM marker at end of RAM */
	brcmf_sdio_bp_write32(sc, sc->ram_base + sc->ram_size - 4, 0);

	/* Write firmware to RAM */
	error = brcmf_sdio_bp_write_block(sc, sc->ram_base,
	    fw->data, fw->datasize);
	if (error != 0) {
		device_printf(sc->dev, "firmware write failed: %d\n", error);
		return (error);
	}

	/* Verify firmware in RAM at multiple offsets */
	{
		static const uint32_t check_offsets[] = {
		    0, 4, 0x100, 0x1000, 0x8000
		};
		int ci;
		for (ci = 0; ci < 5; ci++) {
			uint32_t off = check_offsets[ci];
			if (off + 4 > fw->datasize)
				break;
			uint32_t got = brcmf_sdio_bp_read32(sc,
			    sc->ram_base + off);
			uint32_t want = *(const uint32_t *)
			    ((const char *)fw->data + off);
			if (got != want) {
				device_printf(sc->dev,
				    "fw verify FAIL @0x%x: "
				    "got 0x%08x want 0x%08x\n",
				    off, got, want);
			}
		}
	}

	/* Write NVRAM to end of RAM */
	if (nvram != NULL && nvram_len > 0) {
		uint32_t nvram_addr = sc->ram_base + sc->ram_size - nvram_len;
		error = brcmf_sdio_bp_write_block(sc, nvram_addr,
		    nvram, nvram_len);
		if (error != 0) {
			device_printf(sc->dev, "NVRAM write failed: %d\n",
			    error);
			return (error);
		}
		/* Verify NVRAM token at end of RAM */
		{
			uint32_t token_addr = nvram_addr + nvram_len - 4;
			uint32_t token_val = brcmf_sdio_bp_read32(sc,
			    token_addr);
			uint32_t expect_words = (nvram_len - 4) / 4;
			uint32_t expect_token = (~expect_words << 16) |
			    (expect_words & 0xFFFF);

			if (token_val != expect_token) {
				/* Block write may have failed; try
				 * single-word write as fallback */
				brcmf_sdio_bp_write32(sc, token_addr,
				    expect_token);
				token_val = brcmf_sdio_bp_read32(sc,
				    token_addr);
			}
			device_printf(sc->dev,
			    "NVRAM at 0x%x (%u bytes), "
			    "token @0x%x: got=0x%08x want=0x%08x\n",
			    nvram_addr, nvram_len, token_addr,
			    token_val, expect_token);
		}
	}

	/* Clear SDIO core interrupts before releasing ARM */
	if (sc->sdiocore.base != 0)
		brcmf_sdio_bp_write32(sc,
		    sc->sdiocore.base + SD_REG_INTSTATUS, 0xFFFFFFFF);

	/* Write reset vector to address 0 */
	{
		uint32_t rstvec = *(const uint32_t *)fw->data;
		brcmf_sdio_bp_write32(sc, 0, rstvec);
	}

	/* Release ARM */
	brcmf_sdio_core_reset(sc, &sc->armcore,
	    BCMA_IOCTL_CPUHALT, 0, 0);

	device_printf(sc->dev, "ARM released, waiting for F2...\n");

	/* Force HT clock — firmware needs it to run and signal F2 */
	sdio_write_1(sc->sdio_func1, SBSDIO_FUNC1_CHIPCLKCSR,
	    SBSDIO_FORCE_HT, &error);

	/* Tell firmware our protocol version via tosbmailboxdata */
	if (sc->sdiocore.base != 0)
		brcmf_sdio_bp_write32(sc,
		    sc->sdiocore.base + SD_REG_TOSBMAILBOXDATA,
		    SDPCM_PROT_VERSION << SMB_DATA_VERSION_SHIFT);

	/* Enable F2 via CCCR IOEx */
	{
		uint8_t ioex;
		ioex = sdio_f0_read_1(sc->sdio_func1, 0x02, &error);
		ioex |= 0x04;
		sdio_f0_write_1(sc->sdio_func1, 0x02, ioex, &error);

		/* Verify */
		ioex = sdio_f0_read_1(sc->sdio_func1, 0x02, &error);
		device_printf(sc->dev, "F2 enable: IOEx=0x%02x err=%d\n",
		    ioex, error);

		/* Also enable F2 through the sdiob API if we have the ptr */
		if (sc->sdio_func2 != NULL)
			sdio_enable_func(sc->sdio_func2);
	}

	/* Diag: read SDIO core intstatus */
	if (sc->sdiocore.base != 0) {
		uint32_t intst = brcmf_sdio_bp_read32(sc,
		    sc->sdiocore.base + SD_REG_INTSTATUS);
		device_printf(sc->dev, "sdio core intstatus=0x%08x\n", intst);
	}

	/* Wait for firmware to write shared RAM address (last 4 bytes of RAM).
	 * The CCCR IORdy F2 bit is unreliable on FreeBSD's SDIO stack;
	 * poll the shared RAM marker instead. */
	{
		uint32_t shared = 0;
		for (i = 0; i < BRCMF_SDIO_F2_READY_TIMEOUT_MS /
		    BRCMF_SDIO_F2_READY_POLL_MS; i++) {
			pause_sbt("brcmfw",
			    mstosbt(BRCMF_SDIO_F2_READY_POLL_MS), 0, 0);
			shared = brcmf_sdio_bp_read32(sc,
			    sc->ram_base + sc->ram_size - 4);
			if (shared != 0 && shared != 0xFFFFFFFF)
				break;
		}

		if (shared == 0 || shared == 0xFFFFFFFF) {
			device_printf(sc->dev,
			    "firmware boot timeout (sharedram=0x%08x)\n",
			    shared);
			return (ETIMEDOUT);
		}

		device_printf(sc->dev,
		    "firmware booted, sharedram=0x%08x\n", shared);
	}

	/* Configure SDIO core host interrupt mask */
	if (sc->sdiocore.base != 0) {
		brcmf_sdio_bp_write32(sc,
		    sc->sdiocore.base + SD_REG_HOSTINTMASK,
		    I_HMB_SW_MASK | I_HMB_FRAME_IND |
		    I_HMB_HOST_INT | I_HMB_FC_CHANGE);
	}

	/* F2 watermark and device control — required for F2 data flow */
	{
		uint8_t devctl;
		int err;

		sdio_write_1(sc->sdio_func1, SBSDIO_WATERMARK,
		    CY_43455_F2_WATERMARK, &err);

		devctl = sdio_read_1(sc->sdio_func1, SBSDIO_DEVICE_CTL, &err);
		devctl |= SBSDIO_DEVCTL_F2WM_ENAB;
		sdio_write_1(sc->sdio_func1, SBSDIO_DEVICE_CTL, devctl, &err);

		sdio_write_1(sc->sdio_func1, SBSDIO_FUNC1_MESBUSYCTRL,
		    CY_43455_MES_WATERMARK | SBSDIO_MESBUSYCTRL_ENAB, &err);
	}

	return (0);
}

static int brcmf_sdio_diag_sysctl(SYSCTL_HANDLER_ARGS);

/*
 * Main SDIO bus attach — called from main.c after probe.
 */
int
brcmf_sdio_attach(struct brcmf_softc *sc)
{
	struct sdio_func *f1;
	const struct firmware *fw = NULL;
	const struct firmware *nvram_fw = NULL;
	void *nvram = NULL;
	uint32_t nvram_len = 0;
	int error;

	f1 = sc->sdio_func1;
	if (f1 == NULL) {
		device_printf(sc->dev, "F1 function not set\n");
		return (EINVAL);
	}

	sc->sdio_window = ~0U;

	/* Set F1 block size */
	error = sdio_set_block_size(f1, SDIO_F1_BLOCKSIZE);
	if (error != 0) {
		device_printf(sc->dev, "failed to set F1 block size: %d\n",
		    error);
		return (error);
	}

	/* Enable F1 */
	error = sdio_enable_func(f1);
	if (error != 0) {
		device_printf(sc->dev, "failed to enable F1: %d\n", error);
		return (error);
	}

	/* Request ALP clock for initial setup */
	error = brcmf_sdio_clk_enable(sc, 1);
	if (error != 0) {
		device_printf(sc->dev, "failed to enable ALP clock: %d\n",
		    error);
		return (error);
	}

	/* Identify chip and enumerate cores */
	error = brcmf_sdio_chip_identify(sc);
	if (error != 0)
		return (error);

	/* Get RAM info */
	error = brcmf_sdio_get_raminfo(sc);
	if (error != 0)
		return (error);

	/* ALP clock suffices for firmware download */

	/* Load firmware */
	fw = firmware_get(BRCMF_SDIO_FW_NAME);
	if (fw == NULL) {
		device_printf(sc->dev, "failed to load firmware %s\n",
		    BRCMF_SDIO_FW_NAME);
		return (ENOENT);
	}
	device_printf(sc->dev, "loaded firmware %s (%zu bytes)\n",
	    BRCMF_SDIO_FW_NAME, fw->datasize);

	/* Load NVRAM */
	nvram_fw = firmware_get(BRCMF_SDIO_NVRAM_NAME);
	if (nvram_fw != NULL) {
		nvram = brcmf_nvram_parse(nvram_fw->data,
		    nvram_fw->datasize, &nvram_len);
		firmware_put(nvram_fw, FIRMWARE_UNLOAD);
	}

	/* Download firmware */
	error = brcmf_sdio_download_fw(sc, fw, nvram, nvram_len);
	firmware_put(fw, FIRMWARE_UNLOAD);

	if (nvram != NULL)
		free(nvram, M_BRCMFMAC);

	if (error != 0)
		return (error);

	/* Set F2 block size via CCCR FBR (Function Basic Registers).
	 * FBR for F2 starts at 0x200. Block size is at FBR+0x10 (2 bytes). */
	{
		int bserr;
		sdio_f0_write_1(sc->sdio_func1, 0x210,
		    SDIO_F2_BLOCKSIZE & 0xFF, &bserr);
		sdio_f0_write_1(sc->sdio_func1, 0x211,
		    (SDIO_F2_BLOCKSIZE >> 8) & 0xFF, &bserr);
		device_printf(sc->dev, "F2 block size set to %d\n",
		    SDIO_F2_BLOCKSIZE);

		/* Also try via API if available */
		if (sc->sdio_func2 != NULL)
			sdio_set_block_size(sc->sdio_func2, SDIO_F2_BLOCKSIZE);
	}

	/* Diagnostic sysctl */
	{
		struct sysctl_ctx_list *ctx;
		struct sysctl_oid *tree;

		ctx = device_get_sysctl_ctx(sc->dev);
		tree = device_get_sysctl_tree(sc->dev);
		SYSCTL_ADD_PROC(ctx, SYSCTL_CHILDREN(tree), OID_AUTO,
		    "sdio_diag", CTLTYPE_STRING | CTLFLAG_RD | CTLFLAG_MPSAFE,
		    sc, 0, brcmf_sdio_diag_sysctl, "A",
		    "SDIO diagnostic: read core state and F2");
	}

	return (0);
}

/*
 * Diagnostic sysctl: read SDIO core state and attempt F2 read.
 */
static int
brcmf_sdio_diag_sysctl(SYSCTL_HANDLER_ARGS)
{
	struct brcmf_softc *sc = arg1;
	char buf[512];
	uint32_t intst;
	int error, len;

	if (sc->sdiocore.base == 0) {
		len = snprintf(buf, sizeof(buf), "no sdio core\n");
		return SYSCTL_OUT(req, buf, len);
	}

	intst = brcmf_sdio_bp_read32(sc,
	    sc->sdiocore.base + SD_REG_INTSTATUS);

	/* Read additional SDIO core registers */
	{
		uint32_t hostmask = brcmf_sdio_bp_read32(sc,
		    sc->sdiocore.base + 0x024);
		uint32_t tohost = brcmf_sdio_bp_read32(sc,
		    sc->sdiocore.base + 0x044);
		uint8_t clkval = sdio_read_1(sc->sdio_func1,
		    SBSDIO_FUNC1_CHIPCLKCSR, &error);
		uint8_t devctl = sdio_read_1(sc->sdio_func1,
		    0x10009 /* SBSDIO_DEVICE_CTL */, &error);
		len = snprintf(buf, sizeof(buf),
		    "intst=0x%08x hostmask=0x%08x tohost=0x%08x "
		    "clk=0x%02x devctl=0x%02x\n",
		    intst, hostmask, tohost, clkval, devctl);
	}

	return SYSCTL_OUT(req, buf, len);
}

void
brcmf_sdio_detach(struct brcmf_softc *sc)
{

	brcmf_sdio_clk_disable(sc);
}
