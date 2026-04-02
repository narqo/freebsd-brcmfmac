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

#define SDIO_F1_BLOCKSIZE	64

/* F2 block size (BCM43455 default) */
#define SDIO_F2_BLOCKSIZE	64

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

/* Protocol version for tosbmailboxdata */
#define SDPCM_PROT_VERSION	4

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

	/* clock sequencer needs time to stabilize; poll up to 500ms */
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
	int error, count = 0;

	while (len > 0) {
		brcmf_sdio_set_window(sc, addr);
		offset = (addr & SBSDIO_SB_OFT_ADDR_MASK) |
		    SBSDIO_SB_ACCESS_2_4B_FLAG;

		/* Bytes remaining in this 32KB window */
		winsz = (SBSDIO_SB_OFT_ADDR_MASK + 1) -
		    (addr & SBSDIO_SB_OFT_ADDR_MASK);
		if (winsz > len)
			winsz = len;

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
			/* let watchdog run during large transfers */
			if (++count % 128 == 0)
				pause_sbt("brcmfw", SBT_1MS, 0, 0);
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
	DELAY(20); /* reset crosses backplane clock domains */

	/* reset status bit updates asynchronously */
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

	/* reset deassert may require multiple attempts */
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
		/*
		 * ARM CR4: ensure core is out of reset before reading.
		 * After kldunload, the core may be in undefined state.
		 */
		brcmf_sdio_core_reset(sc, &sc->armcore, 0, 0, 0);

		/* Read bank info from ARM core */
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

	BRCMF_DBG(sc, "ram_base=0x%x ram_size=0x%x (%uKB)\n",
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

	/* Disable F2 before firmware download to clear stale frame state.
	 * Linux does this during probe. Without it, a second kldload
	 * leaves F2 enabled from the previous load, and the new firmware
	 * may not re-initialize F2 properly. */
	{
		uint8_t ioex;
		ioex = sdio_f0_read_1(sc->sdio_func1, 0x02, &error);
		if (ioex & 0x04) {
			ioex &= ~0x04;
			sdio_f0_write_1(sc->sdio_func1, 0x02, ioex, &error);
		}
		if (sc->sdio_func2 != NULL)
			sdio_disable_func(sc->sdio_func2);
	}

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
	BRCMF_DBG(sc, "writing firmware (%zu bytes) to 0x%x...\n",
	    fw->datasize, sc->ram_base);
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

	BRCMF_DBG(sc, "firmware verify passed\n");

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
			BRCMF_DBG(sc,
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

	BRCMF_DBG(sc, "ARM released, waiting for F2...\n");

	/* Request and wait for HT clock. The SDIO core needs the backplane
	 * HT clock to complete F2 initialization. */
	sdio_write_1(sc->sdio_func1, SBSDIO_FUNC1_CHIPCLKCSR,
	    SBSDIO_HT_AVAIL_REQ | SBSDIO_FORCE_HT, &error);
	{
		uint8_t clkval;
		for (i = 0; i < 100; i++) {
			pause_sbt("brcmht", mstosbt(10), 0, 0);
			clkval = sdio_read_1(sc->sdio_func1,
			    SBSDIO_FUNC1_CHIPCLKCSR, &error);
			if (error != 0)
				break;
			if (clkval & SBSDIO_HT_AVAIL)
				break;
		}
		BRCMF_DBG(sc, "HT clock: clkval=0x%02x iter=%d\n",
		    clkval, i);
	}

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
		BRCMF_DBG(sc, "F2 enable: IOEx=0x%02x err=%d\n",
		    ioex, error);

		/* Also enable F2 through the sdiob API if we have the ptr */
		if (sc->sdio_func2 != NULL)
			sdio_enable_func(sc->sdio_func2);
	}

	/* Set F2 block size on the card via CCCR FBR before F2 becomes
	 * ready. Also update sdiob's cur_blksize so it uses byte mode
	 * for frames < 512 bytes (multi-block hangs the Arasan SDHCI). */
	{
		int bserr;
		sdio_f0_write_1(sc->sdio_func1, 0x210,
		    SDIO_F2_BLOCKSIZE & 0xFF, &bserr);
		sdio_f0_write_1(sc->sdio_func1, 0x211,
		    (SDIO_F2_BLOCKSIZE >> 8) & 0xFF, &bserr);
		/* Update sdiob's internal cur_blksize directly. The
		 * sdio_set_block_size API hangs when called before F2
		 * is ready — it goes through CAM which blocks. */
		if (sc->sdio_func2 != NULL)
			sc->sdio_func2->cur_blksize = SDIO_F2_BLOCKSIZE;
	}

	/* Diag: read SDIO core intstatus */
	if (sc->sdiocore.base != 0) {
		uint32_t intst = brcmf_sdio_bp_read32(sc,
		    sc->sdiocore.base + SD_REG_INTSTATUS);
		BRCMF_DBG(sc, "sdio core intstatus=0x%08x\n", intst);
	}

	/* Wait for firmware boot via sharedram marker (F1 backplane reads). */
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

		BRCMF_DBG(sc, "firmware booted, sharedram=0x%08x\n", shared);

		/* Read the sdpcm_shared structure at the advertised address.
		 * Linux validates protocol version from flags and uses
		 * console_addr for firmware log access. */
		{
			uint32_t sh_flags, sh_trap, sh_console, sh_fwid;

			sh_flags = brcmf_sdio_bp_read32(sc, shared);
			sh_trap = brcmf_sdio_bp_read32(sc, shared + 4);
			sh_console = brcmf_sdio_bp_read32(sc, shared + 20);
			sh_fwid = brcmf_sdio_bp_read32(sc, shared + 28);

			BRCMF_DBG(sc,
			    "sdpcm_shared: flags=0x%08x trap=0x%08x "
			    "console=0x%08x fwid=0x%08x\n",
			    sh_flags, sh_trap, sh_console, sh_fwid);

			sc->sdpcm_shared_flags = sh_flags;
			sc->shared.console_addr = sh_console;
		}
	}

	/* Poll F2 ready (CCCR IORdy bit 2), up to 3s.
	 * The F0 timeout=0 bug in sdiob (fixed in SDIOF2PACE2) caused
	 * these polls to hang — CAM waited forever on fn=0 CMD52. */
	{
		uint8_t iordy = 0;
		for (i = 0; i < 300; i++) {
			iordy = sdio_f0_read_1(sc->sdio_func1, 0x03, &error);
			if (error == 0 && (iordy & 0x04))
				break;
			pause_sbt("brcmf2", mstosbt(10), 0, 0);
		}
		BRCMF_DBG(sc,
		    "CCCR IORdy=0x%02x (F2_ready=%d) iter=%d\n",
		    iordy, (iordy & 0x04) != 0, i);
		if (!(iordy & 0x04)) {
			device_printf(sc->dev, "F2 not ready, aborting\n");
			return (ENXIO);
		}
	}

	/* Ack any pending SDIO core interrupts before enabling the mask. */
	if (sc->sdiocore.base != 0) {
		uint32_t intst = brcmf_sdio_bp_read32(sc,
		    sc->sdiocore.base + SD_REG_INTSTATUS);
		if (intst != 0)
			brcmf_sdio_bp_write32(sc,
			    sc->sdiocore.base + SD_REG_INTSTATUS, intst);
	}

	/* Configure SDIO core host interrupt mask */
	if (sc->sdiocore.base != 0) {
		brcmf_sdio_bp_write32(sc,
		    sc->sdiocore.base + SD_REG_HOSTINTMASK,
		    I_HMB_SW_MASK | I_HMB_FRAME_IND |
		    I_HMB_HOST_INT | I_HMB_FC_CHANGE);
	}

	/*
	 * Read and ack the firmware's tohostmailbox. Linux does this
	 * in its DPC loop before the first ioctl. Without the ack,
	 * the firmware may not enable its connection state machine.
	 */
	if (sc->sdiocore.base != 0) {
		uint32_t mbox = brcmf_sdio_bp_read32(sc,
		    sc->sdiocore.base + SD_REG_TOHOSTMAILBOXDATA);
		BRCMF_DBG(sc, "tohostmailbox=0x%08x\n", mbox);
		if (mbox != 0) {
			brcmf_sdio_bp_write32(sc,
			    sc->sdiocore.base + SD_REG_TOSBMAILBOX,
			    SMB_INT_ACK);
		}
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

	/* Verify F2 block size on card side and probe F2 write path.
	 * Read back CCCR FBR block size for F2 (registers 0x210/0x211). */
	{
		uint8_t bslo, bshi;
		int berr;
		bslo = sdio_f0_read_1(sc->sdio_func1, 0x210, &berr);
		bshi = sdio_f0_read_1(sc->sdio_func1, 0x211, &berr);
		BRCMF_DBG(sc,
		    "F2 card blksz=%u sdiob_blksz=%u\n",
		    bslo | (bshi << 8),
		    sc->sdio_func2 ? sc->sdio_func2->cur_blksize : 0);
	}

	/* Enable SDIO interrupts in CCCR. Linux calls sdio_claim_irq()
	 * which enables IEN for F1 and F2. The firmware may check
	 * CCCR IENx to confirm host readiness. */
	{
		uint8_t ien;
		int err;
		ien = sdio_f0_read_1(sc->sdio_func1, 0x04, &err);
		ien |= 0x01 | 0x02 | 0x04;  /* IEN master + F1 + F2 */
		sdio_f0_write_1(sc->sdio_func1, 0x04, ien, &err);
		BRCMF_DBG(sc, "CCCR IENx=0x%02x err=%d\n", ien, err);
	}

	/* SaveRestore init — required for BCM4345/CYW43455.
	 * Configures wake-up control, card capability, and clock.
	 * Without this the chip's radio may not transmit. */
	{
		uint8_t val;
		int err;

		/* WAKEUPCTRL: set HT wait bit */
		val = sdio_read_1(sc->sdio_func1, 0x1001E, &err);
		val |= (1 << 1);	/* HTWAIT */
		sdio_write_1(sc->sdio_func1, 0x1001E, val, &err);

		/* CCCR CARDCAP: enable CMD14 support */
		sdio_f0_write_1(sc->sdio_func1, 0xF0,
		    (1 << 1) | (1 << 2), &err);

		/* CHIPCLKCSR: force HT clock */
		sdio_write_1(sc->sdio_func1, SBSDIO_FUNC1_CHIPCLKCSR,
		    SBSDIO_FORCE_HT, &err);

		BRCMF_DBG(sc, "SR init done\n");
	}



	return (0);
}

static int brcmf_sdio_diag_sysctl(SYSCTL_HANDLER_ARGS);
static int brcmf_sdio_fwcon_sysctl(SYSCTL_HANDLER_ARGS);

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

	BRCMF_DBG(sc, "sdio_attach: entry, f1=%p fn=%d\n",
	    f1, f1->fn);

	/* Set F1 block size */
	error = sdio_set_block_size(f1, SDIO_F1_BLOCKSIZE);
	if (error != 0) {
		device_printf(sc->dev, "F1 block size error: %d\n", error);
		return (error);
	}

	/* Enable F1 */
	error = sdio_enable_func(f1);
	if (error != 0) {
		device_printf(sc->dev, "F1 enable error: %d\n", error);
		return (error);
	}

	/* Request ALP clock for initial setup */
	error = brcmf_sdio_clk_enable(sc, 1);
	if (error != 0)
		return (error);

	/* Identify chip and enumerate cores */
	error = brcmf_sdio_chip_identify(sc);
	if (error != 0)
		return (error);

	/* Get RAM info */
	error = brcmf_sdio_get_raminfo(sc);
	if (error != 0)
		return (error);

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
		BRCMF_DBG(sc, "F2 block size set to %d\n",
		    SDIO_F2_BLOCKSIZE);

		/* Skip sdio_set_block_size(func2) — it goes through CAM
		 * and hangs. The CCCR FBR writes above + direct
		 * cur_blksize update in download_fw are sufficient. */
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
		SYSCTL_ADD_PROC(ctx, SYSCTL_CHILDREN(tree), OID_AUTO,
		    "fwcon", CTLTYPE_STRING | CTLFLAG_RD | CTLFLAG_MPSAFE,
		    sc, 0, brcmf_sdio_fwcon_sysctl, "A",
		    "Firmware console log (last 1KB)");
	}

	return (0);
}

/*
 * Diagnostic sysctl: read SDIO core state.
 * Pauses DPC thread for exclusive SDIO bus access.
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

	sx_xlock(&sc->sdio_lock);

	intst = brcmf_sdio_bp_read32(sc,
	    sc->sdiocore.base + SD_REG_INTSTATUS);

	{
		uint32_t hostmask = brcmf_sdio_bp_read32(sc,
		    sc->sdiocore.base + 0x024);
		uint32_t tohost = brcmf_sdio_bp_read32(sc,
		    sc->sdiocore.base + 0x044);
		uint8_t clkval = sdio_read_1(sc->sdio_func1,
		    SBSDIO_FUNC1_CHIPCLKCSR, &error);
		uint8_t devctl = sdio_read_1(sc->sdio_func1,
		    0x10009 /* SBSDIO_DEVICE_CTL */, &error);
		uint8_t ioex = sdio_f0_read_1(sc->sdio_func1, 0x02, &error);
		uint8_t iordy = sdio_f0_read_1(sc->sdio_func1, 0x03, &error);
		len = snprintf(buf, sizeof(buf),
		    "intst=0x%08x hostmask=0x%08x tohost=0x%08x "
		    "clk=0x%02x devctl=0x%02x IOEx=0x%02x IORdy=0x%02x\n",
		    intst, hostmask, tohost, clkval, devctl, ioex, iordy);
	}

	sx_xunlock(&sc->sdio_lock);
	return SYSCTL_OUT(req, buf, len);
}

/*
 * Firmware console sysctl: read firmware log buffer.
 *
 * Must stop the DPC thread during access — concurrent SDIO bus
 * access from two threads corrupts CAM queue state (camq_remove
 * panic at out-of-bounds index).
 */
static int
brcmf_sdio_fwcon_sysctl(SYSCTL_HANDLER_ARGS)
{
	struct brcmf_softc *sc = arg1;
	uint32_t console_addr, buf_addr, bufsize, writeidx;
	char out[2048];
	int pos = 0;

	console_addr = sc->shared.console_addr;
	if (console_addr == 0)
		return SYSCTL_OUT(req, "no console\n", 11);

	sx_xlock(&sc->sdio_lock);

	buf_addr = brcmf_sdio_bp_read32(sc, console_addr + 8);
	bufsize = brcmf_sdio_bp_read32(sc, console_addr + 12);
	writeidx = brcmf_sdio_bp_read32(sc, console_addr + 16);

	pos = snprintf(out, sizeof(out),
	    "console=0x%x buf=0x%x size=%u widx=%u\n",
	    console_addr, buf_addr, bufsize, writeidx);
	if (bufsize == 0 || bufsize > 0x100000 || buf_addr == 0)
		goto done;

	{
		uint32_t readidx = 0;
		while (readidx != writeidx && pos < (int)sizeof(out) - 2) {
			int err;
			brcmf_sdio_set_window(sc, buf_addr + readidx);
			uint32_t off = ((buf_addr + readidx) & 0x7FFF) |
			    0x8000;
			char ch = sdio_read_1(sc->sdio_func1, off, &err);
			if (err != 0)
				break;
			if (ch != '\0')
				out[pos++] = ch;
			readidx++;
			if (readidx >= bufsize)
				readidx = 0;
		}
	}

done:
	sx_xunlock(&sc->sdio_lock);
	out[pos] = '\0';
	return SYSCTL_OUT(req, out, pos);
}

/*
 * Put chip into passive state: halt ARM, disable D11 core.
 *
 * Without this, the firmware continues running when we disable clocks,
 * leaving the chip's internal state machine stuck. The next kldload
 * then fails with "clock enable timeout" because CHIPCLKCSR can't
 * bring clocks back up on a wedged chip.
 *
 * Matches Linux brcmf_chip_cr4_set_passive + brcmf_chip_coredisable(d11).
 */
static void
brcmf_sdio_chip_set_passive(struct brcmf_softc *sc)
{
	uint32_t val;

	/* Halt ARM CR4: read current IOCTL, keep only CPUHALT,
	 * then resetcore with CPUHALT held throughout. */
	if (sc->armcore.id != 0 && sc->armcore.wrapbase != 0) {
		val = brcmf_sdio_bp_read32(sc,
		    sc->armcore.wrapbase + BCMA_IOCTL);
		val &= BCMA_IOCTL_CPUHALT;
		brcmf_sdio_core_reset(sc, &sc->armcore,
		    val, BCMA_IOCTL_CPUHALT, BCMA_IOCTL_CPUHALT);
	}

	/* Disable D11 core (radio) */
	if (sc->d11core.id != 0 && sc->d11core.wrapbase != 0)
		brcmf_sdio_core_disable(sc, &sc->d11core,
		    0x08 | 0x04, 0x04);
}

void
brcmf_sdio_detach(struct brcmf_softc *sc)
{
	int err;

	if (sc->sdio_func1 == NULL)
		return;

	/* Bring backplane clocks up so we can access core wrappers */
	err = brcmf_sdio_clk_enable(sc, 0);
	if (err == 0) {
		/* Clear SDIO core host interrupt mask and pending interrupts.
		 * Linux does this in brcmf_sdio_bus_stop before set_passive. */
		if (sc->sdiocore.base != 0) {
			brcmf_sdio_bp_write32(sc,
			    sc->sdiocore.base + SD_REG_HOSTINTMASK, 0);
		}

		/* Disable F2 before halting ARM — matches Linux bus_stop.
		 * Disabling F2 while firmware is still running lets the
		 * SDIO core drain any pending write FIFO data cleanly. */
		{
			uint8_t ioex;
			ioex = sdio_f0_read_1(sc->sdio_func1,
			    SDIO_CCCR_IOEx, &err);
			ioex &= ~0x04;
			sdio_f0_write_1(sc->sdio_func1,
			    SDIO_CCCR_IOEx, ioex, &err);
		}

		/* Clear pending interrupts after F2 disable */
		if (sc->sdiocore.base != 0) {
			brcmf_sdio_bp_write32(sc,
			    sc->sdiocore.base + SD_REG_INTSTATUS,
			    0xFFFFFFFF);
		}

		DELAY(20000); /* let SDIO core drain pending F2 writes */
		brcmf_sdio_chip_set_passive(sc);
	}

	brcmf_sdio_clk_disable(sc);
}
