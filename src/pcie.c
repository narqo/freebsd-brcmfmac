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

/* BCMA_RESET_CTL bits */
#define BCMA_RESET_CTL_RESET 0x0001

/* Core IDs */
#define BCMA_CORE_ARM_CR4 0x3e
#define BCMA_CORE_SOCRAM  0x1a

/* Firmware polling */
#define BRCMF_FW_READY_TIMEOUT_MS 2000
#define BRCMF_FW_READY_POLL_MS	  50

/* Firmware names */
#define BRCMF_FW_NAME	 "brcmfmac4350-pcie.bin"
#define BRCMF_FW_NAME_C2 "brcmfmac4350c2-pcie.bin"
#define BRCMF_NVRAM_NAME "brcmfmac4350-pcie.txt"

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

static void
brcmf_tcm_write32(struct brcmf_softc *sc, uint32_t off, uint32_t val)
{
	bus_space_write_4(sc->tcm_bst, sc->tcm_bsh, off, val);
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

	/* Find SOCRAM core */
	sc->ramcore = brcmf_find_core(erombase, brcmf_erom_read, sc,
	    BCMA_CORE_SOCRAM);
	if (sc->ramcore.id == 0) {
		device_printf(sc->dev, "SOCRAM core not found\n");
		return (ENODEV);
	}
	printf("brcmfmac: SOCRAM: id=0x%x rev=%u base=0x%x wrap=0x%x\n",
	    sc->ramcore.id, sc->ramcore.rev, sc->ramcore.base,
	    sc->ramcore.wrapbase);

	return (0);
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
 * Disable a core (put into reset)
 */
static void
brcmf_core_disable(struct brcmf_softc *sc, struct brcmf_coreinfo *core,
    uint32_t prereset, uint32_t reset)
{
	uint32_t val;

	if (brcmf_core_in_reset(sc, core)) {
		val = reset | BCMA_IOCTL_FGC | BCMA_IOCTL_CLK;
		brcmf_bp_write32(sc, core->wrapbase + BCMA_IOCTL, val);
		brcmf_bp_read32(sc, core->wrapbase + BCMA_IOCTL);
		return;
	}

	/* Disable clock */
	val = brcmf_bp_read32(sc, core->wrapbase + BCMA_IOCTL);
	val &= ~BCMA_IOCTL_CLK;
	val |= prereset;
	brcmf_bp_write32(sc, core->wrapbase + BCMA_IOCTL, val);
	brcmf_bp_read32(sc, core->wrapbase + BCMA_IOCTL);
	DELAY(10);

	/* Put into reset */
	brcmf_bp_write32(sc, core->wrapbase + BCMA_RESET_CTL,
	    BCMA_RESET_CTL_RESET);
	DELAY(1);

	/* Apply reset flags */
	val = reset | BCMA_IOCTL_FGC | BCMA_IOCTL_CLK;
	brcmf_bp_write32(sc, core->wrapbase + BCMA_IOCTL, val);
	brcmf_bp_read32(sc, core->wrapbase + BCMA_IOCTL);
	DELAY(10);
}

/*
 * Reset a core (bring out of reset)
 */
static void
brcmf_core_reset(struct brcmf_softc *sc, struct brcmf_coreinfo *core,
    uint32_t prereset, uint32_t reset, uint32_t postreset)
{
	uint32_t val;
	int i;

	brcmf_core_disable(sc, core, prereset, reset);

	for (i = 0; i < 10; i++) {
		brcmf_bp_write32(sc, core->wrapbase + BCMA_RESET_CTL, 0);
		val = brcmf_bp_read32(sc, core->wrapbase + BCMA_RESET_CTL);
		if ((val & BCMA_RESET_CTL_RESET) == 0)
			break;
		DELAY(40);
	}

	if (val & BCMA_RESET_CTL_RESET) {
		printf("brcmfmac: core 0x%x reset timeout\n", core->id);
		return;
	}

	val = postreset | BCMA_IOCTL_CLK;
	brcmf_bp_write32(sc, core->wrapbase + BCMA_IOCTL, val);
	brcmf_bp_read32(sc, core->wrapbase + BCMA_IOCTL);
	DELAY(1);
}

/*
 * Enter firmware download state: halt ARM core
 */
static int
brcmf_enter_download(struct brcmf_softc *sc)
{
	if (sc->armcore.wrapbase == 0) {
		device_printf(sc->dev, "no wrapper address for ARM core\n");
		return (EINVAL);
	}

	printf("brcmfmac: halting ARM at wrapper 0x%x\n", sc->armcore.wrapbase);

	brcmf_core_reset(sc, &sc->armcore, BCMA_IOCTL_CPUHALT,
	    BCMA_IOCTL_CPUHALT, BCMA_IOCTL_CPUHALT);

	return (0);
}

/*
 * Exit firmware download state: release ARM core
 */
static void
brcmf_exit_download(struct brcmf_softc *sc)
{
	uint32_t val;

	/* Write reset vector */
	printf("brcmfmac: writing reset vector 0x%x to TCM[0]\n", sc->ram_base);
	brcmf_tcm_write32(sc, 0, sc->ram_base);

	val = brcmf_tcm_read32(sc, 0);
	printf("brcmfmac: TCM[0] readback: 0x%x\n", val);

	if (sc->armcore.wrapbase == 0) {
		device_printf(sc->dev,
		    "no wrapper address, cannot release ARM\n");
		return;
	}

	brcmf_core_reset(sc, &sc->armcore, 0, 0, 0);
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
 * Download firmware to device
 */
static int
brcmf_download_fw(struct brcmf_softc *sc, const struct firmware *fw)
{
	uint32_t sharedaddr;
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

	error = brcmf_enter_download(sc);
	if (error != 0)
		return (error);

	/* Copy firmware to TCM */
	printf("brcmfmac: copying %zu bytes to TCM offset 0x%x\n", fw->datasize,
	    sc->ram_base);
	brcmf_tcm_copy(sc, sc->ram_base, fw->data, fw->datasize);

	/* Verify */
	{
		uint32_t v0 = brcmf_tcm_read32(sc, sc->ram_base);
		uint32_t v1 = brcmf_tcm_read32(sc, sc->ram_base + 4);
		printf("brcmfmac: TCM verify: [0]=0x%x [4]=0x%x\n", v0, v1);
	}

	/* Copy NVRAM */
	if (sc->nvram != NULL && sc->nvram_len > 0) {
		uint32_t nvram_addr = sc->ram_base + sc->ram_size - 4 -
		    sc->nvram_len;
		printf("brcmfmac: copying NVRAM (%u bytes) to offset 0x%x\n",
		    sc->nvram_len, nvram_addr);
		brcmf_tcm_copy(sc, nvram_addr, sc->nvram, sc->nvram_len);
	}

	/* Clear shared RAM address */
	brcmf_ram_write32(sc, sc->ram_size - 4, 0);

	brcmf_exit_download(sc);

	/* Poll for firmware ready */
	printf("brcmfmac: waiting for firmware to boot...\n");
	for (i = 0; i < BRCMF_FW_READY_TIMEOUT_MS / BRCMF_FW_READY_POLL_MS;
	    i++) {
		pause_sbt("brcmfw", mstosbt(BRCMF_FW_READY_POLL_MS), 0, 0);
		sharedaddr = brcmf_ram_read32(sc, sc->ram_size - 4);
		if (i < 5 || (i % 10 == 0))
			printf("brcmfmac: poll[%d]: sharedaddr=0x%x\n", i,
			    sharedaddr);
		if (sharedaddr != 0 && sharedaddr != 0xffffffff)
			break;
	}

	if (sharedaddr == 0 || sharedaddr == 0xffffffff) {
		uint32_t ioctl, resetctl, iost, tcm0, tcm4, tcmvec, chipid;

		pci_write_config(sc->dev, BRCMF_PCIE_BAR0_WINDOW, SI_ENUM_BASE,
		    4);
		brcmf_reg_read(sc, 0);
		chipid = brcmf_reg_read(sc, 0);
		printf("brcmfmac: chipid re-read: 0x%x\n", chipid);

		ioctl = brcmf_bp_read32(sc, sc->armcore.wrapbase + BCMA_IOCTL);
		resetctl = brcmf_bp_read32(sc,
		    sc->armcore.wrapbase + BCMA_RESET_CTL);
		iost = brcmf_bp_read32(sc, sc->armcore.wrapbase + BCMA_IOST);
		printf(
		    "brcmfmac: ARM wrap=0x%x ioctl=0x%x resetctl=0x%x iost=0x%x\n",
		    sc->armcore.wrapbase, ioctl, resetctl, iost);

		tcmvec = brcmf_tcm_read32(sc, 0);
		printf("brcmfmac: TCM[0] (reset vector): 0x%x\n", tcmvec);

		tcm0 = brcmf_tcm_read32(sc, sc->ram_base);
		tcm4 = brcmf_tcm_read32(sc, sc->ram_base + 4);
		printf("brcmfmac: TCM[ram_base]: [0]=0x%x [4]=0x%x\n", tcm0,
		    tcm4);

		device_printf(sc->dev,
		    "firmware boot timeout, sharedaddr=0x%x\n", sharedaddr);
		return (ETIMEDOUT);
	}

	printf("brcmfmac: firmware booted, sharedaddr=0x%x\n", sharedaddr);
	return (ENOTSUP); /* TODO: continue with msgbuf setup */
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

	fwname = (sc->chiprev >= 6) ? BRCMF_FW_NAME_C2 : BRCMF_FW_NAME;

	fw = firmware_get(fwname);
	if (fw == NULL) {
		device_printf(dev, "failed to load firmware %s\n", fwname);
		error = ENOENT;
		goto fail;
	}
	printf("brcmfmac: loaded firmware %s (%zu bytes)\n", fwname,
	    fw->datasize);

	/* Try to load NVRAM (optional) */
	nvram = firmware_get(BRCMF_NVRAM_NAME);
	if (nvram != NULL) {
		printf("brcmfmac: loaded NVRAM %s (%zu bytes)\n",
		    BRCMF_NVRAM_NAME, nvram->datasize);
		sc->nvram = brcmf_nvram_parse(nvram->data, nvram->datasize,
		    &sc->nvram_len);
		if (sc->nvram != NULL)
			printf("brcmfmac: parsed NVRAM: %u bytes\n",
			    sc->nvram_len);
		firmware_put(nvram, FIRMWARE_UNLOAD);
	} else {
		printf("brcmfmac: NVRAM %s not found, continuing without\n",
		    BRCMF_NVRAM_NAME);
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
