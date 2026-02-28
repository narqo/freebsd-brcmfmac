// SPDX-License-Identifier: ISC
/*
 * Copyright (c) 2010-2022 Broadcom Corporation
 * Copyright (c) brcmfmac-freebsd contributors
 *
 * Based on the Linux brcmfmac driver.
 */

/* PCIe bus layer: BAR mapping, DMA, ring allocation, interrupts, firmware load */

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

/* PCIe BAR0 register offsets */
#define BRCMF_PCIE_PCIE2REG_INTMASK	   0x24
#define BRCMF_PCIE_PCIE2REG_MAILBOXINT	   0x48
#define BRCMF_PCIE_PCIE2REG_MAILBOXMASK	   0x4C
#define BRCMF_PCIE_PCIE2REG_CONFIGADDR	   0x120
#define BRCMF_PCIE_PCIE2REG_CONFIGDATA	   0x124
#define BRCMF_PCIE_PCIE2REG_H2D_MAILBOX_1  0x144

/* Shared RAM structure offsets */
#define BRCMF_PCIE_SHARED_VERSION_MASK	      0x00FF
#define BRCMF_PCIE_MIN_SHARED_VERSION	      5
#define BRCMF_PCIE_MAX_SHARED_VERSION	      7
#define BRCMF_PCIE_SHARED_DMA_INDEX	      0x10000
#define BRCMF_PCIE_SHARED_DMA_2B_IDX	      0x100000
#define BRCMF_PCIE_SHARED_HOSTRDY_DB1	      0x10000000

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

#define BRCMF_SHARED_CONSOLE_ADDR_OFFSET      20
#define BRCMF_CONSOLE_BUFADDR_OFFSET          8
#define BRCMF_CONSOLE_BUFSIZE_OFFSET          12
#define BRCMF_CONSOLE_WRITEIDX_OFFSET         16

/* Ring info structure offsets */
#define BRCMF_RING_RINGMEM_OFFSET	 0
#define BRCMF_RING_H2D_W_IDX_PTR_OFFSET	 4
#define BRCMF_RING_H2D_R_IDX_PTR_OFFSET	 8
#define BRCMF_RING_D2H_W_IDX_PTR_OFFSET	 12
#define BRCMF_RING_D2H_R_IDX_PTR_OFFSET	 16
#define BRCMF_RING_H2D_W_HOSTADDR_OFFSET 20
#define BRCMF_RING_H2D_R_HOSTADDR_OFFSET 28
#define BRCMF_RING_D2H_W_HOSTADDR_OFFSET 36
#define BRCMF_RING_D2H_R_HOSTADDR_OFFSET 44
#define BRCMF_RING_MAX_FLOWRINGS_OFFSET	 52
#define BRCMF_RING_MAX_SUBMISSION_OFFSET 54
#define BRCMF_RING_MAX_COMPLETION_OFFSET 56

/* Ring memory descriptor offsets */
#define BRCMF_RING_MEM_BASE_ADDR_OFFSET	8
#define BRCMF_RING_MAX_ITEM_OFFSET	4
#define BRCMF_RING_LEN_ITEMS_OFFSET	6
#define BRCMF_RING_MEM_SZ		16

/* Ring sizes */
#define BRCMF_H2D_MSGRING_CONTROL_SUBMIT_MAX_ITEM   64
#define BRCMF_H2D_MSGRING_RXPOST_SUBMIT_MAX_ITEM    1024
#define BRCMF_D2H_MSGRING_CONTROL_COMPLETE_MAX_ITEM 64
#define BRCMF_D2H_MSGRING_TX_COMPLETE_MAX_ITEM	    1024
#define BRCMF_D2H_MSGRING_RX_COMPLETE_MAX_ITEM	    1024

/* Ring item sizes */
#define BRCMF_H2D_MSGRING_CONTROL_SUBMIT_ITEMSIZE     40
#define BRCMF_H2D_MSGRING_RXPOST_SUBMIT_ITEMSIZE      32
#define BRCMF_D2H_MSGRING_CONTROL_COMPLETE_ITEMSIZE   24
#define BRCMF_D2H_MSGRING_TX_COMPLETE_ITEMSIZE_PRE_V7 16
#define BRCMF_D2H_MSGRING_RX_COMPLETE_ITEMSIZE_PRE_V7 32
#define BRCMF_D2H_MSGRING_TX_COMPLETE_ITEMSIZE	      24
#define BRCMF_D2H_MSGRING_RX_COMPLETE_ITEMSIZE	      40

/* DMA buffer sizes */
#define BRCMF_DMA_D2H_SCRATCH_BUF_LEN  8
#define BRCMF_DMA_D2H_RINGUPD_BUF_LEN  1024

/* Interrupt bits */
#define BRCMF_PCIE_MB_INT_D2H_DB \
	(0x10000 | 0x20000 | 0x40000 | 0x80000 | \
	 0x100000 | 0x200000 | 0x400000 | 0x800000)
#define BRCMF_PCIE_MB_INT_FN0 (0x0100 | 0x0200)

/* Mailbox data bits */
#define BRCMF_D2H_DEV_FWHALT 0x10000000

/* Firmware polling */
#define BRCMF_FW_READY_TIMEOUT_MS 5000
#define BRCMF_FW_READY_POLL_MS	  50

/* Firmware names */
#define BRCMF_FW_NAME	    "brcmfmac4350-pcie.bin"
#define BRCMF_FW_NAME_C2    "brcmfmac4350c2-pcie.bin"
#define BRCMF_NVRAM_NAME    "brcmfmac4350-pcie.txt"
#define BRCMF_NVRAM_NAME_C2 "brcmfmac4350c2-pcie.txt"

/*
 * BAR0 register access
 */
uint32_t
brcmf_reg_read(struct brcmf_softc *sc, uint32_t off)
{
	return (bus_space_read_4(sc->reg_bst, sc->reg_bsh, off));
}

void
brcmf_reg_write(struct brcmf_softc *sc, uint32_t off, uint32_t val)
{
	bus_space_write_4(sc->reg_bst, sc->reg_bsh, off, val);
}

/*
 * TCM (BAR2) access
 */
uint32_t
brcmf_tcm_read32(struct brcmf_softc *sc, uint32_t off)
{
	return (bus_space_read_4(sc->tcm_bst, sc->tcm_bsh, off));
}

uint8_t
brcmf_tcm_read8(struct brcmf_softc *sc, uint32_t off)
{
	return (bus_space_read_1(sc->tcm_bst, sc->tcm_bsh, off));
}

uint16_t
brcmf_tcm_read16(struct brcmf_softc *sc, uint32_t off)
{
	return (bus_space_read_2(sc->tcm_bst, sc->tcm_bsh, off));
}

void
brcmf_tcm_write16(struct brcmf_softc *sc, uint32_t off, uint16_t val)
{
	bus_space_write_2(sc->tcm_bst, sc->tcm_bsh, off, val);
}

void
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
 */
uint32_t
brcmf_bp_read32(struct brcmf_softc *sc, uint32_t addr)
{
	uint32_t window = addr & 0xfffff000;
	uint32_t offset = addr & 0x00000fff;

	pci_write_config(sc->dev, BRCMF_PCIE_BAR0_WINDOW, window, 4);
	brcmf_reg_read(sc, 0);

	return (brcmf_reg_read(sc, offset));
}

void
brcmf_bp_write32(struct brcmf_softc *sc, uint32_t addr, uint32_t val)
{
	uint32_t window = addr & 0xfffff000;
	uint32_t offset = addr & 0x00000fff;

	pci_write_config(sc->dev, BRCMF_PCIE_BAR0_WINDOW, window, 4);
	brcmf_reg_read(sc, 0);

	brcmf_reg_write(sc, offset, val);
	brcmf_reg_read(sc, 0);
}

/*
 * Select a core by setting BAR0 window to its base address.
 */
void
brcmf_pcie_select_core(struct brcmf_softc *sc, struct brcmf_coreinfo *core)
{
	pci_write_config(sc->dev, BRCMF_PCIE_BAR0_WINDOW, core->base, 4);
	brcmf_reg_read(sc, 0);
}

/*
 * DMA callback to get physical address.
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
int
brcmf_alloc_dma_buf(device_t dev, size_t size, bus_dma_tag_t *tag,
    bus_dmamap_t *map, void **buf, bus_addr_t *paddr)
{
	int error;

	error = bus_dma_tag_create(bus_get_dma_tag(dev),
	    4, 0,
	    BUS_SPACE_MAXADDR,
	    BUS_SPACE_MAXADDR,
	    NULL, NULL,
	    size, 1, size,
	    BUS_DMA_COHERENT,
	    NULL, NULL,
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
void
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

	desc_addr = ringmem_addr + id * BRCMF_RING_MEM_SZ;

	brcmf_tcm_write16(sc, desc_addr + BRCMF_RING_MAX_ITEM_OFFSET, depth);
	brcmf_tcm_write16(sc, desc_addr + BRCMF_RING_LEN_ITEMS_OFFSET, item_len);
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

	BRCMF_DBG(sc, "ringinfo: max_flowrings=%d max_sub=%d max_cmp=%d\n",
	    sc->max_flowrings, sc->max_submissionrings, sc->max_completionrings);
	BRCMF_DBG(sc, "ringinfo: ringmem=0x%x h2d_w=0x%x h2d_r=0x%x d2h_w=0x%x d2h_r=0x%x\n",
	    sc->ringmem_addr, sc->h2d_w_idx_addr, sc->h2d_r_idx_addr,
	    sc->d2h_w_idx_addr, sc->d2h_r_idx_addr);

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

	addr = sc->shared.ring_info_addr;
	dma64 = sc->idx_buf_dma;

	brcmf_tcm_write64(sc, addr + BRCMF_RING_H2D_W_HOSTADDR_OFFSET, dma64);
	dma64 += sc->max_submissionrings * sc->shared.dma_idx_sz;

	brcmf_tcm_write64(sc, addr + BRCMF_RING_H2D_R_HOSTADDR_OFFSET, dma64);
	dma64 += sc->max_submissionrings * sc->shared.dma_idx_sz;

	brcmf_tcm_write64(sc, addr + BRCMF_RING_D2H_W_HOSTADDR_OFFSET, dma64);
	dma64 += sc->max_completionrings * sc->shared.dma_idx_sz;

	brcmf_tcm_write64(sc, addr + BRCMF_RING_D2H_R_HOSTADDR_OFFSET, dma64);

	return (0);
}

/*
 * Allocate scratch and ring update DMA buffers.
 */
static int
brcmf_pcie_alloc_scratch_buffers(struct brcmf_softc *sc)
{
	uint32_t addr;
	int error;

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

	return (0);
}

/*
 * Allocate common rings.
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

		if (i < BRCMF_NROF_H2D_COMMON_MSGRINGS) {
			sc->commonrings[i]->w_idx_addr = sc->h2d_w_idx_addr +
			    i * sizeof(uint32_t);
			sc->commonrings[i]->r_idx_addr = sc->h2d_r_idx_addr +
			    i * sizeof(uint32_t);
		} else {
			int d2h_idx = i - BRCMF_NROF_H2D_COMMON_MSGRINGS;
			sc->commonrings[i]->w_idx_addr = sc->d2h_w_idx_addr +
			    d2h_idx * sizeof(uint32_t);
			sc->commonrings[i]->r_idx_addr = sc->d2h_r_idx_addr +
			    d2h_idx * sizeof(uint32_t);
		}

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

	/* Linux driver order: common rings first, then scratch buffers */
	error = brcmf_pcie_alloc_common_rings(sc);
	if (error != 0)
		return (error);

	error = brcmf_pcie_alloc_scratch_buffers(sc);
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
 * Enable/disable interrupts.
 */
static void
brcmf_pcie_intr_enable(struct brcmf_softc *sc)
{
	brcmf_pcie_select_core(sc, &sc->pciecore);
	brcmf_reg_write(sc, BRCMF_PCIE_PCIE2REG_MAILBOXMASK,
	    BRCMF_PCIE_MB_INT_D2H_DB | BRCMF_PCIE_MB_INT_FN0);
}

static void
brcmf_pcie_intr_disable(struct brcmf_softc *sc)
{
	brcmf_pcie_select_core(sc, &sc->pciecore);
	brcmf_reg_write(sc, BRCMF_PCIE_PCIE2REG_MAILBOXMASK, 0);
}

/*
 * Handle mailbox data from firmware.
 */
static void
brcmf_pcie_handle_mb_data(struct brcmf_softc *sc)
{
	uint32_t dtoh_mb;

	dtoh_mb = brcmf_tcm_read32(sc, sc->shared.dtoh_mb_data_addr);
	if (dtoh_mb == 0)
		return;

	brcmf_tcm_write32(sc, sc->shared.dtoh_mb_data_addr, 0);

	if (dtoh_mb & BRCMF_D2H_DEV_FWHALT)
		device_printf(sc->dev, "firmware halted\n");
}

/*
 * Interrupt handler.
 */
static int
brcmf_pcie_isr_filter(void *arg)
{
	struct brcmf_softc *sc = arg;
	uint32_t status;

	brcmf_pcie_select_core(sc, &sc->pciecore);
	status = brcmf_reg_read(sc, BRCMF_PCIE_PCIE2REG_MAILBOXINT);
	if (status == 0 || status == 0xffffffff)
		return (FILTER_STRAY);

	/* Ack and disable further interrupts until task runs */
	brcmf_reg_write(sc, BRCMF_PCIE_PCIE2REG_MAILBOXINT, status);
	brcmf_pcie_intr_disable(sc);

	sc->isr_filter_count++;
	taskqueue_enqueue(sc->isr_tq, &sc->isr_task);

	return (FILTER_HANDLED);
}

static void
brcmf_pcie_isr_task(void *arg, int pending)
{
	struct brcmf_softc *sc = arg;
	uint32_t status;

	/* Re-read in case new events arrived between filter and task */
	brcmf_pcie_select_core(sc, &sc->pciecore);
	status = brcmf_reg_read(sc, BRCMF_PCIE_PCIE2REG_MAILBOXINT);
	if (status != 0 && status != 0xffffffff)
		brcmf_reg_write(sc, BRCMF_PCIE_PCIE2REG_MAILBOXINT, status);

	sc->isr_task_count++;

	if (status & BRCMF_PCIE_MB_INT_FN0)
		brcmf_pcie_handle_mb_data(sc);

	brcmf_msgbuf_process_d2h(sc);

	brcmf_pcie_intr_enable(sc);
}

/*
 * Set up MSI interrupt.
 */
static int
brcmf_pcie_setup_irq(struct brcmf_softc *sc)
{
	int count, error;

	count = 1;
	if (pci_alloc_msi(sc->dev, &count) != 0) {
		device_printf(sc->dev, "failed to allocate MSI\n");
		return (ENXIO);
	}

	sc->irq_rid = 1;
	sc->irq_res = bus_alloc_resource_any(sc->dev, SYS_RES_IRQ,
	    &sc->irq_rid, RF_ACTIVE);
	if (sc->irq_res == NULL) {
		device_printf(sc->dev, "failed to allocate IRQ resource\n");
		pci_release_msi(sc->dev);
		return (ENXIO);
	}

	TASK_INIT(&sc->isr_task, 0, brcmf_pcie_isr_task, sc);
	sc->isr_tq = taskqueue_create("brcmfmac_isr", M_WAITOK,
	    taskqueue_thread_enqueue, &sc->isr_tq);
	taskqueue_start_threads(&sc->isr_tq, 1, PI_NET, "%s isr",
	    device_get_nameunit(sc->dev));

	error = bus_setup_intr(sc->dev, sc->irq_res,
	    INTR_TYPE_NET | INTR_MPSAFE, brcmf_pcie_isr_filter, NULL, sc,
	    &sc->irq_handle);
	if (error != 0) {
		device_printf(sc->dev, "failed to setup interrupt: %d\n",
		    error);
		bus_release_resource(sc->dev, SYS_RES_IRQ, sc->irq_rid,
		    sc->irq_res);
		pci_release_msi(sc->dev);
		return (error);
	}

	return (0);
}

/*
 * Periodic check for device liveness.
 */
static void
brcmf_watchdog(void *arg)
{
	struct brcmf_softc *sc = arg;
	uint32_t val, mask;

	if (sc->fw_dead || sc->detaching)
		return;

	/* D2H poll: process completions that interrupts may have missed */
	brcmf_msgbuf_process_d2h(sc);

	/* Re-enable interrupts if stuck disabled */
	brcmf_pcie_select_core(sc, &sc->pciecore);
	mask = brcmf_reg_read(sc, BRCMF_PCIE_PCIE2REG_MAILBOXMASK);
	if (mask == 0)
		brcmf_pcie_intr_enable(sc);

	/* Every 500th tick (~5s): check chip liveness and firmware stalls */
	sc->watchdog_tick++;
	if (sc->watchdog_tick >= 500) {
		sc->watchdog_tick = 0;

		val = brcmf_reg_read(sc, BRCMF_PCIE_PCIE2REG_MAILBOXINT);
		if (val == 0xffffffff) {
			device_printf(sc->dev,
			    "device not responding, marking dead\n");
			sc->fw_dead = 1;
			wakeup(&sc->ioctl_completed);
			wakeup(&sc->flowring_create_done);
			return;
		}

		if (!sc->ioctl_completed && sc->ioctl_trans_id > 0) {
			if (sc->isr_task_count == sc->watchdog_last_isr) {
				sc->watchdog_stall_count++;
				if (sc->watchdog_stall_count >= 2) {
					device_printf(sc->dev,
					    "firmware not processing rings, "
					    "marking dead (isr_task=%u)\n",
					    sc->isr_task_count);
					sc->fw_dead = 1;
					wakeup(&sc->ioctl_completed);
					wakeup(&sc->flowring_create_done);
					return;
				}
			} else {
				sc->watchdog_stall_count = 0;
			}
		} else {
			sc->watchdog_stall_count = 0;
		}
		sc->watchdog_last_isr = sc->isr_task_count;
	}

	callout_reset(&sc->watchdog, hz / 100, brcmf_watchdog, sc);
}

/*
 * Tear down MSI interrupt.
 */
static void
brcmf_pcie_free_irq(struct brcmf_softc *sc)
{
	callout_drain(&sc->watchdog);
	if (sc->irq_handle != NULL) {
		brcmf_pcie_intr_disable(sc);
		bus_teardown_intr(sc->dev, sc->irq_res, sc->irq_handle);
		sc->irq_handle = NULL;
	}
	if (sc->isr_tq != NULL) {
		taskqueue_drain(sc->isr_tq, &sc->isr_task);
		taskqueue_free(sc->isr_tq);
		sc->isr_tq = NULL;
	}
	if (sc->irq_res != NULL) {
		bus_release_resource(sc->dev, SYS_RES_IRQ, sc->irq_rid,
		    sc->irq_res);
		sc->irq_res = NULL;
	}
	pci_release_msi(sc->dev);
}

/*
 * Parse NVRAM text into binary format.
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
#define BRCMF_RAMSIZE_MAGIC  0x534d4152
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

	addr = sharedram_addr + BRCMF_SHARED_CONSOLE_ADDR_OFFSET;
	shared->console_addr = brcmf_tcm_read32(sc, addr);

	addr = sharedram_addr + BRCMF_SHARED_RING_INFO_ADDR_OFFSET;
	shared->ring_info_addr = brcmf_tcm_read32(sc, addr);

	BRCMF_DBG(sc, "shared: version=%d flags=0x%x max_rxbufpost=%d rx_dataoffset=%d\n",
	    shared->version, shared->flags, shared->max_rxbufpost, shared->rx_dataoffset);

	return (0);
}

/*
 * Signal host ready to firmware.
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
 * Download firmware to device.
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

	error = brcmf_chip_enumerate_cores(sc);
	if (error != 0)
		return (error);

	brcmf_pcie_adjust_ramsize(sc, fw->data, fw->datasize);

	brcmf_chip_reset(sc);

	brcmf_pcie_select_core(sc, &sc->pciecore);
	brcmf_reg_write(sc, BRCMF_PCIE_PCIE2REG_CONFIGADDR, 0x4e0);
	{
		uint32_t barconfig;
		barconfig = brcmf_reg_read(sc, BRCMF_PCIE_PCIE2REG_CONFIGDATA);
		brcmf_reg_write(sc, BRCMF_PCIE_PCIE2REG_CONFIGDATA, barconfig);
	}

	error = brcmf_chip_enter_download(sc);
	if (error != 0)
		return (error);

	resetintr = *(const uint32_t *)fw->data;
	brcmf_tcm_copy(sc, sc->ram_base, fw->data, fw->datasize);

	brcmf_ram_write32(sc, sc->ram_size - 4, 0);

	if (sc->nvram != NULL && sc->nvram_len > 0) {
		uint32_t nvram_addr = sc->ram_base + sc->ram_size -
		    sc->nvram_len;
		brcmf_tcm_copy(sc, nvram_addr, sc->nvram, sc->nvram_len);
	}

	sharedaddr_written = brcmf_ram_read32(sc, sc->ram_size - 4);

	brcmf_chip_exit_download(sc, resetintr);

	sharedaddr = sharedaddr_written;
	for (i = 0; i < BRCMF_FW_READY_TIMEOUT_MS / BRCMF_FW_READY_POLL_MS;
	    i++) {
		pause_sbt("brcmfw", mstosbt(BRCMF_FW_READY_POLL_MS), 0, 0);
		sharedaddr = brcmf_ram_read32(sc, sc->ram_size - 4);
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

	error = brcmf_pcie_init_shared(sc, sharedaddr);
	if (error != 0)
		return (error);

	error = brcmf_pcie_setup_rings(sc);
	if (error != 0)
		return (error);

	brcmf_pcie_hostready(sc);

	error = brcmf_pcie_setup_irq(sc);
	if (error != 0)
		return (error);

	error = brcmf_msgbuf_init(sc);
	if (error != 0)
		return (error);

	brcmf_pcie_intr_enable(sc);

	callout_reset(&sc->watchdog, hz / 100, brcmf_watchdog, sc);

	/* Get firmware version */
	{
		char ver[256]; /* generous for a version string */
		memset(ver, 0, sizeof(ver));
		error = brcmf_fil_iovar_data_get(sc, "ver", ver,
		    sizeof(ver) - 1);
		if (error == 0) {
			char *nl = strchr(ver, '\n');
			if (nl)
				*nl = '\0';
			device_printf(sc->dev, "firmware: %s\n", ver);
		}
	}

	/* Disable MPC during init */
	brcmf_fil_iovar_int_set(sc, "mpc", 0);

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

	sc->reg_rid = PCIR_BAR(0);
	sc->reg_res = bus_alloc_resource_any(dev, SYS_RES_MEMORY, &sc->reg_rid,
	    RF_ACTIVE);
	if (sc->reg_res == NULL) {
		device_printf(dev, "failed to map BAR0\n");
		return (ENXIO);
	}
	sc->reg_bst = rman_get_bustag(sc->reg_res);
	sc->reg_bsh = rman_get_bushandle(sc->reg_res);

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

	pci_write_config(dev, BRCMF_PCIE_BAR0_WINDOW, SI_ENUM_BASE, 4);
	callout_init(&sc->watchdog, 1);
	mtx_init(&sc->ioctl_mtx, "brcmfmac_ioctl", NULL, MTX_DEF);

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

	BRCMF_DBG(sc, "ram_base=0x%x ram_size=0x%x (%uKB)\n", sc->ram_base,
	    sc->ram_size, sc->ram_size / 1024);

	fwname = (sc->chiprev <= 7) ? BRCMF_FW_NAME_C2 : BRCMF_FW_NAME;

	fw = firmware_get(fwname);
	if (fw == NULL) {
		device_printf(dev, "failed to load firmware %s\n", fwname);
		error = ENOENT;
		goto fail;
	}
	device_printf(sc->dev, "loaded firmware %s (%zu bytes)\n", fwname,
	    fw->datasize);

	{
		const char *nvname;
		nvname = (sc->chiprev <= 7) ? BRCMF_NVRAM_NAME_C2 :
		    BRCMF_NVRAM_NAME;
		nvram = firmware_get(nvname);
		if (nvram != NULL) {
			sc->nvram = brcmf_nvram_parse(nvram->data,
			    nvram->datasize, &sc->nvram_len);
			firmware_put(nvram, FIRMWARE_UNLOAD);
		}
	}

	error = brcmf_download_fw(sc, fw);
	firmware_put(fw, FIRMWARE_UNLOAD);

	if (error != 0)
		goto fail;

	error = brcmf_cfg_attach(sc);
	if (error != 0)
		goto fail;

	return (0);

fail:
	brcmf_pcie_detach(dev);
	return (error);
}

void
brcmf_pcie_console_read(struct brcmf_softc *sc)
{
	uint32_t console_addr = sc->shared.console_addr;
	uint32_t buf_addr, bufsize, writeidx;
	char line[256];
	int pos = 0;
	uint32_t readidx, count;

	if (console_addr == 0) {
		device_printf(sc->dev, "  fwcon: no console address\n");
		return;
	}

	buf_addr = brcmf_tcm_read32(sc,
	    console_addr + BRCMF_CONSOLE_BUFADDR_OFFSET);
	bufsize = brcmf_tcm_read32(sc,
	    console_addr + BRCMF_CONSOLE_BUFSIZE_OFFSET);
	writeidx = brcmf_tcm_read32(sc,
	    console_addr + BRCMF_CONSOLE_WRITEIDX_OFFSET);

	device_printf(sc->dev,
	    "  fwcon: addr=0x%x buf=0x%x size=%u widx=%u\n",
	    console_addr, buf_addr, bufsize, writeidx);

	if (bufsize == 0 || bufsize > 0x100000 || buf_addr == 0)
		return;

	/* Dump the last 512 bytes (or less if buffer is smaller) */
	count = bufsize < 512 ? bufsize : 512;
	if (writeidx < count)
		readidx = bufsize - (count - writeidx);
	else
		readidx = writeidx - count;

	while (readidx != writeidx) {
		char ch = brcmf_tcm_read8(sc, buf_addr + readidx);
		if (ch == '\n' || pos >= (int)sizeof(line) - 1) {
			line[pos] = '\0';
			if (pos > 0)
				device_printf(sc->dev, "  fwcon: %s\n", line);
			pos = 0;
		} else if (ch >= ' ' && ch <= '~') {
			line[pos++] = ch;
		}
		readidx++;
		if (readidx >= bufsize)
			readidx = 0;
	}
	if (pos > 0) {
		line[pos] = '\0';
		device_printf(sc->dev, "  fwcon: %s\n", line);
	}
}

int
brcmf_pcie_detach(device_t dev)
{
	struct brcmf_softc *sc;

	sc = device_get_softc(dev);

	/*
	 * Mark dead and detaching before cfg_detach. This causes any
	 * inflight or newly-enqueued callbacks (link_task, key_delete,
	 * state transitions) to skip firmware ioctls and return
	 * immediately rather than sleeping on a dead firmware.
	 */
	sc->detaching = 1;
	sc->fw_dead = 1;
	wakeup(&sc->ioctl_completed);
	wakeup(&sc->flowring_create_done);

	brcmf_cfg_detach(sc);
	brcmf_pcie_free_irq(sc);
	brcmf_msgbuf_cleanup(sc);
	brcmf_pcie_free_rings(sc);
	mtx_destroy(&sc->ioctl_mtx);

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
