#ifndef _BRCMFMAC_H_
#define _BRCMFMAC_H_

#include <sys/types.h>
#include <sys/bus.h>

#include <machine/bus.h>

/* PCI IDs */
#define PCI_VENDOR_BROADCOM 0x14e4
#define PCI_DEVICE_BCM4350  0x43a3

/* Device ID table entry */
struct brcmf_pci_id {
	uint16_t vendor;
	uint16_t device;
	const char *desc;
};

/* Core info from EROM */
struct brcmf_coreinfo {
	uint32_t id;
	uint32_t rev;
	uint32_t base;
	uint32_t wrapbase;
};

/* Chip info from ID register */
struct brcmf_chipinfo {
	uint32_t chip;
	uint32_t chiprev;
	uint32_t socitype;
};

/* Shared RAM info parsed from firmware */
struct brcmf_pcie_shared_info {
	uint32_t tcm_base_address;
	uint32_t flags;
	uint8_t  version;
	uint16_t max_rxbufpost;
	uint32_t rx_dataoffset;
	uint32_t htod_mb_data_addr;
	uint32_t dtoh_mb_data_addr;
	uint32_t ring_info_addr;
	uint32_t dma_idx_sz;
};

/* Ring IDs */
#define BRCMF_H2D_MSGRING_CONTROL_SUBMIT   0
#define BRCMF_H2D_MSGRING_RXPOST_SUBMIT    1
#define BRCMF_D2H_MSGRING_CONTROL_COMPLETE 2
#define BRCMF_D2H_MSGRING_TX_COMPLETE      3
#define BRCMF_D2H_MSGRING_RX_COMPLETE      4
#define BRCMF_NROF_H2D_COMMON_MSGRINGS     2
#define BRCMF_NROF_D2H_COMMON_MSGRINGS     3
#define BRCMF_NROF_COMMON_MSGRINGS         5

/* Ring buffer */
struct brcmf_pcie_ringbuf {
	void *buf;		  /* DMA buffer virtual address */
	bus_addr_t dma_handle;	  /* DMA buffer physical address */
	bus_dma_tag_t dma_tag;
	bus_dmamap_t dma_map;
	uint32_t w_idx_addr;	  /* TCM offset for write index */
	uint32_t r_idx_addr;	  /* TCM offset for read index */
	uint16_t w_ptr;		  /* local write pointer */
	uint16_t r_ptr;		  /* local read pointer */
	uint16_t id;
	uint16_t depth;		  /* max items */
	uint16_t item_len;	  /* bytes per item */
};

/* Control buffer tracking */
struct brcmf_ctrlbuf {
	void *buf;
	bus_addr_t paddr;
	bus_dma_tag_t dma_tag;
	bus_dmamap_t dma_map;
	uint32_t pktid;
};

/* Per-device softc */
struct brcmf_softc {
	device_t dev;
	struct resource *reg_res; /* BAR0 */
	struct resource *tcm_res; /* BAR2 (TCM) */
	int reg_rid;
	int tcm_rid;
	bus_space_tag_t reg_bst;
	bus_space_handle_t reg_bsh;
	bus_space_tag_t tcm_bst;
	bus_space_handle_t tcm_bsh;
	uint32_t chip;
	uint32_t chiprev;
	uint32_t ram_base;
	uint32_t ram_size;
	struct brcmf_coreinfo armcore;
	struct brcmf_coreinfo ramcore;
	struct brcmf_coreinfo d11core;
	struct brcmf_coreinfo pciecore;
	struct brcmf_pcie_shared_info shared;
	void *nvram;
	uint32_t nvram_len;

	/* Ring info from firmware */
	uint32_t ringmem_addr;	  /* TCM address of ring memory descriptors */
	uint32_t h2d_w_idx_addr;  /* TCM address of H2D write indices */
	uint32_t h2d_r_idx_addr;  /* TCM address of H2D read indices */
	uint32_t d2h_w_idx_addr;  /* TCM address of D2H write indices */
	uint32_t d2h_r_idx_addr;  /* TCM address of D2H read indices */
	uint16_t max_flowrings;
	uint16_t max_submissionrings;
	uint16_t max_completionrings;

	/* Common rings */
	struct brcmf_pcie_ringbuf *commonrings[BRCMF_NROF_COMMON_MSGRINGS];

	/* DMA index buffers (when DMA_INDEX flag is set) */
	void *idx_buf;
	bus_addr_t idx_buf_dma;
	bus_dma_tag_t idx_dma_tag;
	bus_dmamap_t idx_dma_map;
	uint32_t idx_buf_sz;

	/* Scratch and ring update buffers */
	void *scratch_buf;
	bus_addr_t scratch_dma;
	bus_dma_tag_t scratch_dma_tag;
	bus_dmamap_t scratch_dma_map;

	void *ringupd_buf;
	bus_addr_t ringupd_dma;
	bus_dma_tag_t ringupd_dma_tag;
	bus_dmamap_t ringupd_dma_map;

	/* Interrupt */
	struct resource *irq_res;
	int irq_rid;
	void *irq_handle;

	/* IOCTL buffer */
	void *ioctlbuf;
	bus_addr_t ioctlbuf_dma;
	bus_dma_tag_t ioctlbuf_dma_tag;
	bus_dmamap_t ioctlbuf_dma_map;

	/* Control response/event buffers */
	struct brcmf_ctrlbuf *ioctlresp_buf;
	struct brcmf_ctrlbuf *event_buf;
	uint32_t cur_ioctlrespbuf;
	uint32_t cur_eventbuf;

	/* RX data buffers */
	struct brcmf_ctrlbuf *rxbuf;
	uint32_t rxbufpost;

	/* Request ID counter */
	uint16_t reqid;

	/* IOCTL state */
	uint16_t ioctl_trans_id;
	int ioctl_status;
	uint32_t ioctl_resp_len;
	int ioctl_completed;
};

/* PCIe bus functions */
int brcmf_pcie_attach(device_t dev);
int brcmf_pcie_detach(device_t dev);

/* Zig functions */
struct brcmf_chipinfo brcmf_parse_chipid(uint32_t regdata);
bool brcmf_chip_supported(uint32_t chip);
const char *brcmf_socitype_name(uint32_t socitype);

typedef uint32_t (*brcmf_erom_read_fn)(void *ctx, uint32_t offset);
struct brcmf_coreinfo brcmf_find_core(uint32_t erom_base,
    brcmf_erom_read_fn read_fn, void *ctx, uint32_t target_coreid);

#endif /* _BRCMFMAC_H_ */
