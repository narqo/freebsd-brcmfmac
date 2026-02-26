// SPDX-License-Identifier: ISC
/*
 * Copyright (c) 2010-2022 Broadcom Corporation
 * Copyright (c) brcmfmac-freebsd contributors
 *
 * Based on the Linux brcmfmac driver.
 */

/* Broadcom FullMAC WiFi driver for FreeBSD */

#ifndef _BRCMFMAC_H_
#define _BRCMFMAC_H_

#include <sys/types.h>
#include <sys/bus.h>
#include <sys/malloc.h>
#include <sys/socket.h>

#include <machine/bus.h>

#include <net/if.h>
#include <net/if_media.h>
#include <net/ethernet.h>

#include <net80211/ieee80211_var.h>

/* Ethernet address length */
#define ETHER_ADDR_LEN 6

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
	uint32_t console_addr;
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

/* TX buffer tracking */
#define BRCMF_TX_RING_SIZE	256

struct brcmf_txbuf {
	struct mbuf *m;
	bus_dmamap_t dma_map;
	bus_dma_tag_t dma_tag;
	bus_addr_t paddr;
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
	struct task isr_task;
	struct taskqueue *isr_tq;

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

	/* TX buffers */
	struct brcmf_txbuf txbuf[BRCMF_TX_RING_SIZE];
	uint32_t tx_pktid_next;
	struct brcmf_pcie_ringbuf *flowring;
	int flowring_create_done;
	int flowring_create_status;

	/* Request ID counter */
	uint16_t reqid;

	/* IOCTL state */
	struct mtx ioctl_mtx;
	uint16_t ioctl_trans_id;
	int ioctl_status;
	uint32_t ioctl_resp_len;
	int ioctl_completed;

	/* Firmware health */
	int fw_dead;
	int detaching;
	struct callout watchdog;

	/* Diagnostic counters */
	volatile uint32_t isr_filter_count;
	volatile uint32_t isr_task_count;

	/* net80211 */
	struct ieee80211com ic;
	uint8_t macaddr[ETHER_ADDR_LEN];
	int running;

	/* Scan state */
	uint16_t escan_sync_id;
	int scan_active;
	int scan_complete;
	struct task scan_task;

	/* Link state */
	int link_up;
	struct task link_task;
	struct task restart_task;
	uint8_t join_bssid[6];

	/* WPA PSK (set via sysctl) */
	char psk[65];
	int psk_len;
	struct sysctl_ctx_list sysctl_ctx;
	int cfg_attached;

	/* Tuning (sysctl) */
	int debug;

	/* Scan result cache */
#define BRCMF_SCAN_RESULTS_MAX	64
#define BRCMF_SCAN_IE_MAX	512
	struct brcmf_scan_result {
		uint8_t bssid[6];
		uint8_t ssid[32];
		uint8_t ssid_len;
		uint8_t chan;
		uint16_t chanspec;
		int16_t rssi;
		int8_t noise;
		uint16_t capinfo;
		uint16_t bintval;
		uint16_t ie_len;
		uint8_t ie[BRCMF_SCAN_IE_MAX];
	} scan_results[BRCMF_SCAN_RESULTS_MAX];
	int scan_nresults;
};

MALLOC_DECLARE(M_BRCMFMAC);

/* Debug print: emits when sc->debug >= 2 or bootverbose is set */
#define BRCMF_DBG_VERBOSE 2
#define BRCMF_DBG(sc, fmt, ...) do {					\
	if ((sc)->debug >= BRCMF_DBG_VERBOSE || bootverbose)		\
		device_printf((sc)->dev, fmt, ##__VA_ARGS__);		\
} while (0)

/* pcie.c - PCIe bus layer */
int brcmf_pcie_attach(device_t dev);
int brcmf_pcie_detach(device_t dev);

/* Bus access functions (used by other modules) */
uint32_t brcmf_reg_read(struct brcmf_softc *sc, uint32_t off);
void brcmf_reg_write(struct brcmf_softc *sc, uint32_t off, uint32_t val);
uint32_t brcmf_tcm_read32(struct brcmf_softc *sc, uint32_t off);
uint16_t brcmf_tcm_read16(struct brcmf_softc *sc, uint32_t off);
uint8_t brcmf_tcm_read8(struct brcmf_softc *sc, uint32_t off);
void brcmf_tcm_write32(struct brcmf_softc *sc, uint32_t off, uint32_t val);
void brcmf_tcm_write16(struct brcmf_softc *sc, uint32_t off, uint16_t val);
uint32_t brcmf_bp_read32(struct brcmf_softc *sc, uint32_t addr);
void brcmf_bp_write32(struct brcmf_softc *sc, uint32_t addr, uint32_t val);
void brcmf_pcie_select_core(struct brcmf_softc *sc, struct brcmf_coreinfo *core);
void brcmf_pcie_console_read(struct brcmf_softc *sc);

/* DMA helpers */
int brcmf_alloc_dma_buf(device_t dev, size_t size, bus_dma_tag_t *tag,
    bus_dmamap_t *map, void **buf, bus_addr_t *paddr);
void brcmf_free_dma_buf(bus_dma_tag_t tag, bus_dmamap_t map, void *buf);

/* core.c - Chip core management and firmware download */
int brcmf_chip_enumerate_cores(struct brcmf_softc *sc);
void brcmf_chip_reset(struct brcmf_softc *sc);
int brcmf_chip_enter_download(struct brcmf_softc *sc);
void brcmf_chip_exit_download(struct brcmf_softc *sc, uint32_t resetintr);

/* msgbuf.c - Message buffer protocol */
void brcmf_msgbuf_ring_doorbell(struct brcmf_softc *sc);
void *brcmf_msgbuf_ring_reserve(struct brcmf_softc *sc,
    struct brcmf_pcie_ringbuf *ring);
void brcmf_msgbuf_ring_submit(struct brcmf_softc *sc,
    struct brcmf_pcie_ringbuf *ring);
void brcmf_msgbuf_process_d2h(struct brcmf_softc *sc);
int brcmf_msgbuf_init(struct brcmf_softc *sc);
void brcmf_msgbuf_cleanup(struct brcmf_softc *sc);
int brcmf_msgbuf_ioctl(struct brcmf_softc *sc, uint32_t cmd,
    void *buf, uint32_t len, uint32_t *resp_len);
int brcmf_msgbuf_tx(struct brcmf_softc *sc, struct mbuf *m);
void brcmf_msgbuf_delete_flowring(struct brcmf_softc *sc);
int brcmf_msgbuf_init_flowring(struct brcmf_softc *sc, const uint8_t *da);


/* fwil.c - Firmware interface layer */
int brcmf_fil_cmd_data_set(struct brcmf_softc *sc, uint32_t cmd,
    const void *data, uint32_t len);
int brcmf_fil_cmd_data_get(struct brcmf_softc *sc, uint32_t cmd,
    void *data, uint32_t len);
int brcmf_fil_iovar_data_get(struct brcmf_softc *sc, const char *name,
    void *data, uint32_t len);
int brcmf_fil_iovar_data_set(struct brcmf_softc *sc, const char *name,
    const void *data, uint32_t len);
int brcmf_fil_iovar_int_set(struct brcmf_softc *sc, const char *name,
    uint32_t val);
int brcmf_fil_iovar_int_get(struct brcmf_softc *sc, const char *name,
    uint32_t *val);
int brcmf_fil_bss_up(struct brcmf_softc *sc);
int brcmf_fil_bss_down(struct brcmf_softc *sc);

/* cfg.c - net80211 interface */
int brcmf_cfg_attach(struct brcmf_softc *sc);
void brcmf_cfg_detach(struct brcmf_softc *sc);
void brcmf_escan_result(struct brcmf_softc *sc, void *data, uint32_t datalen);
void brcmf_link_event(struct brcmf_softc *sc, uint32_t event_code,
    uint32_t status, uint16_t flags);

/* Zig functions (brcmfmac.zig) */
struct brcmf_chipinfo brcmf_parse_chipid(uint32_t regdata);
bool brcmf_chip_supported(uint32_t chip);
const char *brcmf_socitype_name(uint32_t socitype);

typedef uint32_t (*brcmf_erom_read_fn)(void *ctx, uint32_t offset);
struct brcmf_coreinfo brcmf_find_core(uint32_t erom_base,
    brcmf_erom_read_fn read_fn, void *ctx, uint32_t target_coreid);

#endif /* _BRCMFMAC_H_ */
