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
	void *nvram;
	uint32_t nvram_len;
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
