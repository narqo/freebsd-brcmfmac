/*
 * brcmfmac - Broadcom FullMAC WiFi driver for FreeBSD
 *
 * LinuxKPI PCI driver registration, probe, and kernel interactions.
 * Complex kernel API usage stays in C; pure logic can be in Zig.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/module.h>

#include <linux/pci.h>
#include <linux/module.h>
#include <linux/io.h>

/* BCM4350 - MacBook Pro 2016 */
#define PCI_VENDOR_ID_BROADCOM	0x14e4
#define PCI_DEVICE_ID_BCM4350	0x43a3

/* SI_ENUM_BASE - chip enumeration base address */
#define SI_ENUM_BASE		0x18000000

/* BAR0 window register */
#define BRCMF_PCIE_BAR0_WINDOW	0x80

/* Zig functions */
struct brcmf_chipinfo {
	uint32_t chip;
	uint32_t chiprev;
	uint32_t socitype;
};

extern struct brcmf_chipinfo brcmf_parse_chipid(uint32_t regdata);
extern bool brcmf_chip_supported(uint32_t chip);
extern const char *brcmf_socitype_name(uint32_t socitype);

static int
brcmf_pcie_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	void __iomem *bar0;
	struct brcmf_chipinfo ci;
	uint32_t regdata;

	printf("brcmfmac: probing device %04x:%04x\n", pdev->vendor, pdev->device);

	if (pcim_enable_device(pdev) != 0) {
		printf("brcmfmac: pcim_enable_device failed\n");
		return (-ENXIO);
	}

	pci_set_master(pdev);

	bar0 = pcim_iomap(pdev, 0, 0);
	if (bar0 == NULL) {
		printf("brcmfmac: failed to map BAR0\n");
		return (-ENOMEM);
	}

	/* Set BAR0 window to ChipCommon core */
	pci_write_config_dword(pdev, BRCMF_PCIE_BAR0_WINDOW, SI_ENUM_BASE);

	/* Read chip ID register (offset 0 from SI_ENUM_BASE) */
	regdata = readl(bar0);
	if (regdata == 0xffffffff) {
		printf("brcmfmac: chip ID read failed\n");
		return (-EIO);
	}

	/* Parse chip info using Zig */
	ci = brcmf_parse_chipid(regdata);

	printf("brcmfmac: chip=%04x rev=%u socitype=%s\n",
	    ci.chip, ci.chiprev, brcmf_socitype_name(ci.socitype));

	if (!brcmf_chip_supported(ci.chip)) {
		printf("brcmfmac: unsupported chip\n");
		return (-ENODEV);
	}

	printf("brcmfmac: BCM4350 detected, probe successful\n");

	pci_set_drvdata(pdev, NULL);
	return (0);
}

static void
brcmf_pcie_remove(struct pci_dev *pdev)
{
	printf("brcmfmac: device removed\n");
}

static const struct pci_device_id brcmf_pcie_devid_table[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_BCM4350) },
	{ /* sentinel */ }
};
MODULE_DEVICE_TABLE(pci, brcmf_pcie_devid_table);

static struct pci_driver brcmf_pcie_driver = {
	.name = "brcmfmac",
	.id_table = brcmf_pcie_devid_table,
	.probe = brcmf_pcie_probe,
	.remove = brcmf_pcie_remove,
};

static int
brcmfmac_mod_event_handler(module_t mod, int cmd, void *arg)
{
	int error = 0;

	switch (cmd) {
	case MOD_LOAD:
		error = pci_register_driver(&brcmf_pcie_driver);
		break;
	case MOD_UNLOAD:
		pci_unregister_driver(&brcmf_pcie_driver);
		break;
	default:
		error = EOPNOTSUPP;
		break;
	}

	return (error);
}

static moduledata_t brcmfmac_mod = {
	"if_brcmfmac",
	brcmfmac_mod_event_handler,
	NULL
};

DECLARE_MODULE(if_brcmfmac, brcmfmac_mod, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);
MODULE_VERSION(if_brcmfmac, 1);
MODULE_DEPEND(if_brcmfmac, linuxkpi, 1, 1, 1);
MODULE_DEPEND(if_brcmfmac, linuxkpi_wlan, 1, 1, 1);
MODULE_DEPEND(if_brcmfmac, firmware, 1, 1, 1);
