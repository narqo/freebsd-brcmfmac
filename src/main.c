// SPDX-License-Identifier: ISC
/*
 * Copyright (c) 2010-2022 Broadcom Corporation
 * Copyright (c) brcmfmac-freebsd contributors
 *
 * Based on the Linux brcmfmac driver.
 */

/*
 * brcmfmac - Broadcom FullMAC WiFi driver for FreeBSD
 */

#include <sys/param.h>
#include <sys/bus.h>
#include <sys/kernel.h>
#include <sys/module.h>

#include <dev/pci/pcireg.h>
#include <dev/pci/pcivar.h>

#include "brcmfmac.h"

static int brcmf_probe(device_t dev);
static int brcmf_attach(device_t dev);
static int brcmf_detach(device_t dev);

/* Device ID table */
static const struct brcmf_pci_id brcmf_devid_table[] = {
	{ PCI_VENDOR_BROADCOM, PCI_DEVICE_BCM4350, "Broadcom BCM4350 WiFi" },
	{ 0, 0, NULL }
};

static device_method_t brcmf_methods[] = { DEVMETHOD(device_probe, brcmf_probe),
	DEVMETHOD(device_attach, brcmf_attach),
	DEVMETHOD(device_detach, brcmf_detach), DEVMETHOD_END };

static driver_t brcmf_driver = { "brcmfmac", brcmf_methods,
	sizeof(struct brcmf_softc) };

DRIVER_MODULE(if_brcmfmac, pci, brcmf_driver, NULL, NULL);
MODULE_VERSION(if_brcmfmac, 1);
MODULE_DEPEND(if_brcmfmac, pci, 1, 1, 1);
MODULE_DEPEND(if_brcmfmac, firmware, 1, 1, 1);
MODULE_PNP_INFO("U16:vendor;U16:device", pci, if_brcmfmac, brcmf_devid_table,
    nitems(brcmf_devid_table) - 1);

static int
brcmf_probe(device_t dev)
{
	const struct brcmf_pci_id *id;
	uint16_t vendor, device;

	vendor = pci_get_vendor(dev);
	device = pci_get_device(dev);

	for (id = brcmf_devid_table; id->vendor != 0; id++) {
		if (id->vendor == vendor && id->device == device) {
			device_set_desc(dev, id->desc);
			return (BUS_PROBE_DEFAULT);
		}
	}

	return (ENXIO);
}

static int
brcmf_attach(device_t dev)
{
	return (brcmf_pcie_attach(dev));
}

static int
brcmf_detach(device_t dev)
{
	return (brcmf_pcie_detach(dev));
}
