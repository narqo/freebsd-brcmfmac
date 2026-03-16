// SPDX-License-Identifier: ISC
/*
 * Copyright (c) 2010-2022 Broadcom Corporation
 * Copyright (c) brcmfmac-freebsd contributors
 *
 * Based on the Linux brcmfmac driver.
 */

/*
 * brcmfmac - Broadcom FullMAC WiFi driver for FreeBSD
 *
 * Two DRIVER_MODULE registrations: one for PCIe (pci bus), one for
 * SDIO (sdiob bus). Only the matching one probes at runtime.
 */

#include <sys/param.h>
#include <sys/bus.h>
#include <sys/kernel.h>
#include <sys/module.h>

#include <dev/pci/pcireg.h>
#include <dev/pci/pcivar.h>

#include <dev/sdio/sdiob.h>

#include "brcmfmac.h"

/* ----------------------------------------------------------------
 * PCIe bus attachment
 * ---------------------------------------------------------------- */

static int brcmf_pci_probe(device_t dev);
static int brcmf_pci_attach(device_t dev);
static int brcmf_pci_detach(device_t dev);

static const struct brcmf_pci_id brcmf_devid_table[] = {
	{ PCI_VENDOR_BROADCOM, PCI_DEVICE_BCM4350, "Broadcom BCM4350 WiFi" },
	{ 0, 0, NULL }
};

static device_method_t brcmf_pci_methods[] = {
	DEVMETHOD(device_probe, brcmf_pci_probe),
	DEVMETHOD(device_attach, brcmf_pci_attach),
	DEVMETHOD(device_detach, brcmf_pci_detach),
	DEVMETHOD_END
};

static driver_t brcmf_pci_driver = {
	"brcmfmac",
	brcmf_pci_methods,
	sizeof(struct brcmf_softc)
};

DRIVER_MODULE(if_brcmfmac, pci, brcmf_pci_driver, NULL, NULL);
MODULE_VERSION(if_brcmfmac, 1);
MODULE_DEPEND(if_brcmfmac, pci, 1, 1, 1);
MODULE_DEPEND(if_brcmfmac, firmware, 1, 1, 1);
MODULE_DEPEND(if_brcmfmac, wlan, 1, 1, 1);
MODULE_PNP_INFO("U16:vendor;U16:device", pci, if_brcmfmac, brcmf_devid_table,
    nitems(brcmf_devid_table) - 1);

static int
brcmf_pci_probe(device_t dev)
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
brcmf_pci_attach(device_t dev)
{
	return (brcmf_pcie_attach(dev));
}

static int
brcmf_pci_detach(device_t dev)
{
	return (brcmf_pcie_detach(dev));
}

/* ----------------------------------------------------------------
 * SDIO bus attachment
 * ---------------------------------------------------------------- */

#define SDIO_VENDOR_BROADCOM	0x02D0
#define SDIO_DEVICE_BCM43455	0xA9A6

static int brcmf_sdio_probe(device_t dev);
static int brcmf_sdio_bus_attach(device_t dev);
static int brcmf_sdio_bus_detach(device_t dev);

static device_method_t brcmf_sdio_methods[] = {
	DEVMETHOD(device_probe, brcmf_sdio_probe),
	DEVMETHOD(device_attach, brcmf_sdio_bus_attach),
	DEVMETHOD(device_detach, brcmf_sdio_bus_detach),
	DEVMETHOD_END
};

static driver_t brcmf_sdio_driver = {
	"brcmfmac",
	brcmf_sdio_methods,
	sizeof(struct brcmf_softc)
};

DRIVER_MODULE(if_brcmfmac, sdiob, brcmf_sdio_driver, NULL, NULL);
MODULE_DEPEND(if_brcmfmac, sdiob, 1, 1, 1);

static int
brcmf_sdio_probe(device_t dev)
{
	uint16_t vendor, device;

	vendor = sdio_get_vendor(dev);
	device = sdio_get_device(dev);

	if (vendor != SDIO_VENDOR_BROADCOM)
		return (ENXIO);
	if (device != SDIO_DEVICE_BCM43455)
		return (ENXIO);

	/* Only attach to F1 (backplane access) */
	if (sdio_get_funcnum(dev) != 1)
		return (ENXIO);

	device_set_desc(dev, "Broadcom BCM43455 WiFi (SDIO)");
	return (BUS_PROBE_DEFAULT);
}

static int
brcmf_sdio_bus_attach(device_t dev)
{
	struct brcmf_softc *sc;
	struct sdio_func *f;
	int error;

	sc = device_get_softc(dev);
	sc->dev = dev;

	f = sdio_get_function(dev);
	sc->sdio_func1 = f;

	/*
	 * F2 is a sibling device on the same sdiob bus. We need its
	 * sdio_func pointer for data transfer. Walk the parent's children
	 * to find function 2.
	 */
	{
		device_t parent = device_get_parent(dev);
		device_t *children;
		int nchildren, i;

		if (device_get_children(parent, &children, &nchildren) == 0) {
			for (i = 0; i < nchildren; i++) {
				if (children[i] == dev)
					continue;
				if (sdio_get_vendor(children[i]) ==
				    SDIO_VENDOR_BROADCOM &&
				    sdio_get_funcnum(children[i]) == 2) {
					sc->sdio_func2 =
					    sdio_get_function(children[i]);
					break;
				}
			}
			free(children, M_TEMP);
		}
	}

	error = brcmf_sdio_attach(sc);
	if (error != 0)
		goto fail;

	/* TODO: brcmf_sdpcm_init + brcmf_cfg_attach come in M-S3 */

	return (0);

fail:
	brcmf_sdio_detach(sc);
	return (error);
}

static int
brcmf_sdio_bus_detach(device_t dev)
{
	struct brcmf_softc *sc;

	sc = device_get_softc(dev);
	brcmf_sdio_detach(sc);
	return (0);
}
