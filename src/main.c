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
#include <sys/firmware.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/module.h>

#include <dev/pci/pcireg.h>
#include <dev/pci/pcivar.h>

#include <dev/sdio/sdiob.h>
#include <dev/sdio/sdio_subr.h>

#include "sdio_if.h"
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

#define BRCMF_CLM_FW_NAME	"brcmfmac43455-sdio.clm_blob"
#define BRCMF_CLM_MAX_CHUNK	1400

/* CLM download header (matches Linux brcmf_dload_data_le) */
struct brcmf_dload_data_le {
	uint16_t flag;
	uint16_t dload_type;
	uint32_t len;
	uint32_t crc;
	uint8_t data[];
} __packed;

#define DL_BEGIN	0x0002
#define DL_END		0x0004
#define DL_TYPE_CLM	2
#define DLOAD_HANDLER_VER 1
#define DLOAD_FLAG_VER_SHIFT 12

static void
brcmf_sdio_load_clm(struct brcmf_softc *sc)
{
	const struct firmware *fw;
	struct brcmf_dload_data_le *chunk;
	uint32_t datalen, cumulative, chunk_len;
	uint16_t dl_flag;
	uint32_t status;
	int error;

	fw = firmware_get(BRCMF_CLM_FW_NAME);
	if (fw == NULL) {
		device_printf(sc->dev,
		    "no CLM blob available, channels may be limited\n");
		return;
	}

	device_printf(sc->dev, "loading CLM blob (%zu bytes)\n",
	    fw->datasize);

	chunk = malloc(sizeof(*chunk) + BRCMF_CLM_MAX_CHUNK,
	    M_BRCMFMAC, M_WAITOK | M_ZERO);

	datalen = fw->datasize;
	cumulative = 0;
	dl_flag = DL_BEGIN;

	do {
		if (datalen > BRCMF_CLM_MAX_CHUNK) {
			chunk_len = BRCMF_CLM_MAX_CHUNK;
		} else {
			chunk_len = datalen;
			dl_flag |= DL_END;
		}

		chunk->flag = htole16(dl_flag |
		    (DLOAD_HANDLER_VER << DLOAD_FLAG_VER_SHIFT));
		chunk->dload_type = htole16(DL_TYPE_CLM);
		chunk->len = htole32(chunk_len);
		chunk->crc = 0;
		memcpy(chunk->data,
		    (const uint8_t *)fw->data + cumulative, chunk_len);

		/*
		 * Can't use brcmf_fil_iovar_data_set — its 512-byte
		 * stack buffer is too small for CLM chunks. Build the
		 * iovar buffer manually and call ioctl directly.
		 */
		{
			static const char clmload[] = "clmload";
			uint32_t namelen = sizeof(clmload);
			uint32_t paylen = sizeof(*chunk) + chunk_len;
			uint32_t total = namelen + paylen;
			uint8_t *iobuf = malloc(total, M_BRCMFMAC,
			    M_WAITOK);
			memcpy(iobuf, clmload, namelen);
			memcpy(iobuf + namelen, chunk, paylen);
			error = sc->bus_ops->ioctl(sc,
			    263 /* C_SET_VAR */, 1, iobuf, total, NULL);
			free(iobuf, M_BRCMFMAC);
		}
		if (error != 0) {
			device_printf(sc->dev,
			    "CLM download failed at offset %u: %d\n",
			    cumulative, error);
			break;
		}

		dl_flag &= ~DL_BEGIN;
		cumulative += chunk_len;
		datalen -= chunk_len;
	} while (datalen > 0);

	free(chunk, M_BRCMFMAC);
	firmware_put(fw, FIRMWARE_UNLOAD);

	if (error == 0) {
		error = brcmf_fil_iovar_int_get(sc, "clmload_status",
		    &status);
		if (error == 0 && status != 0) {
			device_printf(sc->dev,
			    "CLM load status: %u\n", status);
		} else if (error == 0) {
			device_printf(sc->dev, "CLM blob loaded\n");
		}
	}
}

static int brcmf_sdio_probe(device_t dev);
static int brcmf_sdio_bus_attach(device_t dev);
static int brcmf_sdio_bus_detach(device_t dev);
static int brcmf_sdio_bus_start(struct brcmf_softc *sc);

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
brcmf_sdio_bus_start(struct brcmf_softc *sc)
{
	char ver[128];
	char caps[256];
	int error;

	/* Disable BT coexistence ASAP — before any ioctl that might
	 * trigger wl_open. CYW43455 firmware has a bug where btc_mode=1
	 * causes FEM misconfiguration (FIXME bt_coex). */
	brcmf_fil_iovar_int_set(sc, "btc_mode", 0);

	memset(ver, 0, sizeof(ver));
	error = brcmf_fil_iovar_data_get(sc, "ver", ver, sizeof(ver) - 1);
	if (error != 0) {
		device_printf(sc->dev, "firmware ver ioctl failed: %d\n", error);
		return (error);
	}
	{
		char *nl = strchr(ver, '\n');
		if (nl != NULL)
			*nl = '\0';
		device_printf(sc->dev, "firmware: %s\n", ver);
	}

	memset(caps, 0, sizeof(caps));
	error = brcmf_fil_iovar_data_get(sc, "cap", caps, sizeof(caps) - 1);
	if (error == 0)
		device_printf(sc->dev, "cap: %s\n", caps);
	else
		device_printf(sc->dev, "cap iovar failed: %d\n", error);

	/* Linux disables glom on SDIO during preinit. We do not support
	 * glom descriptors yet; leaving it enabled can desynchronize F2 RX. */
	brcmf_fil_cmd_data_set(sc, 89 /* C_SET_GLOM */,
	    &(uint32_t){ htole32(0) }, sizeof(uint32_t));

	brcmf_sdio_load_clm(sc);
	return (0);
}

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

	sc->bus_ops = &brcmf_sdio_bus_ops;
	mtx_init(&sc->ioctl_mtx, "brcmfmac_ioctl", NULL, MTX_DEF);
	brcmf_sdpcm_init(sc);

	error = brcmf_sdio_attach(sc);
	if (error != 0)
		goto fail;

	brcmf_sdpcm_start_poll(sc);

	error = brcmf_sdio_bus_start(sc);
	if (error != 0)
		goto fail;

	error = brcmf_cfg_attach(sc);
	if (error != 0)
		goto fail;

	return (0);

fail:
	brcmf_sdpcm_stop_poll(sc);
	if (sc->bus_ops != NULL && sc->bus_ops->cleanup != NULL)
		sc->bus_ops->cleanup(sc);
	brcmf_sdio_detach(sc);
	mtx_destroy(&sc->ioctl_mtx);
	return (error);
}

static int
brcmf_sdio_bus_detach(device_t dev)
{
	struct brcmf_softc *sc;

	sc = device_get_softc(dev);
	sc->detaching = 1;

	/* Bring firmware down before stopping poll/cleanup */
	if (sc->cfg_attached) {
		brcmf_fil_bss_down(sc);
	}

	sc->fw_dead = 1;

	/* Stop RX poll before tearing down net80211 — the poll task
	 * accesses VAP state that ieee80211_ifdetach destroys. */
	brcmf_sdpcm_stop_poll(sc);

	/* Wake any sleeping ioctl so it doesn't block detach */
	wakeup(&sc->ioctl_completed);

	brcmf_cfg_detach(sc);
	sc->bus_ops->cleanup(sc);
	brcmf_sdio_detach(sc);
	mtx_destroy(&sc->ioctl_mtx);
	return (0);
}
