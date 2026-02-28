// SPDX-License-Identifier: ISC
/*
 * Copyright (c) 2010-2022 Broadcom Corporation
 * Copyright (c) brcmfmac-freebsd contributors
 *
 * Based on the Linux brcmfmac driver.
 */

/* Firmware interface layer: IOVAR get/set operations */

#include <sys/param.h>
#include <sys/systm.h>

#include "brcmfmac.h"

/* FWIL command codes */
#define BRCMF_C_UP   2
#define BRCMF_C_DOWN 3
#define BRCMF_C_GET_VAR 262
#define BRCMF_C_SET_VAR 263

/* Buffer size */
#define BRCMF_MSGBUF_MAX_CTL_PKT_SIZE 8192

/*
 * Get an IOVAR value from firmware.
 */
int
brcmf_fil_iovar_data_get(struct brcmf_softc *sc, const char *name,
    void *data, uint32_t len)
{
	char buf[512]; /* must fit name + response; largest is ~256 (ver) */
	uint32_t namelen;
	int error;

	namelen = strlen(name) + 1;
	if (namelen + len > sizeof(buf))
		return (EINVAL);

	memset(buf, 0, namelen + len);
	memcpy(buf, name, namelen);

	error = brcmf_msgbuf_ioctl(sc, BRCMF_C_GET_VAR, buf,
	    namelen + len, NULL);
	if (error == 0 && data != NULL && len > 0)
		memcpy(data, buf, len);

	return (error);
}

/*
 * Set an IOVAR value in firmware.
 */
int
brcmf_fil_iovar_data_set(struct brcmf_softc *sc, const char *name,
    const void *data, uint32_t len)
{
	char buf[512]; /* must fit name + data; largest is ~170 (wsec_key) */
	uint32_t namelen;

	namelen = strlen(name) + 1;
	if (namelen + len > sizeof(buf))
		return (EINVAL);

	memcpy(buf, name, namelen);
	if (data != NULL && len > 0)
		memcpy(buf + namelen, data, len);

	return brcmf_msgbuf_ioctl(sc, BRCMF_C_SET_VAR, buf,
	    namelen + len, NULL);
}

/*
 * Set an integer IOVAR.
 */
int
brcmf_fil_iovar_int_set(struct brcmf_softc *sc, const char *name, uint32_t val)
{
	uint32_t le_val = htole32(val);

	return brcmf_fil_iovar_data_set(sc, name, &le_val, sizeof(le_val));
}

/*
 * Get an integer IOVAR.
 */
int
brcmf_fil_iovar_int_get(struct brcmf_softc *sc, const char *name, uint32_t *val)
{
	uint32_t tmp;
	int error;

	error = brcmf_fil_iovar_data_get(sc, name, &tmp, sizeof(tmp));
	if (error == 0 && val != NULL)
		*val = le32toh(tmp);

	return (error);
}

/*
 * Send a command with data to firmware.
 */
int
brcmf_fil_cmd_data_set(struct brcmf_softc *sc, uint32_t cmd,
    const void *data, uint32_t len)
{
	return brcmf_msgbuf_ioctl(sc, cmd, __DECONST(void *, data), len, NULL);
}

/*
 * Get data from firmware via command.
 */
int
brcmf_fil_cmd_data_get(struct brcmf_softc *sc, uint32_t cmd,
    void *data, uint32_t len)
{
	return brcmf_msgbuf_ioctl(sc, cmd, data, len, NULL);
}

/*
 * Bring firmware interface up.
 */
int
brcmf_fil_bss_up(struct brcmf_softc *sc)
{
	uint32_t val = 0;

	return brcmf_msgbuf_ioctl(sc, BRCMF_C_UP, &val, sizeof(val), NULL);
}

/*
 * Bring firmware interface down.
 */
int
brcmf_fil_bss_down(struct brcmf_softc *sc)
{
	uint32_t val = 0;

	return brcmf_msgbuf_ioctl(sc, BRCMF_C_DOWN, &val, sizeof(val), NULL);
}
