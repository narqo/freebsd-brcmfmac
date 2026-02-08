/* Firmware interface layer: IOVAR get/set operations */

#include <sys/param.h>
#include <sys/systm.h>

#include "brcmfmac.h"

/* FWIL command codes */
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
	uint32_t namelen;

	namelen = strlen(name) + 1;
	if (namelen + len > BRCMF_MSGBUF_MAX_CTL_PKT_SIZE)
		return (EINVAL);

	memset(sc->ioctlbuf, 0, namelen + len);
	memcpy(sc->ioctlbuf, name, namelen);

	return brcmf_msgbuf_ioctl(sc, BRCMF_C_GET_VAR, sc->ioctlbuf,
	    namelen + len, NULL);
}

/*
 * Set an IOVAR value in firmware.
 */
int
brcmf_fil_iovar_data_set(struct brcmf_softc *sc, const char *name,
    const void *data, uint32_t len)
{
	uint32_t namelen;

	namelen = strlen(name) + 1;
	if (namelen + len > BRCMF_MSGBUF_MAX_CTL_PKT_SIZE)
		return (EINVAL);

	memcpy(sc->ioctlbuf, name, namelen);
	if (data != NULL && len > 0)
		memcpy((char *)sc->ioctlbuf + namelen, data, len);

	return brcmf_msgbuf_ioctl(sc, BRCMF_C_SET_VAR, sc->ioctlbuf,
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
	int error;

	error = brcmf_fil_iovar_data_get(sc, name, NULL, sizeof(*val));
	if (error == 0 && val != NULL)
		*val = le32toh(*(uint32_t *)sc->ioctlbuf);

	return (error);
}
