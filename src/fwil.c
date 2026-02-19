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

/*
 * Send a command with data to firmware.
 */
int
brcmf_fil_cmd_data_set(struct brcmf_softc *sc, uint32_t cmd,
    const void *data, uint32_t len)
{
	if (len > BRCMF_MSGBUF_MAX_CTL_PKT_SIZE)
		return (EINVAL);

	if (data != NULL && len > 0)
		memcpy(sc->ioctlbuf, data, len);

	return brcmf_msgbuf_ioctl(sc, cmd, sc->ioctlbuf, len, NULL);
}

/*
 * Get data from firmware via command.
 */
int
brcmf_fil_cmd_data_get(struct brcmf_softc *sc, uint32_t cmd,
    void *data, uint32_t len)
{
	int error;

	error = brcmf_msgbuf_ioctl(sc, cmd, sc->ioctlbuf, len, NULL);
	if (error == 0 && data != NULL && len > 0)
		memcpy(data, sc->ioctlbuf, len);

	return error;
}

/*
 * Set a bsscfg-indexed IOVAR. The wire format is:
 *   "bsscfg:<name>\0" + le32(bsscfgidx) + data
 */
int
brcmf_fil_bsscfg_data_set(struct brcmf_softc *sc, const char *name,
    int bsscfg_idx, const void *data, uint32_t len)
{
	uint32_t prefix_len;

	prefix_len = 7 + strlen(name) + 1; /* "bsscfg:" + name + '\0' */
	if (prefix_len + 4 + len > BRCMF_MSGBUF_MAX_CTL_PKT_SIZE)
		return (EINVAL);

	memcpy(sc->ioctlbuf, "bsscfg:", 7);
	strcpy((char *)sc->ioctlbuf + 7, name);
	*(uint32_t *)((char *)sc->ioctlbuf + prefix_len) = htole32(bsscfg_idx);
	if (data != NULL && len > 0)
		memcpy((char *)sc->ioctlbuf + prefix_len + 4, data, len);

	return brcmf_msgbuf_ioctl(sc, BRCMF_C_SET_VAR, sc->ioctlbuf,
	    prefix_len + 4 + len, NULL);
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
	uint32_t val = 1;

	return brcmf_msgbuf_ioctl(sc, BRCMF_C_DOWN, &val, sizeof(val), NULL);
}
