// SPDX-License-Identifier: ISC
/*
 * Copyright (c) 2010-2022 Broadcom Corporation
 * Copyright (c) brcmfmac-freebsd contributors
 *
 * Based on the Linux brcmfmac driver.
 */

#ifndef _BRCMF_DEBUG_H_
#define _BRCMF_DEBUG_H_

#include <sys/bus.h>

void brcmf_dbg(const char *fmt, ...);

/* Debug emits for sc->debug >= BRCMF_DBG_VERBOSE or bootverbose is set */
#define BRCMF_DBG_VERBOSE 2
#define BRCMF_DBG(sc /* struct brcmf_softc* */, fmt, ...)             \
	do {                                                          \
		if ((sc)->debug >= BRCMF_DBG_VERBOSE || bootverbose)  \
			device_printf((sc)->dev, fmt, ##__VA_ARGS__); \
	} while (0)

#endif /* _BRCMF_DEBUG_H_ */
