// SPDX-License-Identifier: ISC
/*
 * Copyright (c) 2010-2022 Broadcom Corporation
 * Copyright (c) brcmfmac-freebsd contributors
 *
 * Based on the Linux brcmfmac driver.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/stdarg.h>

#include "debug.h"

/*
 * Debug print wrapper for Zig.
 * Using a wrapper prevents LLVM from recognizing printf and
 * optimizing calls like printf("foo\n") to puts("foo").
 */
void
brcmf_dbg(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
}
