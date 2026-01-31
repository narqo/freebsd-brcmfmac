/* SPDX-License-Identifier: ISC */
/*
 * FreeBSD compatibility shims for brcmfmac driver
 * This file provides compatibility for APIs not yet in LinuxKPI
 */

#ifndef _BRCMFMAC_COMPAT_H_
#define _BRCMFMAC_COMPAT_H_

#ifdef __FreeBSD__

/*
 * LinuxKPI may not have all Linux APIs we need.
 * This header will be populated as we discover gaps during porting.
 */

#include <linux/delay.h>
#include <linux/list.h>
#include <sys/systm.h>

/*
 * LIST_HEAD_INIT - LinuxKPI uses LINUX_LIST_HEAD_INIT instead
 */
#ifndef LIST_HEAD_INIT
#define LIST_HEAD_INIT(name) LINUX_LIST_HEAD_INIT(name)
#endif

/*
 * mdelay() - busy-wait delay in milliseconds
 * Linux has this, but LinuxKPI might not expose it properly
 */
#ifndef mdelay
#define mdelay(ms) DELAY((ms) * 1000)
#endif

/*
 * msleep() - sleep for milliseconds
 * Linux msleep(ms) vs FreeBSD msleep(chan, mtx, pri, wmesg, timo)
 * Linux version doesn't need a lock and is simpler
 */
#ifdef msleep
#undef msleep
#endif
static inline void msleep(unsigned int msecs)
{
	pause("brcmf", (msecs * hz) / 1000);
}

/* Stub for missing cfg80211 operations */
struct bss_parameters;  /* Forward declaration for incomplete type */

/* Stub IRQ structures - not used for PCIe WiFi */
struct irq_chip {};
struct irq_desc { void *unused; };
struct irq_data {};

/* no_printk - null debug macro */
#ifndef no_printk
#define no_printk(fmt, ...) do { } while (0)
#endif

#endif /* __FreeBSD__ */

#endif /* _BRCMFMAC_COMPAT_H_ */
