#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/module.h>

// brcmfmac_mod_event_handler is defined in brcmfmac.zig.
extern int brcmfmac_mod_event_handler(module_t mod, int cmd, void *arg);

static moduledata_t brcmfmac_mod = { "if_brcmfmac", brcmfmac_mod_event_handler,
	NULL };

DECLARE_MODULE(if_brcmfmac, brcmfmac_mod, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);
MODULE_VERSION(if_brcmfmac, 1);
MODULE_DEPEND(if_brcmfmac, linuxkpi, 1, 1, 1);
MODULE_DEPEND(if_brcmfmac, linuxkpi_wlan, 1, 1, 1);
MODULE_DEPEND(if_brcmfmac, firmware, 1, 1, 1);
