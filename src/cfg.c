/* net80211 interface: VAP management, scan, connect */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bus.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/socket.h>
#include <sys/sockio.h>

#include <net/if.h>
#include <net/if_media.h>
#include <net/ethernet.h>

#include <net80211/ieee80211_var.h>

#include "brcmfmac.h"

struct brcmf_vap {
	struct ieee80211vap vap;
	int (*newstate)(struct ieee80211vap *, enum ieee80211_state, int);
};

#define BRCMF_VAP(vap) ((struct brcmf_vap *)(vap))

/*
 * Get MAC address from firmware.
 */
static int
brcmf_get_macaddr(struct brcmf_softc *sc)
{
	int error;

	error = brcmf_fil_iovar_data_get(sc, "cur_etheraddr", NULL,
	    ETHER_ADDR_LEN);
	if (error != 0) {
		device_printf(sc->dev, "failed to get MAC address: %d\n",
		    error);
		return (error);
	}

	memcpy(sc->macaddr, sc->ioctlbuf, ETHER_ADDR_LEN);
	printf("brcmfmac: MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n",
	    sc->macaddr[0], sc->macaddr[1], sc->macaddr[2],
	    sc->macaddr[3], sc->macaddr[4], sc->macaddr[5]);

	return (0);
}

/*
 * VAP state change handler.
 */
static int
brcmf_newstate(struct ieee80211vap *vap, enum ieee80211_state nstate, int arg)
{
	struct brcmf_vap *bvap = BRCMF_VAP(vap);
	struct ieee80211com *ic = vap->iv_ic;

	IEEE80211_UNLOCK(ic);

	switch (nstate) {
	case IEEE80211_S_INIT:
		printf("brcmfmac: state -> INIT\n");
		break;
	case IEEE80211_S_SCAN:
		printf("brcmfmac: state -> SCAN\n");
		/* TODO: start scan */
		break;
	case IEEE80211_S_AUTH:
		printf("brcmfmac: state -> AUTH\n");
		break;
	case IEEE80211_S_ASSOC:
		printf("brcmfmac: state -> ASSOC\n");
		break;
	case IEEE80211_S_RUN:
		printf("brcmfmac: state -> RUN\n");
		break;
	default:
		break;
	}

	IEEE80211_LOCK(ic);
	return (bvap->newstate(vap, nstate, arg));
}

/*
 * Create a VAP.
 */
static struct ieee80211vap *
brcmf_vap_create(struct ieee80211com *ic, const char name[IFNAMSIZ], int unit,
    enum ieee80211_opmode opmode, int flags,
    const uint8_t bssid[IEEE80211_ADDR_LEN],
    const uint8_t mac[IEEE80211_ADDR_LEN])
{
	struct brcmf_softc *sc = ic->ic_softc;
	struct brcmf_vap *bvap;
	struct ieee80211vap *vap;

	if (!TAILQ_EMPTY(&ic->ic_vaps)) {
		device_printf(sc->dev, "only one VAP supported\n");
		return (NULL);
	}

	bvap = malloc(sizeof(*bvap), M_80211_VAP, M_WAITOK | M_ZERO);
	vap = &bvap->vap;

	if (ieee80211_vap_setup(ic, vap, name, unit, opmode, flags,
	    bssid) != 0) {
		free(bvap, M_80211_VAP);
		return (NULL);
	}

	bvap->newstate = vap->iv_newstate;
	vap->iv_newstate = brcmf_newstate;

	ieee80211_vap_attach(vap, ieee80211_media_change,
	    ieee80211_media_status, mac);

	ic->ic_opmode = opmode;

	return (vap);
}

/*
 * Destroy a VAP.
 */
static void
brcmf_vap_delete(struct ieee80211vap *vap)
{
	struct brcmf_vap *bvap = BRCMF_VAP(vap);

	ieee80211_vap_detach(vap);
	free(bvap, M_80211_VAP);
}

/*
 * Parent interface control (up/down).
 */
static void
brcmf_parent(struct ieee80211com *ic)
{
	struct brcmf_softc *sc = ic->ic_softc;
	int startall = 0;

	if (ic->ic_nrunning > 0) {
		if (!sc->running) {
			brcmf_fil_iovar_int_set(sc, "mpc", 0);
			sc->running = 1;
			startall = 1;
		}
	} else {
		if (sc->running)
			sc->running = 0;
	}

	if (startall)
		ieee80211_start_all(ic);
}

/*
 * Start a scan.
 */
static void
brcmf_scan_start(struct ieee80211com *ic)
{
	/* TODO: implement escan */
	printf("brcmfmac: scan_start\n");
}

/*
 * End a scan.
 */
static void
brcmf_scan_end(struct ieee80211com *ic)
{
	printf("brcmfmac: scan_end\n");
}

/*
 * Set channel.
 */
static void
brcmf_set_channel(struct ieee80211com *ic)
{
	printf("brcmfmac: set_channel %d\n",
	    ieee80211_chan2ieee(ic, ic->ic_curchan));
}

/*
 * Transmit a frame.
 */
static int
brcmf_transmit(struct ieee80211com *ic, struct mbuf *m)
{
	/* TODO: implement TX */
	m_freem(m);
	return (0);
}

/*
 * Raw transmit (management frames).
 */
static int
brcmf_raw_xmit(struct ieee80211_node *ni, struct mbuf *m,
    const struct ieee80211_bpf_params *params)
{
	/* TODO: implement raw TX */
	m_freem(m);
	return (0);
}

/*
 * Setup channel list from firmware capabilities.
 */
static void
brcmf_getradiocaps(struct ieee80211com *ic, int maxchans, int *nchans,
    struct ieee80211_channel chans[])
{
	uint8_t bands[IEEE80211_MODE_BYTES];

	memset(bands, 0, sizeof(bands));

	/* For now, just add basic 2.4GHz channels */
	setbit(bands, IEEE80211_MODE_11B);
	setbit(bands, IEEE80211_MODE_11G);

	/* TODO: query firmware for actual channel list */
	ieee80211_add_channels_default_2ghz(chans, maxchans, nchans, bands, 0);

	/* Add 5GHz if supported */
	setbit(bands, IEEE80211_MODE_11A);
	ieee80211_add_channel_list_5ghz(chans, maxchans, nchans,
	    (const uint8_t[]){36, 40, 44, 48, 52, 56, 60, 64,
	    100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140,
	    149, 153, 157, 161, 165}, 24, bands, 0);
}

/*
 * Attach net80211 interface.
 */
int
brcmf_cfg_attach(struct brcmf_softc *sc)
{
	struct ieee80211com *ic = &sc->ic;
	int error;

	error = brcmf_get_macaddr(sc);
	if (error != 0)
		return (error);

	ic->ic_softc = sc;
	ic->ic_name = device_get_nameunit(sc->dev);
	ic->ic_phytype = IEEE80211_T_OFDM;
	ic->ic_opmode = IEEE80211_M_STA;

	ic->ic_caps =
	    IEEE80211_C_STA |
	    IEEE80211_C_MONITOR |
	    IEEE80211_C_WPA |
	    IEEE80211_C_SHPREAMBLE |
	    IEEE80211_C_SHSLOT |
	    IEEE80211_C_BGSCAN |
	    IEEE80211_C_WME;

	ic->ic_cryptocaps =
	    IEEE80211_CRYPTO_WEP |
	    IEEE80211_CRYPTO_TKIP |
	    IEEE80211_CRYPTO_AES_CCM;

	brcmf_getradiocaps(ic, IEEE80211_CHAN_MAX, &ic->ic_nchans,
	    ic->ic_channels);

	IEEE80211_ADDR_COPY(ic->ic_macaddr, sc->macaddr);

	ieee80211_ifattach(ic);

	ic->ic_vap_create = brcmf_vap_create;
	ic->ic_vap_delete = brcmf_vap_delete;
	ic->ic_parent = brcmf_parent;
	ic->ic_scan_start = brcmf_scan_start;
	ic->ic_scan_end = brcmf_scan_end;
	ic->ic_set_channel = brcmf_set_channel;
	ic->ic_transmit = brcmf_transmit;
	ic->ic_raw_xmit = brcmf_raw_xmit;
	ic->ic_getradiocaps = brcmf_getradiocaps;

	ieee80211_announce(ic);

	return (0);
}

/*
 * Detach net80211 interface.
 */
void
brcmf_cfg_detach(struct brcmf_softc *sc)
{
	struct ieee80211com *ic = &sc->ic;

	ieee80211_ifdetach(ic);
}
