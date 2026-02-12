/* net80211 interface: VAP management, scan, connect */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bus.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/taskqueue.h>

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

/* Event codes */
#define BRCMF_E_SET_SSID	0
#define BRCMF_E_LINK		16
#define BRCMF_E_IF		54
#define BRCMF_E_ESCAN_RESULT	69

/* Event status codes */
#define BRCMF_E_STATUS_SUCCESS	0

/* Event flags */
#define BRCMF_EVENT_MSG_LINK	0x01

/* IOCTL commands */
#define BRCMF_C_SET_INFRA	20
#define BRCMF_C_GET_BSSID	23
#define BRCMF_C_SET_SSID	26

/* Event mask: 128 bits (16 bytes) for 128 event codes */
#define BRCMF_EVENTING_MASK_LEN	16

/* escan action values */
#define WL_ESCAN_ACTION_START	1
#define WL_ESCAN_ACTION_CONTINUE 2
#define WL_ESCAN_ACTION_ABORT	3

/* escan version */
#define BRCMF_ESCAN_REQ_VERSION 1

/* BSS type */
#define DOT11_BSSTYPE_ANY 2

/*
 * Chanspec encoding (D11AC PHY format)
 * Bits 0-7:   channel number (or center for wide channels)
 * Bits 8-9:   control sideband
 * Bits 10-11: bandwidth (0=20, 1=40, 2=80, 3=160)
 * Bits 12-13: band (0=2G, 1=3G, 2=4G, 3=5G)
 * Bit 14:     reserved
 * Bit 15:     D11AC format indicator (1=D11AC)
 */
#define BRCMF_CHSPEC_D11AC_SB_MASK	0x0700
#define BRCMF_CHSPEC_D11AC_SB_SHIFT	8
#define BRCMF_CHSPEC_D11AC_SB_LLL	0x0000
#define BRCMF_CHSPEC_D11AC_SB_LLU	0x0100
#define BRCMF_CHSPEC_D11AC_SB_LUL	0x0200
#define BRCMF_CHSPEC_D11AC_SB_LUU	0x0300
#define BRCMF_CHSPEC_D11AC_SB_ULL	0x0400
#define BRCMF_CHSPEC_D11AC_SB_ULU	0x0500
#define BRCMF_CHSPEC_D11AC_SB_UUL	0x0600
#define BRCMF_CHSPEC_D11AC_SB_UUU	0x0700
#define BRCMF_CHSPEC_D11AC_SB_L		0x0000
#define BRCMF_CHSPEC_D11AC_SB_U		0x0100
#define BRCMF_CHSPEC_D11AC_BW_MASK	0x3800
#define BRCMF_CHSPEC_D11AC_BW_SHIFT	11
#define BRCMF_CHSPEC_D11AC_BW_5		0x0000
#define BRCMF_CHSPEC_D11AC_BW_10	0x0800
#define BRCMF_CHSPEC_D11AC_BW_20	0x1000
#define BRCMF_CHSPEC_D11AC_BW_40	0x1800
#define BRCMF_CHSPEC_D11AC_BW_80	0x2000
#define BRCMF_CHSPEC_D11AC_BW_160	0x2800
#define BRCMF_CHSPEC_D11AC_BW_8080	0x3000
#define BRCMF_CHSPEC_D11AC_BAND_MASK	0xc000
#define BRCMF_CHSPEC_D11AC_BAND_2G	0x0000
#define BRCMF_CHSPEC_D11AC_BAND_5G	0xc000
#define BRCMF_CHSPEC_CHAN_MASK		0x00ff

/* Legacy/simple chanspec encoding */
#define BRCMF_CHANSPEC_CHAN_MASK	0x00ff
#define BRCMF_CHANSPEC_BAND_2G		0x0000
#define BRCMF_CHANSPEC_BAND_5G		0xc000
#define BRCMF_CHANSPEC_BW_20		0x1000
#define BRCMF_CHANSPEC_CTL_SB_NONE	0x0000

/* escan result event status */
#define BRCMF_E_STATUS_PARTIAL 8

/* Scan structures */
struct brcmf_ssid_le {
	uint32_t SSID_len;
	uint8_t SSID[32];
} __packed;

struct brcmf_scan_params_le {
	struct brcmf_ssid_le ssid_le;
	uint8_t bssid[6];
	int8_t bss_type;
	uint8_t scan_type;
	uint32_t nprobes;
	uint32_t active_time;
	uint32_t passive_time;
	uint32_t home_time;
	uint32_t channel_num;
	uint16_t channel_list[];
} __packed;

struct brcmf_escan_params_le {
	uint32_t version;
	uint16_t action;
	uint16_t sync_id;
	struct brcmf_scan_params_le params_le;
} __packed;

/* BSS info from scan results - see spec/10-structures-reference.md */
struct brcmf_bss_info_le {
	uint32_t version;
	uint32_t length;
	uint8_t BSSID[6];
	uint16_t beacon_period;
	uint16_t capability;
	uint8_t SSID_len;
	uint8_t SSID[32];
	struct {
		uint32_t count;
		uint8_t rates[16];
	} rateset;
	uint16_t chanspec;
	uint16_t atim_window;
	uint8_t dtim_period;
	int16_t RSSI;
	int8_t phy_noise;
	uint8_t n_cap;
	uint32_t nbss_cap;
	uint8_t ctl_ch;
	uint32_t reserved32[1];
	uint8_t flags;
	uint8_t reserved[3];
	uint8_t basic_mcs[16];
	uint16_t ie_offset;
	uint32_t ie_length;
	int16_t SNR;
} __packed;

struct brcmf_escan_result_le {
	uint32_t buflen;
	uint32_t version;
	uint16_t sync_id;
	uint16_t bss_count;
	struct brcmf_bss_info_le bss_info_le;
} __packed;

/* Join parameters for BRCMF_C_SET_SSID */
struct brcmf_assoc_params_le {
	uint8_t bssid[6];
	uint16_t bssid_cnt;
	uint32_t chanspec_num;
	uint16_t chanspec_list[1];
} __packed;

struct brcmf_join_params {
	struct brcmf_ssid_le ssid_le;
	struct brcmf_assoc_params_le params_le;
} __packed;

/*
 * Add cached scan result to net80211.
 */
/* Default rates IE for 2.4GHz (11b/g rates) */
static const uint8_t default_rates_ie[] = {
	IEEE80211_ELEMID_RATES, 8,
	0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24
};

static void
brcmf_add_scan_result(struct brcmf_softc *sc, struct brcmf_scan_result *sr)
{
	struct ieee80211com *ic = &sc->ic;
	struct ieee80211vap *vap;
	struct ieee80211_scanparams sp;
	struct ieee80211_frame wh;
	struct ieee80211_channel *chan;
	uint8_t ssid_ie[2 + 32];

	vap = TAILQ_FIRST(&ic->ic_vaps);
	if (vap == NULL)
		return;

	/* Find channel */
	chan = ieee80211_find_channel(ic, sr->chan,
	    sr->chan <= 14 ? IEEE80211_CHAN_G : IEEE80211_CHAN_A);
	if (chan == NULL)
		chan = &ic->ic_channels[0];

	/* Build SSID IE */
	ssid_ie[0] = IEEE80211_ELEMID_SSID;
	ssid_ie[1] = sr->ssid_len;
	memcpy(&ssid_ie[2], sr->ssid, sr->ssid_len);

	memset(&sp, 0, sizeof(sp));
	sp.ssid = ssid_ie;
	sp.rates = __DECONST(uint8_t *, default_rates_ie);
	sp.chan = sr->chan;
	sp.bchan = sr->chan;
	sp.capinfo = sr->capinfo;
	sp.bintval = sr->bintval;

	/* Parse IEs */
	if (sr->ie_len > 0) {
		uint8_t *p = sr->ie;
		uint8_t *end = sr->ie + sr->ie_len;

		while (p + 2 <= end) {
			uint8_t id = p[0];
			uint8_t len = p[1];

			if (p + 2 + len > end)
				break;

			switch (id) {
			case IEEE80211_ELEMID_RATES:
				sp.rates = p;
				break;
			case IEEE80211_ELEMID_XRATES:
				sp.xrates = p;
				break;
			case IEEE80211_ELEMID_COUNTRY:
				sp.country = p;
				break;
			case IEEE80211_ELEMID_RSN:
				sp.rsn = p;
				break;
			case IEEE80211_ELEMID_HTCAP:
				sp.htcap = p;
				break;
			case IEEE80211_ELEMID_HTINFO:
				sp.htinfo = p;
				break;
			case IEEE80211_ELEMID_VENDOR:
				if (len >= 4 &&
				    p[2] == 0x00 && p[3] == 0x50 &&
				    p[4] == 0xf2 && p[5] == 0x01)
					sp.wpa = p;
				if (len >= 4 &&
				    p[2] == 0x00 && p[3] == 0x50 &&
				    p[4] == 0xf2 && p[5] == 0x02)
					sp.wme = p;
				break;
			}
			p += 2 + len;
		}
		sp.ies = sr->ie;
		sp.ies_len = sr->ie_len;
	}

	/* Build frame header */
	memset(&wh, 0, sizeof(wh));
	wh.i_fc[0] = IEEE80211_FC0_TYPE_MGT | IEEE80211_FC0_SUBTYPE_BEACON;
	IEEE80211_ADDR_COPY(wh.i_addr2, sr->bssid);
	IEEE80211_ADDR_COPY(wh.i_addr3, sr->bssid);

	/* ieee80211_add_scan crashes - disabled for now */
}

/*
 * Scan completion task - runs in process context.
 */
static void
brcmf_scan_complete_task(void *arg, int pending)
{
	struct brcmf_softc *sc = arg;
	struct ieee80211com *ic = &sc->ic;
	struct ieee80211vap *vap;
	int i, n;

	vap = TAILQ_FIRST(&ic->ic_vaps);
	if (vap == NULL)
		return;

	/* Only process results when scan is complete */
	if (!sc->scan_complete)
		return;

	sc->scan_complete = 0;
	n = sc->scan_nresults;
	sc->scan_nresults = 0;

	for (i = 0; i < n; i++)
		brcmf_add_scan_result(sc, &sc->scan_results[i]);

	ieee80211_scan_done(vap);
}

/*
 * Handle link and association events from firmware.
 */
void
brcmf_link_event(struct brcmf_softc *sc, uint32_t event_code,
    uint32_t status, uint16_t flags)
{
	struct ieee80211com *ic = &sc->ic;
	struct ieee80211vap *vap;

	vap = TAILQ_FIRST(&ic->ic_vaps);
	if (vap == NULL)
		return;

	switch (event_code) {
	case BRCMF_E_SET_SSID:
		if (status == BRCMF_E_STATUS_SUCCESS) {
			printf("brcmfmac: SET_SSID success\n");
		} else {
			printf("brcmfmac: SET_SSID failed, status=%u\n", status);
			/* Association failed - go back to SCAN state */
			ieee80211_new_state(vap, IEEE80211_S_SCAN, -1);
		}
		break;

	case BRCMF_E_LINK:
		if (flags & BRCMF_EVENT_MSG_LINK) {
			printf("brcmfmac: link up\n");
			/* Association complete - transition to RUN */
			ieee80211_new_state(vap, IEEE80211_S_RUN, -1);
		} else {
			printf("brcmfmac: link down\n");
			/* Disconnected - go back to SCAN state */
			ieee80211_new_state(vap, IEEE80211_S_SCAN, -1);
		}
		break;

	default:
		break;
	}
}

/*
 * Initiate association to a BSS.
 */
static int
brcmf_join_bss(struct brcmf_softc *sc, struct ieee80211_node *ni)
{
	struct brcmf_join_params join;
	int error;

	printf("brcmfmac: joining BSS %02x:%02x:%02x:%02x:%02x:%02x \"%.*s\"\n",
	    ni->ni_bssid[0], ni->ni_bssid[1], ni->ni_bssid[2],
	    ni->ni_bssid[3], ni->ni_bssid[4], ni->ni_bssid[5],
	    ni->ni_esslen, ni->ni_essid);

	/* Set infrastructure mode */
	error = brcmf_fil_iovar_int_set(sc, "infra", 1);
	if (error != 0) {
		printf("brcmfmac: failed to set infra mode: %d\n", error);
		return error;
	}

	/* Build join parameters */
	memset(&join, 0, sizeof(join));
	join.ssid_le.SSID_len = htole32(ni->ni_esslen);
	memcpy(join.ssid_le.SSID, ni->ni_essid, ni->ni_esslen);
	memcpy(join.params_le.bssid, ni->ni_bssid, 6);

	/* Initiate association */
	error = brcmf_fil_cmd_data_set(sc, BRCMF_C_SET_SSID, &join, sizeof(join));
	if (error != 0) {
		printf("brcmfmac: SET_SSID failed: %d\n", error);
		return error;
	}

	return 0;
}

/*
 * Decode chanspec to control channel number.
 */
static int
brcmf_chanspec_to_channel(uint16_t chanspec)
{
	int ch = chanspec & BRCMF_CHSPEC_CHAN_MASK;
	int bw = (chanspec & BRCMF_CHSPEC_D11AC_BW_MASK) >> BRCMF_CHSPEC_D11AC_BW_SHIFT;
	int sb = (chanspec & BRCMF_CHSPEC_D11AC_SB_MASK) >> BRCMF_CHSPEC_D11AC_SB_SHIFT;

	switch (bw) {
	case 2: /* 20 MHz */
		return ch;
	case 3: /* 40 MHz */
		return (sb == 0) ? ch - 2 : ch + 2;
	case 4: /* 80 MHz */
		switch (sb) {
		case 0: return ch - 6;
		case 1: return ch - 2;
		case 2: return ch + 2;
		case 3: return ch + 6;
		}
		break;
	case 5: /* 160 MHz */
		return ch - 14 + sb * 4;
	}
	return ch;
}

/*
 * Configure event mask in firmware.
 */
static int
brcmf_setup_events(struct brcmf_softc *sc)
{
	uint8_t evmask[BRCMF_EVENTING_MASK_LEN];
	int error;

	memset(evmask, 0, sizeof(evmask));

	/* Enable IF event (always needed) */
	evmask[BRCMF_E_IF / 8] |= 1 << (BRCMF_E_IF % 8);

	/* Enable ESCAN_RESULT event */
	evmask[BRCMF_E_ESCAN_RESULT / 8] |= 1 << (BRCMF_E_ESCAN_RESULT % 8);

	/* Enable association events */
	evmask[BRCMF_E_SET_SSID / 8] |= 1 << (BRCMF_E_SET_SSID % 8);
	evmask[BRCMF_E_LINK / 8] |= 1 << (BRCMF_E_LINK % 8);

	error = brcmf_fil_iovar_data_set(sc, "event_msgs", evmask, sizeof(evmask));
	if (error != 0)
		device_printf(sc->dev, "failed to set event_msgs: %d\n", error);

	return error;
}

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
	device_printf(sc->dev, "MAC address %02x:%02x:%02x:%02x:%02x:%02x\n",
	    sc->macaddr[0], sc->macaddr[1], sc->macaddr[2],
	    sc->macaddr[3], sc->macaddr[4], sc->macaddr[5]);

	return (0);
}

/*
 * Convert channel number to chanspec.
 */
static uint16_t
brcmf_channel_to_chanspec(int channel)
{
	uint16_t chanspec;

	chanspec = channel & BRCMF_CHANSPEC_CHAN_MASK;
	chanspec |= BRCMF_CHANSPEC_BW_20;
	chanspec |= BRCMF_CHANSPEC_CTL_SB_NONE;

	if (channel <= 14)
		chanspec |= BRCMF_CHANSPEC_BAND_2G;
	else
		chanspec |= BRCMF_CHANSPEC_BAND_5G;

	return htole16(chanspec);
}

/*
 * Start enhanced scan.
 */
static int
brcmf_do_escan(struct brcmf_softc *sc)
{
	struct brcmf_escan_params_le *params;
	size_t params_size;
	int nchan, i, error;

	nchan = 14;
	params_size = sizeof(*params) + nchan * sizeof(uint16_t);
	params = malloc(params_size, M_BRCMFMAC, M_NOWAIT | M_ZERO);
	if (params == NULL)
		return (ENOMEM);

	params->version = htole32(BRCMF_ESCAN_REQ_VERSION);
	params->action = htole16(WL_ESCAN_ACTION_START);
	params->sync_id = htole16(sc->escan_sync_id++);

	/* Scan all SSIDs */
	params->params_le.ssid_le.SSID_len = 0;

	/* Broadcast BSSID */
	memset(params->params_le.bssid, 0xff, 6);

	params->params_le.bss_type = DOT11_BSSTYPE_ANY;
	params->params_le.scan_type = 0;
	params->params_le.nprobes = htole32(-1);
	params->params_le.active_time = htole32(-1);
	params->params_le.passive_time = htole32(-1);
	params->params_le.home_time = htole32(-1);

	/* Add 2.4GHz channels */
	params->params_le.channel_num = htole32(nchan);
	for (i = 0; i < nchan; i++)
		params->params_le.channel_list[i] =
		    brcmf_channel_to_chanspec(i + 1);

	sc->scan_active = 1;

	error = brcmf_fil_iovar_data_set(sc, "escan", params, params_size);
	if (error != 0) {
		sc->scan_active = 0;
	}

	free(params, M_BRCMFMAC);
	return (error);
}

/*
 * Process escan result event.
 */
void
brcmf_escan_result(struct brcmf_softc *sc, void *data, uint32_t datalen)
{
	struct ieee80211com *ic = &sc->ic;
	struct ieee80211vap *vap;
	struct brcmf_escan_result_le *result;
	struct brcmf_bss_info_le *bi;
	uint32_t buflen;
	uint16_t bss_count;

	/* Minimum size is just the header (buflen, version, sync_id, bss_count) */
	if (datalen < 12) {
		printf("brcmfmac: escan result too short: %u\n", datalen);
		return;
	}

	result = data;
	buflen = le32toh(result->buflen);
	bss_count = le16toh(result->bss_count);

	vap = TAILQ_FIRST(&ic->ic_vaps);
	if (vap == NULL)
		return;

	if (bss_count == 0) {
		sc->scan_active = 0;
		sc->scan_complete = 1;
		taskqueue_enqueue(taskqueue_thread, &sc->scan_task);
		return;
	}

	bi = &result->bss_info_le;
	while (bss_count > 0 && (uint8_t *)bi < (uint8_t *)data + buflen) {
		uint32_t bi_len = le32toh(bi->length);
		uint8_t *raw = (uint8_t *)bi;
		struct brcmf_scan_result *sr;
		uint16_t chanspec, ie_off;
		uint32_t ie_len;
		int16_t rssi;
		int8_t noise;
		int chan;

		if (bi_len < 80 || bi_len > buflen)
			break;

		/* Extract fields using verified raw offsets */
		chanspec = le16toh(*(uint16_t *)&raw[72]);
		rssi = (int16_t)le16toh(*(uint16_t *)&raw[78]);
		noise = (int8_t)raw[80];
		ie_off = le16toh(*(uint16_t *)&raw[110]);
		ie_len = le32toh(*(uint32_t *)&raw[112]);
		chan = brcmf_chanspec_to_channel(chanspec);

		/* Cache result for deferred processing (no locking for now) */
		if (sc->scan_nresults < BRCMF_SCAN_RESULTS_MAX) {
			sr = &sc->scan_results[sc->scan_nresults++];
			memcpy(sr->bssid, bi->BSSID, 6);
			sr->ssid_len = bi->SSID_len > 32 ? 32 : bi->SSID_len;
			memcpy(sr->ssid, bi->SSID, sr->ssid_len);
			sr->chan = chan;
			sr->rssi = rssi;
			sr->noise = noise;
			sr->capinfo = le16toh(bi->capability);
			sr->bintval = le16toh(bi->beacon_period);
			if (ie_len > BRCMF_SCAN_IE_MAX)
				ie_len = BRCMF_SCAN_IE_MAX;
			if (ie_off + ie_len <= bi_len) {
				sr->ie_len = ie_len;
				memcpy(sr->ie, raw + ie_off, ie_len);
			} else {
				sr->ie_len = 0;
			}
		}

		bi = (struct brcmf_bss_info_le *)((uint8_t *)bi + bi_len);
		bss_count--;
	}

	/* Schedule task to process cached results */
	taskqueue_enqueue(taskqueue_thread, &sc->scan_task);
}

/*
 * VAP state change handler.
 */
static int
brcmf_newstate(struct ieee80211vap *vap, enum ieee80211_state nstate, int arg)
{
	struct brcmf_vap *bvap = BRCMF_VAP(vap);
	struct ieee80211com *ic = vap->iv_ic;
	struct brcmf_softc *sc = ic->ic_softc;

	IEEE80211_UNLOCK(ic);

	switch (nstate) {
	case IEEE80211_S_INIT:
		break;
	case IEEE80211_S_SCAN:
		break;
	case IEEE80211_S_AUTH:
		/* FullMAC: initiate association on AUTH state */
		if (vap->iv_bss != NULL)
			brcmf_join_bss(sc, vap->iv_bss);
		break;
	case IEEE80211_S_ASSOC:
		break;
	case IEEE80211_S_RUN:
		sc->running = 1;
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
			brcmf_fil_bss_up(sc);
			sc->running = 1;
			startall = 1;
		}
	} else {
		if (sc->running) {
			brcmf_fil_bss_down(sc);
			sc->running = 0;
		}
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
	struct brcmf_softc *sc = ic->ic_softc;


	brcmf_do_escan(sc);
}

/*
 * End a scan.
 */
static void
brcmf_scan_end(struct ieee80211com *ic)
{

}

/*
 * Set channel (called by net80211 during scan).
 */
static void
brcmf_set_channel(struct ieee80211com *ic)
{
	/* FullMAC: firmware handles channel switching during scan */
}

/*
 * Transmit a frame.
 */
static int
brcmf_transmit(struct ieee80211com *ic, struct mbuf *m)
{
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

	setbit(bands, IEEE80211_MODE_11B);
	setbit(bands, IEEE80211_MODE_11G);

	ieee80211_add_channels_default_2ghz(chans, maxchans, nchans, bands, 0);

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

	brcmf_setup_events(sc);

	/* mtx_init(&sc->scan_mtx, "brcmf_scan", NULL, MTX_SPIN); */
	TASK_INIT(&sc->scan_task, 0, brcmf_scan_complete_task, sc);

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
