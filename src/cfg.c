/* net80211 interface: VAP management, attach/detach, link events */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bus.h>
#include <sys/endian.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/sysctl.h>
#include <sys/taskqueue.h>

#include <net/if.h>
#include <net/if_var.h>
#include <net/if_media.h>
#include <net/ethernet.h>

#include <net80211/ieee80211_var.h>

#include "cfg.h"

static int brcmf_vap_transmit(if_t ifp, struct mbuf *m);

/*
 * Link state change task - runs in process context.
 */
static void
brcmf_link_task(void *arg, int pending)
{
	struct brcmf_softc *sc = arg;
	struct ieee80211com *ic = &sc->ic;
	struct ieee80211vap *vap;
	struct ieee80211_node *ni;
	struct ieee80211_channel *chan;
	uint8_t bssid[6];
	uint32_t channum;
	int error;

	vap = TAILQ_FIRST(&ic->ic_vaps);
	if (vap == NULL)
		return;

	if (sc->link_up) {
		memcpy(bssid, sc->join_bssid, 6);

		error = brcmf_fil_iovar_int_get(sc, "chanspec", &channum);
		if (error != 0) {
			error = brcmf_fil_cmd_data_get(sc, BRCMF_C_GET_CHANNEL,
			    &channum, sizeof(channum));
		}
		if (error != 0)
			channum = 1;
		else
			channum = brcmf_chanspec_to_channel(channum);

		chan = ieee80211_find_channel(ic, channum,
		    channum <= 14 ? IEEE80211_CHAN_G : IEEE80211_CHAN_A);
		if (chan == NULL)
			chan = &ic->ic_channels[0];

		ic->ic_curchan = chan;
		ic->ic_bsschan = chan;

		ni = vap->iv_bss;
		if (ni != NULL) {
			IEEE80211_ADDR_COPY(ni->ni_bssid, bssid);
			IEEE80211_ADDR_COPY(ni->ni_macaddr, bssid);
			ni->ni_chan = chan;
			if (vap->iv_des_nssid > 0) {
				ni->ni_esslen = vap->iv_des_ssid[0].len;
				memcpy(ni->ni_essid, vap->iv_des_ssid[0].ssid,
				    ni->ni_esslen);
			}
			ieee80211_new_state(vap, IEEE80211_S_RUN,
			    IEEE80211_FC0_SUBTYPE_ASSOC_RESP);

			brcmf_msgbuf_delete_flowring(sc);
			brcmf_msgbuf_init_flowring(sc, bssid);

			brcmf_fil_iovar_int_set(sc, "allmulti", 1);
			brcmf_msgbuf_repost_rxbufs(sc);

			/* Debug: read back assoc_req_ies */
			error = brcmf_fil_iovar_data_get(sc,
			    "assoc_req_ies", NULL, 256);
			if (error == 0) {
				uint8_t *p = sc->ioctlbuf;
				uint32_t alen = le32toh(*(uint32_t *)p);
				int j;
				printf("brcmfmac: assoc_req_ies len=%u:",
				    alen);
				for (j = 4; j < (int)(4 + alen) &&
				    j < 60; j++)
					printf(" %02x", p[j]);
				printf("\n");
			} else {
				printf("brcmfmac: assoc_req_ies get: %d\n",
				    error);
			}
		}
	} else {
		ieee80211_new_state(vap, IEEE80211_S_SCAN, -1);
	}
}

/*
 * Handle link and association events from firmware.
 */
void
brcmf_link_event(struct brcmf_softc *sc, uint32_t event_code,
    uint32_t status, uint16_t flags)
{
	switch (event_code) {
	case BRCMF_E_SET_SSID:
		if (status != BRCMF_E_STATUS_SUCCESS) {
			device_printf(sc->dev, "SET_SSID failed, status=%u\n", status);
			sc->link_up = 0;
			taskqueue_enqueue(taskqueue_thread, &sc->link_task);
		}
		break;

	case BRCMF_E_LINK:
		printf("brcmfmac: LINK event flags=0x%x link=%d\n",
		    flags, !!(flags & BRCMF_EVENT_MSG_LINK));
		sc->link_up = (flags & BRCMF_EVENT_MSG_LINK) ? 1 : 0;
		taskqueue_enqueue(taskqueue_thread, &sc->link_task);
		break;

	default:
		break;
	}
}

/*
 * Initiate association to a BSS using scan result.
 */
int
brcmf_join_bss_direct(struct brcmf_softc *sc, struct brcmf_scan_result *sr)
{
	struct brcmf_join_params join;
	uint32_t wsec, wpa_auth;
	int error;

	wsec = brcmf_detect_security(sr, &wpa_auth);
	error = brcmf_set_security(sc, wsec, wpa_auth);
	if (error != 0)
		return error;

	brcmf_fil_iovar_int_set(sc, "sup_wpa", 0);

	if (wpa_auth != WPA_AUTH_DISABLED && sc->psk_len > 0)
		brcmf_set_pmk(sc, sc->psk, sc->psk_len);

	memcpy(sc->join_bssid, sr->bssid, 6);

	memset(&join, 0, sizeof(join));
	join.ssid_le.SSID_len = htole32(sr->ssid_len);
	memcpy(join.ssid_le.SSID, sr->ssid, sr->ssid_len);
	memcpy(join.params_le.bssid, sr->bssid, 6);

	error = brcmf_fil_cmd_data_set(sc, BRCMF_C_SET_SSID, &join, sizeof(join));
	if (error != 0)
		return error;

	return 0;
}

/*
 * Initiate association to a BSS (from net80211 node).
 */
static int
brcmf_join_bss(struct brcmf_softc *sc, struct ieee80211_node *ni)
{
	struct brcmf_join_params join;
	int error;

	memcpy(sc->join_bssid, ni->ni_bssid, 6);

	memset(&join, 0, sizeof(join));
	join.ssid_le.SSID_len = htole32(ni->ni_esslen);
	memcpy(join.ssid_le.SSID, ni->ni_essid, ni->ni_esslen);
	memcpy(join.params_le.bssid, ni->ni_bssid, 6);

	printf("brcmfmac: SET_SSID ssid='%.*s' len=%d\n",
	    ni->ni_esslen, ni->ni_essid, ni->ni_esslen);
	error = brcmf_fil_cmd_data_set(sc, BRCMF_C_SET_SSID, &join, sizeof(join));
	if (error != 0) {
		printf("brcmfmac: SET_SSID ioctl error=%d\n", error);
		return error;
	}

	return 0;
}

static int
brcmf_setup_events(struct brcmf_softc *sc)
{
	uint8_t evmask[BRCMF_EVENTING_MASK_LEN];
	int error;

	memset(evmask, 0, sizeof(evmask));

	evmask[BRCMF_E_IF / 8] |= 1 << (BRCMF_E_IF % 8);
	evmask[BRCMF_E_ESCAN_RESULT / 8] |= 1 << (BRCMF_E_ESCAN_RESULT % 8);
	evmask[BRCMF_E_SET_SSID / 8] |= 1 << (BRCMF_E_SET_SSID % 8);
	evmask[BRCMF_E_LINK / 8] |= 1 << (BRCMF_E_LINK % 8);

	error = brcmf_fil_iovar_data_set(sc, "event_msgs", evmask, sizeof(evmask));
	if (error != 0)
		device_printf(sc->dev, "failed to set event_msgs: %d\n", error);

	return error;
}

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
 * Re-start the VAP after a deferred INIT transition completes.
 * The SIOCSIFFLAGS UP handler checks iv_state==INIT to call
 * ieee80211_start_locked. When the INIT transition is deferred,
 * iv_state may not be INIT yet when UP runs, leaving ic_nrunning
 * at 0 and all scan ioctls failing with ENXIO.
 */
static void
brcmf_restart_task(void *arg, int pending)
{
	struct brcmf_softc *sc = arg;
	struct ieee80211com *ic = &sc->ic;
	struct ieee80211vap *vap;

	IEEE80211_LOCK(ic);
	vap = TAILQ_FIRST(&ic->ic_vaps);
	if (vap != NULL &&
	    vap->iv_state == IEEE80211_S_INIT &&
	    (if_getflags(vap->iv_ifp) & IFF_UP) &&
	    ic->ic_nrunning == 0)
		ieee80211_start_locked(vap);
	IEEE80211_UNLOCK(ic);
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
		sc->scan_active = 0;
		sc->scan_complete = 0;
		/*
		 * Schedule restart check after this deferred INIT
		 * transition completes.
		 */
		taskqueue_enqueue(ic->ic_tq, &sc->restart_task);
		break;
	case IEEE80211_S_SCAN:
		break;
	case IEEE80211_S_AUTH: {
		struct ieee80211_node *ni = vap->iv_bss;
		if (ni != NULL) {
			uint32_t wsec = WSEC_NONE;
			uint32_t wpa_auth = WPA_AUTH_DISABLED;

			if (vap->iv_flags & IEEE80211_F_WPA2) {
				wsec = AES_ENABLED;
				wpa_auth = WPA2_AUTH_PSK;
			} else if (vap->iv_flags & IEEE80211_F_WPA1) {
				wsec = TKIP_ENABLED;
				wpa_auth = WPA_AUTH_PSK;
			}
			if (vap->iv_flags & IEEE80211_F_PRIVACY)
				wsec |= AES_ENABLED;

			printf("brcmfmac: AUTH wsec=0x%x wpa_auth=0x%x\n",
			    wsec, wpa_auth);
			brcmf_set_security(sc, wsec, wpa_auth);
			brcmf_fil_iovar_int_set(sc, "sup_wpa", 0);
			brcmf_join_bss(sc, ni);
		}
		break;
	}
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
	vap->iv_key_set = brcmf_key_set;
	vap->iv_key_delete = brcmf_key_delete;

	ieee80211_vap_attach(vap, ieee80211_media_change,
	    ieee80211_media_status, mac);

	if_settransmitfn(vap->iv_ifp, brcmf_vap_transmit);

	/*
	 * Pre-set ss_vap so scan_curchan_task doesn't fault on
	 * IEEE80211_DPRINTF(ss->ss_vap, ...) if the task fires
	 * before ieee80211_swscan_start_scan_locked sets it.
	 */
	if (ic->ic_scan != NULL)
		ic->ic_scan->ss_vap = vap;

	ic->ic_opmode = opmode;

	return (vap);
}

/*
 * Match the swscan private scan state layout so we can access
 * the scan tasks for draining.
 */
struct brcmf_scan_priv {
	struct ieee80211_scan_state base;
	u_int iflags;
	unsigned long chanmindwell;
	unsigned long scanend;
	u_int duration;
	struct task scan_start;
	struct timeout_task scan_curchan;
};

/*
 * Drain swscan tasks before VAP teardown. scan_curchan_task accesses
 * ss->ss_vap which becomes NULL/freed after ieee80211_vap_detach.
 * The kernel doesn't drain these tasks until ieee80211_scan_detach,
 * which runs much later.
 */
static void
brcmf_drain_scan_tasks(struct ieee80211com *ic)
{
	struct ieee80211_scan_state *ss = ic->ic_scan;
	struct brcmf_scan_priv *priv = (struct brcmf_scan_priv *)ss;

	if (ss == NULL)
		return;

	IEEE80211_LOCK(ic);
	priv->iflags |= 0x0018; /* ISCAN_CANCEL | ISCAN_ABORT */
	if (priv->iflags & 0x0020 /* ISCAN_RUNNING */) {
		taskqueue_cancel_timeout(ic->ic_tq, &priv->scan_curchan,
		    NULL);
		taskqueue_enqueue_timeout(ic->ic_tq, &priv->scan_curchan, 0);
	}
	IEEE80211_UNLOCK(ic);

	ieee80211_draintask(ic, &priv->scan_start);
	taskqueue_drain_timeout(ic->ic_tq, &priv->scan_curchan);
}

static void
brcmf_vap_delete(struct ieee80211vap *vap)
{
	struct ieee80211com *ic = vap->iv_ic;
	struct brcmf_vap *bvap = BRCMF_VAP(vap);

	ieee80211_vap_detach(vap);
	brcmf_drain_scan_tasks(ic);
	free(bvap, M_80211_VAP);
}

static void
brcmf_parent(struct ieee80211com *ic)
{
	struct brcmf_softc *sc = ic->ic_softc;
	int startall = 0;

	if (ic->ic_nrunning > 0) {
		if (!sc->running) {
			uint32_t val;

			brcmf_fil_iovar_int_set(sc, "mpc", 0);
			brcmf_fil_bss_up(sc);

			val = htole32(1);
			brcmf_fil_cmd_data_set(sc, BRCMF_C_SET_INFRA,
			    &val, sizeof(val));

			val = htole32(0);
			brcmf_fil_cmd_data_set(sc, BRCMF_C_SET_PM,
			    &val, sizeof(val));

			brcmf_fil_iovar_int_set(sc, "arp_ol", 0);
			brcmf_fil_iovar_int_set(sc, "arpoe", 0);

			sc->running = 1;
			startall = 1;
		}
	} else {
		/*
		 * Don't bring firmware BSS down on interface DOWN.
		 * wpa_supplicant cycles the interface rapidly during
		 * init, and the deferred INIT state transition in
		 * net80211 can race with the UP, leaving ic_nrunning
		 * at 0 and scan ioctls failing with ENXIO.
		 */
		sc->running = 0;
	}

	if (startall)
		ieee80211_start_all(ic);
}

static void
brcmf_scan_start(struct ieee80211com *ic)
{
	struct brcmf_softc *sc = ic->ic_softc;
	struct ieee80211vap *vap;
	const uint8_t *ssid = NULL;
	int ssid_len = 0;

	vap = TAILQ_FIRST(&ic->ic_vaps);
	if (vap == NULL)
		return;

	/*
	 * Let swscan iterate channels normally (it populates ss_chans
	 * from the channel list). We just kick off a parallel firmware
	 * scan. Swscan's channel dwell prevents busy-loop restarts.
	 */
	if (sc->scan_active)
		return;

	if (vap->iv_des_nssid > 0 && vap->iv_des_ssid[0].len > 0) {
		ssid = vap->iv_des_ssid[0].ssid;
		ssid_len = vap->iv_des_ssid[0].len;
	}

	brcmf_do_escan(sc, ssid, ssid_len);
}

static void
brcmf_scan_end(struct ieee80211com *ic)
{
	/* Don't clear scan_active — firmware escan may still be running */
}

static void
brcmf_set_channel(struct ieee80211com *ic)
{
}

/*
 * Scan current channel. For FullMAC, firmware handles channel
 * dwell and timing. We enqueue a short timeout to prevent swscan
 * from completing instantly and busy-looping. The task will check
 * ISCAN_CANCEL/ISCAN_ABORT before accessing ss_vap.
 */
static void
brcmf_scan_curchan(struct ieee80211_scan_state *ss, unsigned long maxdwell)
{
	struct ieee80211com *ic = ss->ss_ic;
	struct brcmf_softc *sc = ic->ic_softc;
	struct brcmf_scan_priv *priv = (struct brcmf_scan_priv *)ss;
	struct ieee80211vap *vap;
	unsigned long dwell;

	/*
	 * On the first channel, wait for the firmware escan to
	 * complete before letting swscan advance. For subsequent
	 * channels, use minimal dwell to finish quickly.
	 */
	if (sc->scan_complete || ss->ss_next > 1)
		dwell = 1;
	else
		dwell = maxdwell;

	IEEE80211_LOCK(ic);
	vap = TAILQ_FIRST(&ic->ic_vaps);
	if (vap != NULL)
		ss->ss_vap = vap;
	if (ss->ss_vap != NULL &&
	    (priv->iflags & (0x08 | 0x10)) == 0)  /* !CANCEL && !ABORT */
		taskqueue_enqueue_timeout(ic->ic_tq,
		    &priv->scan_curchan, dwell);
	IEEE80211_UNLOCK(ic);
}

static void
brcmf_scan_mindwell(struct ieee80211_scan_state *ss)
{
}

/*
 * VAP-level transmit: raw ethernet frames bypassing net80211 encapsulation.
 */
static int
brcmf_vap_transmit(if_t ifp, struct mbuf *m)
{
	struct ieee80211vap *vap = if_getsoftc(ifp);
	struct ieee80211com *ic = vap->iv_ic;
	struct brcmf_softc *sc = ic->ic_softc;

	if (vap->iv_state != IEEE80211_S_RUN) {
		m_freem(m);
		return (ENETDOWN);
	}

	if (m->m_len >= 14) {
		uint8_t *eh = mtod(m, uint8_t *);
		uint16_t etype = eh[12] << 8 | eh[13];
		if (etype == 0x888e) {
			int j, dlen = m->m_pkthdr.len;
			printf("brcmfmac: EAPOL tx len=%d\n", dlen);
			printf("brcmfmac: EAPOL tx data:");
			for (j = 14; j < dlen && j < 135; j++)
				printf(" %02x", eh[j]);
			printf("\n");
		}
	}

	return brcmf_msgbuf_tx(sc, m);
}

static int
brcmf_wme_update(struct ieee80211com *ic)
{
	/* Firmware handles WME parameters internally. */
	return 0;
}

static int
brcmf_transmit(struct ieee80211com *ic, struct mbuf *m)
{
	m_freem(m);
	return (0);
}

static int
brcmf_raw_xmit(struct ieee80211_node *ni, struct mbuf *m,
    const struct ieee80211_bpf_params *params)
{
	m_freem(m);
	return (0);
}

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

int
brcmf_cfg_attach(struct brcmf_softc *sc)
{
	struct ieee80211com *ic = &sc->ic;
	int error;

	error = brcmf_get_macaddr(sc);
	if (error != 0)
		return (error);

	brcmf_setup_events(sc);

	TASK_INIT(&sc->scan_task, 0, brcmf_scan_complete_task, sc);
	TASK_INIT(&sc->link_task, 0, brcmf_link_task, sc);
	TASK_INIT(&sc->restart_task, 0, brcmf_restart_task, sc);

	sysctl_ctx_init(&sc->sysctl_ctx);
	brcmf_security_sysctl_init(sc);

	ic->ic_softc = sc;
	ic->ic_name = device_get_nameunit(sc->dev);
	ic->ic_phytype = IEEE80211_T_OFDM;
	ic->ic_opmode = IEEE80211_M_STA;

	ic->ic_caps =
	    IEEE80211_C_STA |
	    IEEE80211_C_WPA |
	    IEEE80211_C_SHPREAMBLE |
	    IEEE80211_C_SHSLOT |
	    IEEE80211_C_WME;

	ic->ic_cryptocaps =
	    IEEE80211_CRYPTO_WEP |
	    IEEE80211_CRYPTO_TKIP |
	    IEEE80211_CRYPTO_AES_CCM;

	brcmf_getradiocaps(ic, IEEE80211_CHAN_MAX, &ic->ic_nchans,
	    ic->ic_channels);

	IEEE80211_ADDR_COPY(ic->ic_macaddr, sc->macaddr);

	ieee80211_ifattach(ic);

	ic->ic_wme.wme_update = brcmf_wme_update;
	ic->ic_vap_create = brcmf_vap_create;
	ic->ic_vap_delete = brcmf_vap_delete;
	ic->ic_parent = brcmf_parent;
	ic->ic_scan_start = brcmf_scan_start;
	ic->ic_scan_end = brcmf_scan_end;
	ic->ic_scan_curchan = brcmf_scan_curchan;
	ic->ic_scan_mindwell = brcmf_scan_mindwell;
	ic->ic_set_channel = brcmf_set_channel;
	ic->ic_transmit = brcmf_transmit;
	ic->ic_raw_xmit = brcmf_raw_xmit;
	ic->ic_getradiocaps = brcmf_getradiocaps;

	ieee80211_announce(ic);

	return (0);
}

void
brcmf_cfg_detach(struct brcmf_softc *sc)
{
	struct ieee80211com *ic = &sc->ic;

	sysctl_ctx_free(&sc->sysctl_ctx);
	ieee80211_ifdetach(ic);
}
