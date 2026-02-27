// SPDX-License-Identifier: ISC
/*
 * Copyright (c) 2010-2022 Broadcom Corporation
 * Copyright (c) brcmfmac-freebsd contributors
 *
 * Based on the Linux brcmfmac driver.
 */

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

	if (sc->detaching)
		return;

	vap = TAILQ_FIRST(&ic->ic_vaps);
	if (vap == NULL)
		return;

	if (sc->link_up) {
		uint32_t chanspec_raw;
		int bw, sb;

		memcpy(bssid, sc->join_bssid, 6);

		error = brcmf_fil_iovar_int_get(sc, "chanspec",
		    &chanspec_raw);
		if (error != 0) {
			error = brcmf_fil_cmd_data_get(sc, BRCMF_C_GET_CHANNEL,
			    &chanspec_raw, sizeof(chanspec_raw));
		}
		if (error != 0) {
			channum = 1;
			bw = 2; /* 20 MHz */
			sb = 0;
		} else {
			channum = brcmf_chanspec_to_channel(chanspec_raw);
			bw = (chanspec_raw & BRCMF_CHSPEC_D11AC_BW_MASK) >>
			    BRCMF_CHSPEC_D11AC_BW_SHIFT;
			sb = (chanspec_raw & BRCMF_CHSPEC_D11AC_SB_MASK) >>
			    BRCMF_CHSPEC_D11AC_SB_SHIFT;
		}

		{
			int freq = ieee80211_ieee2mhz(channum,
			    channum <= 14 ? IEEE80211_CHAN_2GHZ :
			    IEEE80211_CHAN_5GHZ);
			int base = channum <= 14 ?
			    IEEE80211_CHAN_G : IEEE80211_CHAN_A;

			chan = NULL;

			/* Try VHT80 */
			if (bw == 4) {
				int htdir = (sb & 1) ?
				    IEEE80211_CHAN_HT40D :
				    IEEE80211_CHAN_HT40U;
				chan = ieee80211_find_channel(ic, freq,
				    base | htdir |
				    IEEE80211_CHAN_VHT80);
			}

			/* Try HT40 */
			if (bw >= 3 && chan == NULL) {
				int htflag = (sb & 1) ?
				    IEEE80211_CHAN_HT40D :
				    IEEE80211_CHAN_HT40U;
				chan = ieee80211_find_channel(ic, freq,
				    base | htflag);
			}

			/* HT20 */
			if (chan == NULL)
				chan = ieee80211_find_channel(ic, freq,
				    base | IEEE80211_CHAN_HT20);

			/* Legacy */
			if (chan == NULL)
				chan = ieee80211_find_channel(ic, freq,
				    base);
			if (chan == NULL)
				chan = &ic->ic_channels[0];
		}

		ic->ic_curchan = chan;
		ic->ic_bsschan = chan;

		ni = vap->iv_bss;
		if (ni != NULL) {
			IEEE80211_ADDR_COPY(ni->ni_bssid, bssid);
			IEEE80211_ADDR_COPY(ni->ni_macaddr, bssid);
			ni->ni_chan = chan;
			if (chan->ic_flags & IEEE80211_CHAN_HT) {
				ni->ni_flags |= IEEE80211_NODE_HT;
				ni->ni_htcap = ic->ic_htcaps;
				ni->ni_htrates.rs_nrates = 8;
				for (int i = 0; i < 8; i++)
					ni->ni_htrates.rs_rates[i] = i;
				ieee80211_node_set_txrate_ht_mcsrate(ni, 7);
			}
			if (chan->ic_flags & IEEE80211_CHAN_VHT) {
				ni->ni_flags |= IEEE80211_NODE_VHT;
				ni->ni_vhtcap =
				    ic->ic_vht_cap.vht_cap_info;
				ni->ni_vht_mcsinfo =
				    ic->ic_vht_cap.supp_mcs;
				if (bw >= 4)
					ni->ni_vht_chanwidth =
					    IEEE80211_VHT_CHANWIDTH_80MHZ;
				else
					ni->ni_vht_chanwidth =
					    IEEE80211_VHT_CHANWIDTH_USE_HT;
			}
			if (vap->iv_des_nssid > 0) {
				ni->ni_esslen = vap->iv_des_ssid[0].len;
				memcpy(ni->ni_essid, vap->iv_des_ssid[0].ssid,
				    ni->ni_esslen);
			}
			ieee80211_new_state(vap, IEEE80211_S_RUN,
			    IEEE80211_FC0_SUBTYPE_ASSOC_RESP);

			brcmf_msgbuf_delete_flowring(sc);
			brcmf_msgbuf_init_flowring(sc, bssid);

			/* Receive all multicast frames (no filtering) */
			brcmf_fil_iovar_int_set(sc, "allmulti", 1);
		}
	} else {
		if (vap->iv_state > IEEE80211_S_SCAN)
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
		sc->link_up = (flags & BRCMF_EVENT_MSG_LINK) ? 1 : 0;
		if (!sc->link_up) {
			sc->scan_active = 0;
			sc->scan_complete = 0;
		}
		taskqueue_enqueue(taskqueue_thread, &sc->link_task);
		break;

	case BRCMF_E_DEAUTH:
	case BRCMF_E_DEAUTH_IND:
	case BRCMF_E_DISASSOC:
	case BRCMF_E_DISASSOC_IND:
		if (sc->link_up) {
			sc->link_up = 0;
			sc->scan_active = 0;
			sc->scan_complete = 0;
			taskqueue_enqueue(taskqueue_thread, &sc->link_task);
		}
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

	/*
	 * Skip WPA networks on the direct-join path. Without an
	 * external supplicant (wpa_supplicant) nobody will handle
	 * the 4-way handshake, and the AP will deauth us.
	 */
	if (wpa_auth != WPA_AUTH_DISABLED)
		return (EINVAL);

	error = brcmf_set_security(sc, wsec, wpa_auth);
	if (error != 0)
		return error;

	/* Host-managed WPA; firmware supplicant broken on this chip */
	brcmf_fil_iovar_int_set(sc, "sup_wpa", 0);

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

	error = brcmf_fil_cmd_data_set(sc, BRCMF_C_SET_SSID, &join, sizeof(join));
	if (error != 0)
		return error;

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
	evmask[BRCMF_E_DEAUTH / 8] |= 1 << (BRCMF_E_DEAUTH % 8);
	evmask[BRCMF_E_DEAUTH_IND / 8] |= 1 << (BRCMF_E_DEAUTH_IND % 8);
	evmask[BRCMF_E_DISASSOC / 8] |= 1 << (BRCMF_E_DISASSOC % 8);
	evmask[BRCMF_E_DISASSOC_IND / 8] |= 1 << (BRCMF_E_DISASSOC_IND % 8);

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

	if (sc->detaching)
		goto done;

	switch (nstate) {
	case IEEE80211_S_INIT:
		if (sc->link_up) {
			struct {
				uint32_t val;
				uint8_t ea[6];
				uint8_t pad[2];
			} scbval;
			memset(&scbval, 0, sizeof(scbval));
			scbval.val = htole32(3); /* DEAUTH_LEAVING */
			memcpy(scbval.ea, sc->join_bssid, 6);
			brcmf_fil_cmd_data_set(sc,
			    52 /* BRCMF_C_DISASSOC */,
			    &scbval, sizeof(scbval));
			sc->link_up = 0;
		}
		sc->scan_active = 0;
		sc->scan_complete = 0;
		sc->running = 0;
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

			brcmf_set_security(sc, wsec, wpa_auth);
			/* Host-managed WPA; firmware supplicant broken on this chip */
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

done:
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

	if (sc->detaching)
		return;

	if (ic->ic_nrunning > 0) {
		if (!sc->running) {
			uint32_t val;

			brcmf_fil_bss_up(sc);

			val = htole32(1);
			brcmf_fil_cmd_data_set(sc, BRCMF_C_SET_INFRA,
			    &val, sizeof(val));

			val = htole32(0);
			brcmf_fil_cmd_data_set(sc, BRCMF_C_SET_PM,
			    &val, sizeof(val));

			/* Keep radio on during idle */
			brcmf_fil_iovar_int_set(sc, "mpc", 0);
			/* No firmware-initiated roaming */
			brcmf_fil_iovar_int_set(sc, "roam_off", 1);
			/* Disable firmware ARP offload */
			brcmf_fil_iovar_int_set(sc, "arp_ol", 0);
			brcmf_fil_iovar_int_set(sc, "arpoe", 0);

			sc->running = 1;
			startall = 1;
		}
	} else {
		if (sc->link_up) {
			struct {
				uint32_t val;
				uint8_t ea[6];
				uint8_t pad[2];
			} scbval;
			memset(&scbval, 0, sizeof(scbval));
			scbval.val = htole32(3); /* DEAUTH_LEAVING */
			memcpy(scbval.ea, sc->join_bssid, 6);
			brcmf_fil_cmd_data_set(sc,
			    52 /* BRCMF_C_DISASSOC */,
			    &scbval, sizeof(scbval));
			sc->link_up = 0;
		}
		/* Clear security state so stale keys don't interfere
		 * with the next association's EAPOL handshake. */
		brcmf_fil_iovar_int_set(sc, "wsec", 0);
		brcmf_fil_iovar_int_set(sc, "wpa_auth", 0);
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
	setbit(bands, IEEE80211_MODE_11NG);

	ieee80211_add_channels_default_2ghz(chans, maxchans, nchans, bands,
	    NET80211_CBW_FLAG_HT40);

	memset(bands, 0, sizeof(bands));
	setbit(bands, IEEE80211_MODE_11A);
	setbit(bands, IEEE80211_MODE_11NA);
	setbit(bands, IEEE80211_MODE_VHT_5GHZ);

	ieee80211_add_channel_list_5ghz(chans, maxchans, nchans,
	    (const uint8_t[]){36, 40, 44, 48, 52, 56, 60, 64,
	    100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144,
	    149, 153, 157, 161, 165}, 25, bands,
	    NET80211_CBW_FLAG_HT40 | NET80211_CBW_FLAG_VHT80);
}

int
brcmf_cfg_attach(struct brcmf_softc *sc)
{
	struct ieee80211com *ic = &sc->ic;
	int error;

	error = brcmf_get_macaddr(sc);
	if (error != 0)
		return (error);

	/* Set regulatory domain so firmware enables 5GHz channels */
	{
		struct {
			char country_abbrev[4];
			uint32_t rev;
			char ccode[4];
		} __packed country;
		memset(&country, 0, sizeof(country));
		strlcpy(country.country_abbrev, "DE", sizeof(country.country_abbrev));
		strlcpy(country.ccode, "DE", sizeof(country.ccode));
		country.rev = htole32(0);
		error = brcmf_fil_iovar_data_set(sc, "country",
		    &country, sizeof(country));
		if (error != 0)
			device_printf(sc->dev,
			    "failed to set country: %d\n", error);
	}

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

	ic->ic_htcaps =
	    IEEE80211_HTCAP_CHWIDTH40 |
	    IEEE80211_HTCAP_SMPS_OFF |
	    IEEE80211_HTCAP_SHORTGI20 |
	    IEEE80211_HTCAP_SHORTGI40 |
	    IEEE80211_HTCAP_DSSSCCK40 |
	    IEEE80211_HTCAP_MAXAMSDU_3839;

	/* BCM4350: 2SS VHT, MCS 0-9, SGI80 */
	ic->ic_vht_cap.vht_cap_info =
	    IEEE80211_VHTCAP_MAX_MPDU_LENGTH_3895 |
	    IEEE80211_VHTCAP_SHORT_GI_80 |
	    IEEE80211_VHTCAP_RXLDPC;
	/* 2SS MCS 0-9, streams 3-8 unsupported */
	ic->ic_vht_cap.supp_mcs.rx_mcs_map = htole16(
	    IEEE80211_VHT_MCS_SUPPORT_0_9 |
	    (IEEE80211_VHT_MCS_SUPPORT_0_9 << 2) |
	    (IEEE80211_VHT_MCS_NOT_SUPPORTED << 4) |
	    (IEEE80211_VHT_MCS_NOT_SUPPORTED << 6) |
	    (IEEE80211_VHT_MCS_NOT_SUPPORTED << 8) |
	    (IEEE80211_VHT_MCS_NOT_SUPPORTED << 10) |
	    (IEEE80211_VHT_MCS_NOT_SUPPORTED << 12) |
	    (IEEE80211_VHT_MCS_NOT_SUPPORTED << 14));
	ic->ic_vht_cap.supp_mcs.tx_mcs_map =
	    ic->ic_vht_cap.supp_mcs.rx_mcs_map;
	/* Max rate: 867 Mbps (VHT80 2SS MCS9 SGI) */
	ic->ic_vht_cap.supp_mcs.rx_highest = htole16(867);
	ic->ic_vht_cap.supp_mcs.tx_highest = htole16(867);

	/*
	 * Set regdomain to DEBUG so the channel list isn't filtered
	 * by regulatory rules. The firmware handles regulatory.
	 */
	ic->ic_regdomain.regdomain = 0x1ff; /* SKU_DEBUG */
	ic->ic_regdomain.country = 0x1ff;   /* CTRY_DEBUG */
	ic->ic_regdomain.location = ' ';
	ic->ic_regdomain.isocc[0] = 'D';
	ic->ic_regdomain.isocc[1] = 'B';

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

	if (bootverbose)
		ieee80211_announce(ic);

	sc->cfg_attached = 1;
	return (0);
}

void
brcmf_cfg_detach(struct brcmf_softc *sc)
{
	struct ieee80211com *ic = &sc->ic;

	if (!sc->cfg_attached)
		return;
	sc->cfg_attached = 0;
	sysctl_ctx_free(&sc->sysctl_ctx);

	/*
	 * Drain tasks that may issue firmware ioctls before tearing down
	 * net80211. Both run on taskqueue_thread; sc->detaching ensures
	 * they exit without touching the firmware if re-enqueued.
	 */
	taskqueue_drain(taskqueue_thread, &sc->link_task);
	taskqueue_drain(taskqueue_thread, &sc->restart_task);

	ieee80211_ifdetach(ic);
}
