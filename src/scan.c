/* Scan: escan requests, result processing, chanspec conversion */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bus.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/socket.h>
#include <sys/taskqueue.h>

#include <net/if.h>
#include <net/if_var.h>
#include <net/if_media.h>
#include <net/ethernet.h>

#include <net80211/ieee80211_var.h>

#include "cfg.h"

int
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

uint16_t
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

int
brcmf_do_escan(struct brcmf_softc *sc, const uint8_t *ssid, int ssid_len)
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

	if (ssid != NULL && ssid_len > 0) {
		params->params_le.ssid_le.SSID_len = htole32(ssid_len);
		memcpy(params->params_le.ssid_le.SSID, ssid, ssid_len);
	}

	memset(params->params_le.bssid, 0xff, 6);

	params->params_le.bss_type = DOT11_BSSTYPE_ANY;
	params->params_le.scan_type = 0;
	params->params_le.nprobes = htole32(-1);
	params->params_le.active_time = htole32(-1);
	params->params_le.passive_time = htole32(-1);
	params->params_le.home_time = htole32(-1);

	params->params_le.channel_num = htole32(nchan);
	for (i = 0; i < nchan; i++)
		params->params_le.channel_list[i] =
		    brcmf_channel_to_chanspec(i + 1);

	sc->scan_active = 1;

	error = brcmf_fil_iovar_data_set(sc, "escan", params, params_size);
	if (error != 0)
		sc->scan_active = 0;

	free(params, M_BRCMFMAC);
	return (error);
}

void
brcmf_escan_result(struct brcmf_softc *sc, void *data, uint32_t datalen)
{
	struct ieee80211com *ic = &sc->ic;
	struct ieee80211vap *vap;
	struct brcmf_escan_result_le *result;
	struct brcmf_bss_info_le *bi;
	uint32_t buflen;
	uint16_t bss_count;

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

		if (bi_len < sizeof(*bi) || bi_len > buflen)
			break;

		chanspec = le16toh(bi->chanspec);
		rssi = (int16_t)le16toh(bi->RSSI);
		noise = bi->phy_noise;
		ie_off = le16toh(bi->ie_offset);
		ie_len = le32toh(bi->ie_length);

		if (ie_off == 0 && ie_len > 0 && ie_len < bi_len)
			ie_off = bi_len - ie_len;
		if (ie_off < sizeof(*bi))
			ie_off = sizeof(*bi);
		chan = brcmf_chanspec_to_channel(chanspec);

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

	taskqueue_enqueue(taskqueue_thread, &sc->scan_task);
}

/* Default rates IE for 2.4GHz (11b/g rates) */
static const uint8_t default_rates_ie[] = {
	IEEE80211_ELEMID_RATES, 8,
	0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24
};

void
brcmf_add_scan_result(struct brcmf_softc *sc, struct brcmf_scan_result *sr)
{
	struct ieee80211com *ic = &sc->ic;
	struct ieee80211vap *vap;
	struct ieee80211_scanparams sp;
	struct ieee80211_frame wh;
	struct ieee80211_channel *chan;
	uint8_t ssid_ie[2 + 32];
	uint8_t tstamp[8];

	vap = TAILQ_FIRST(&ic->ic_vaps);
	if (vap == NULL)
		return;

	chan = ieee80211_find_channel(ic, sr->chan,
	    sr->chan <= 14 ? IEEE80211_CHAN_G : IEEE80211_CHAN_A);
	if (chan == NULL)
		chan = &ic->ic_channels[0];

	ssid_ie[0] = IEEE80211_ELEMID_SSID;
	ssid_ie[1] = sr->ssid_len;
	memcpy(&ssid_ie[2], sr->ssid, sr->ssid_len);

	memset(tstamp, 0, sizeof(tstamp));

	memset(&sp, 0, sizeof(sp));
	sp.tstamp = tstamp;
	sp.ssid = ssid_ie;
	sp.rates = __DECONST(uint8_t *, default_rates_ie);
	sp.chan = sr->chan;
	sp.bchan = sr->chan;
	sp.capinfo = sr->capinfo;
	sp.bintval = sr->bintval;

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

	memset(&wh, 0, sizeof(wh));
	wh.i_fc[0] = IEEE80211_FC0_TYPE_MGT | IEEE80211_FC0_SUBTYPE_BEACON;
	IEEE80211_ADDR_COPY(wh.i_addr2, sr->bssid);
	IEEE80211_ADDR_COPY(wh.i_addr3, sr->bssid);

	if (sp.rates == NULL) {
		printf("brcmfmac: skip scan entry %02x:%02x:%02x:%02x:%02x:%02x"
		    " - no rates\n",
		    sr->bssid[0], sr->bssid[1], sr->bssid[2],
		    sr->bssid[3], sr->bssid[4], sr->bssid[5]);
		return;
	}

	ieee80211_add_scan(vap, chan, &sp, &wh,
	    IEEE80211_FC0_SUBTYPE_BEACON, sr->rssi, sr->noise);
}

void
brcmf_scan_complete_task(void *arg, int pending)
{
	struct brcmf_softc *sc = arg;
	struct ieee80211com *ic = &sc->ic;
	struct ieee80211vap *vap;
	int i, n;

	vap = TAILQ_FIRST(&ic->ic_vaps);
	if (vap == NULL)
		return;

	if (!sc->scan_complete)
		return;

	sc->scan_complete = 0;
	n = sc->scan_nresults;
	sc->scan_nresults = 0;

	if (sc->link_up)
		return;

	if (vap->iv_des_nssid > 0 && vap->iv_des_ssid[0].len > 0) {
		static const uint8_t zerobssid[6] = {0, 0, 0, 0, 0, 0};
		int bssid_any = IEEE80211_ADDR_EQ(vap->iv_des_bssid,
		    ieee80211broadcastaddr) ||
		    IEEE80211_ADDR_EQ(vap->iv_des_bssid, zerobssid);
		for (i = 0; i < n; i++) {
			struct brcmf_scan_result *sr = &sc->scan_results[i];
			if (sr->ssid_len == vap->iv_des_ssid[0].len &&
			    memcmp(sr->ssid, vap->iv_des_ssid[0].ssid, sr->ssid_len) == 0 &&
			    (bssid_any || IEEE80211_ADDR_EQ(sr->bssid, vap->iv_des_bssid))) {
				brcmf_join_bss_direct(sc, sr);
				return;
			}
		}
	}

	for (i = 0; i < n; i++)
		brcmf_add_scan_result(sc, &sc->scan_results[i]);

	ieee80211_scan_done(vap);
}
