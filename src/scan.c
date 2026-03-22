// SPDX-License-Identifier: ISC
/*
 * Copyright (c) 2010-2022 Broadcom Corporation
 * Copyright (c) brcmfmac-freebsd contributors
 *
 * Based on the Linux brcmfmac driver.
 */

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

static int
brcmf_chanspec_to_channel_d11ac(uint16_t chanspec)
{
	int ch = chanspec & BRCMF_CHSPEC_CHAN_MASK;
	int bw = (chanspec & BRCMF_CHSPEC_D11AC_BW_MASK) >> BRCMF_CHSPEC_D11AC_BW_SHIFT;
	int sb = (chanspec & BRCMF_CHSPEC_D11AC_SB_MASK) >> BRCMF_CHSPEC_D11AC_SB_SHIFT;

	switch (bw) {
	case BRCMF_BW_20:
		return ch;
	case BRCMF_BW_40:
		return (sb == 0) ? ch - 2 : ch + 2;
	case BRCMF_BW_80:
		switch (sb) {
		case 0: return ch - 6;
		case 1: return ch - 2;
		case 2: return ch + 2;
		case 3: return ch + 6;
		}
		break;
	case BRCMF_BW_160:
		return ch - 14 + sb * 4;
	}
	return ch;
}

static int
brcmf_chanspec_to_channel_d11n(uint16_t chanspec)
{
	int ch = chanspec & BRCMF_CHSPEC_CHAN_MASK;
	int bw = (chanspec & BRCMF_CHSPEC_D11N_BW_MASK) >> BRCMF_CHSPEC_D11N_BW_SHIFT;
	int sb = (chanspec & BRCMF_CHSPEC_D11N_SB_MASK) >> BRCMF_CHSPEC_D11N_SB_SHIFT;

	if (bw == BRCMF_BW_40) {
		if (sb == 1) /* lower */
			return ch - 2;
		if (sb == 2) /* upper */
			return ch + 2;
	}
	return ch;
}

int
brcmf_chanspec_to_channel(struct brcmf_softc *sc, uint16_t chanspec)
{
	if (sc->io_type == BRCMF_IO_TYPE_D11N)
		return brcmf_chanspec_to_channel_d11n(chanspec);
	return brcmf_chanspec_to_channel_d11ac(chanspec);
}

void
brcmf_chanspec_get_bw_sb(struct brcmf_softc *sc, uint16_t chanspec,
    int *bw, int *sb)
{
	if (sc->io_type == BRCMF_IO_TYPE_D11N) {
		int n_bw = (chanspec & BRCMF_CHSPEC_D11N_BW_MASK) >>
		    BRCMF_CHSPEC_D11N_BW_SHIFT;
		int n_sb = (chanspec & BRCMF_CHSPEC_D11N_SB_MASK) >>
		    BRCMF_CHSPEC_D11N_SB_SHIFT;
		*bw = (n_bw == BRCMF_BW_40) ? BRCMF_BW_40 : BRCMF_BW_20;
		*sb = (n_sb == 2) ? 1 : 0; /* D11N: 2=upper, 1=lower */
	} else {
		*bw = (chanspec & BRCMF_CHSPEC_D11AC_BW_MASK) >>
		    BRCMF_CHSPEC_D11AC_BW_SHIFT;
		*sb = (chanspec & BRCMF_CHSPEC_D11AC_SB_MASK) >>
		    BRCMF_CHSPEC_D11AC_SB_SHIFT;
	}
}

uint16_t
brcmf_channel_to_chanspec(struct brcmf_softc *sc, int channel)
{
	uint16_t chanspec;

	chanspec = channel & BRCMF_CHSPEC_CHAN_MASK;

	if (sc->io_type == BRCMF_IO_TYPE_D11N) {
		chanspec |= BRCMF_CHSPEC_D11N_BW_20;
		chanspec |= BRCMF_CHSPEC_D11N_SB_NONE;
		if (channel <= 14)
			chanspec |= BRCMF_CHSPEC_D11N_BAND_2G;
		else
			chanspec |= BRCMF_CHSPEC_D11N_BAND_5G;
	} else {
		chanspec |= BRCMF_CHSPEC_D11AC_BW_20;
		if (channel <= 14)
			chanspec |= BRCMF_CHSPEC_D11AC_BAND_2G;
		else
			chanspec |= BRCMF_CHSPEC_D11AC_BAND_5G;
	}

	return htole16(chanspec);
}

int
brcmf_do_escan(struct brcmf_softc *sc, const uint8_t *ssid, int ssid_len)
{
	struct brcmf_escan_params_le *params;
	size_t params_size;
	int error;

	params_size = sizeof(*params);
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
	params->params_le.channel_num = 0;

	sc->scan_nresults = 0;
	sc->scan_active = 1;

	error = brcmf_fil_iovar_data_set(sc, "escan", params, params_size);
	if (error != 0) {
		device_printf(sc->dev, "escan failed: %d\n", error);
		sc->scan_active = 0;
	}

	free(params, M_BRCMFMAC);
	return (error);
}

/*
 * Find the byte offset where IEs begin within a raw bss_info buffer.
 * Returns 0 if IEs cannot be located.
 *
 * The firmware's bss_info struct is larger than the public 128-byte
 * header and varies by firmware version (see spec/A2-structures.md).
 * The ie_offset/ie_length fields may contain garbage on newer
 * firmwares, so we search for the SSID IE matching the fixed header.
 */
static uint32_t
brcmf_find_ie_offset(const struct brcmf_bss_info_le *bi,
    const uint8_t *raw, uint32_t bi_len)
{
	uint32_t j;

	/* Search for SSID IE matching the fixed-header SSID */
	if (bi->SSID_len > 0 && bi->SSID_len <= 32) {
		for (j = sizeof(*bi);
		    j + 2 + bi->SSID_len <= bi_len; j++) {
			if (raw[j] == IEEE80211_ELEMID_SSID &&
			    raw[j + 1] == bi->SSID_len &&
			    memcmp(raw + j + 2, bi->SSID,
			    bi->SSID_len) == 0)
				return (j);
		}
	}

	/* Hidden SSID: tag 0x00, length 0, followed by Rates (tag 0x01) */
	if (bi->SSID_len == 0) {
		for (j = sizeof(*bi); j + 4 <= bi_len; j++) {
			if (raw[j] == 0x00 && raw[j + 1] == 0x00 &&
			    raw[j + 2] == 0x01)
				return (j);
		}
	}

	/* Trust ie_offset if it looks plausible */
	{
		uint16_t raw_off = le16toh(bi->ie_offset);
		if (raw_off >= sizeof(*bi) && raw_off < bi_len)
			return (raw_off);
	}

	/* Last resort: assume 128-byte header (BCM4350 firmware) */
	if (bi_len > 128)
		return (128);

	return (0);
}

/*
 * Store one BSS entry into the scan cache. Returns the slot used,
 * or NULL if the cache is full or a dedup rule suppressed the entry.
 */
static struct brcmf_scan_result *
brcmf_store_bss(struct brcmf_softc *sc, const struct brcmf_bss_info_le *bi,
    int chan, int16_t rssi, int8_t noise, uint16_t chanspec,
    const uint8_t *ie_data, uint32_t ie_len)
{
	struct brcmf_scan_result *sr;
	int k, dup = -1;

	if (sc->scan_nresults >= BRCMF_SCAN_RESULTS_MAX)
		return (NULL);

	for (k = 0; k < sc->scan_nresults; k++) {
		if (memcmp(sc->scan_results[k].bssid, bi->BSSID, 6) == 0) {
			dup = k;
			break;
		}
	}

	/* Don't overwrite an entry that has IEs with one that doesn't */
	if (dup >= 0 && sc->scan_results[dup].ie_len > 0 && ie_len == 0)
		return (NULL);

	sr = (dup >= 0) ? &sc->scan_results[dup] :
	    &sc->scan_results[sc->scan_nresults++];

	memcpy(sr->bssid, bi->BSSID, 6);
	sr->ssid_len = bi->SSID_len > 32 ? 32 : bi->SSID_len;
	memcpy(sr->ssid, bi->SSID, sr->ssid_len);
	sr->chan = chan;
	sr->chanspec = chanspec;
	sr->rssi = rssi;
	sr->noise = noise;
	sr->capinfo = le16toh(bi->capability);
	sr->bintval = le16toh(bi->beacon_period);

	if (ie_len > BRCMF_SCAN_IE_MAX)
		ie_len = BRCMF_SCAN_IE_MAX;
	sr->ie_len = ie_len;
	if (ie_len > 0)
		memcpy(sr->ie, ie_data, ie_len);

	return (sr);
}

void
brcmf_escan_result(struct brcmf_softc *sc, void *data, uint32_t datalen)
{
	struct brcmf_escan_result_le *result;
	struct brcmf_bss_info_le *bi;
	uint32_t buflen;
	uint16_t bss_count;

	if (datalen < 12) {
		device_printf(sc->dev, "escan result too short: %u\n", datalen);
		return;
	}

	if (TAILQ_FIRST(&sc->ic.ic_vaps) == NULL)
		return;

	result = data;
	buflen = le32toh(result->buflen);
	bss_count = le16toh(result->bss_count);

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
		uint32_t ie_off, ie_len;
		struct brcmf_scan_result *sr;
		int16_t rssi;
		int8_t noise;

		if (bi_len < sizeof(*bi) || bi_len > buflen)
			break;

		rssi = (int16_t)le16toh(bi->RSSI);
		noise = bi->phy_noise;
		if (noise == 0)
			noise = -95;

		ie_off = brcmf_find_ie_offset(bi, raw, bi_len);
		ie_len = (ie_off > 0 && ie_off < bi_len) ?
		    bi_len - ie_off : 0;

		sr = brcmf_store_bss(sc, bi,
		    brcmf_chanspec_to_channel(sc, le16toh(bi->chanspec)),
		    rssi, noise, le16toh(bi->chanspec),
		    (ie_off > 0) ? raw + ie_off : NULL, ie_len);
		if (sr != NULL)
			brcmf_add_scan_result(sc, sr);

		bi = (struct brcmf_bss_info_le *)(raw + bi_len);
		bss_count--;
	}
}

/* Default rates IE for 2.4GHz (11b/g rates) */
static const uint8_t default_rates_2g[] = {
	IEEE80211_ELEMID_RATES, 8,
	0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24
};

/* Default rates IE for 5GHz (11a rates) */
static const uint8_t default_rates_5g[] = {
	IEEE80211_ELEMID_RATES, 8,
	0x8c, 0x12, 0x98, 0x24, 0xb0, 0x48, 0x60, 0x6c
};

/*
 * Synthetic WMM IE — injected when BSS has RSN but no WMM.
 * Makes wpa_supplicant set 16 PTKSA replay counters (RSN
 * capabilities 0x000c) to match the firmware's association
 * request.
 */
static const uint8_t default_wmm_ie[] = {
	IEEE80211_ELEMID_VENDOR, 0x07,
	0x00, 0x50, 0xf2, 0x02,
	0x00, 0x01, 0x00,
};

/*
 * swscan sets ISCAN_DISCARD at scan start and clears it at first
 * channel dwell. Firmware escan results may arrive outside that
 * window, so clear the flag before each ieee80211_add_scan call.
 */
static void
brcmf_clear_scan_discard(struct ieee80211com *ic)
{
	struct ieee80211_scan_state *ss = ic->ic_scan;
	u_int *flagsp;

	if (ss == NULL)
		return;
	flagsp = (u_int *)((uint8_t *)ss +
	    sizeof(struct ieee80211_scan_state));
	*flagsp &= ~0x02; /* ISCAN_DISCARD */
}

static struct ieee80211_channel *
brcmf_find_scan_channel(struct ieee80211com *ic, int chan)
{
	int freq = ieee80211_ieee2mhz(chan,
	    chan <= 14 ? IEEE80211_CHAN_2GHZ : IEEE80211_CHAN_5GHZ);
	int base = chan <= 14 ? IEEE80211_CHAN_G : IEEE80211_CHAN_A;
	struct ieee80211_channel *c;

	c = ieee80211_find_channel(ic, freq, base | IEEE80211_CHAN_HT20);
	if (c == NULL)
		c = ieee80211_find_channel(ic, freq, base);
	if (c == NULL)
		c = &ic->ic_channels[0];
	return (c);
}

static void
brcmf_parse_ies(struct ieee80211_scanparams *sp,
    uint8_t *ie, uint16_t ie_len)
{
	uint8_t *p = ie;
	uint8_t *end = ie + ie_len;
	uint8_t *validated_end = p;

	while (p + 2 <= end) {
		uint8_t id = p[0];
		uint8_t len = p[1];

		if (p + 2 + len > end)
			break;

		switch (id) {
		case IEEE80211_ELEMID_RATES:
			sp->rates = p;
			break;
		case IEEE80211_ELEMID_XRATES:
			sp->xrates = p;
			break;
		case IEEE80211_ELEMID_COUNTRY:
			sp->country = p;
			break;
		case IEEE80211_ELEMID_RSN:
			sp->rsn = p;
			break;
		case IEEE80211_ELEMID_HTCAP:
			sp->htcap = p;
			break;
		case IEEE80211_ELEMID_HTINFO:
			sp->htinfo = p;
			break;
		case IEEE80211_ELEMID_VENDOR:
			if (len >= 4 &&
			    p[2] == 0x00 && p[3] == 0x50 &&
			    p[4] == 0xf2 && p[5] == 0x01)
				sp->wpa = p;
			if (len >= 4 &&
			    p[2] == 0x00 && p[3] == 0x50 &&
			    p[4] == 0xf2 && p[5] == 0x02)
				sp->wme = p;
			break;
		}
		p += 2 + len;
		validated_end = p;
	}

	/* Inject synthetic WMM IE when BSS has RSN but no WMM */
	if (sp->rsn != NULL && sp->wme == NULL &&
	    validated_end - ie + (int)sizeof(default_wmm_ie)
	    <= BRCMF_SCAN_IE_MAX) {
		memcpy(validated_end, default_wmm_ie,
		    sizeof(default_wmm_ie));
		sp->wme = validated_end;
		validated_end += sizeof(default_wmm_ie);
	}

	sp->ies = ie;
	sp->ies_len = validated_end - ie;
}

void
brcmf_add_scan_result(struct brcmf_softc *sc, struct brcmf_scan_result *sr)
{
	struct ieee80211com *ic = &sc->ic;
	struct ieee80211vap *vap;
	struct ieee80211_scanparams sp;
	struct ieee80211_frame wh;
	uint8_t ssid_ie[2 + 32];
	uint8_t tstamp[8];

	vap = TAILQ_FIRST(&ic->ic_vaps);
	if (vap == NULL)
		return;

	brcmf_clear_scan_discard(ic);

	ssid_ie[0] = IEEE80211_ELEMID_SSID;
	ssid_ie[1] = sr->ssid_len;
	memcpy(&ssid_ie[2], sr->ssid, sr->ssid_len);

	memset(tstamp, 0, sizeof(tstamp));
	memset(&sp, 0, sizeof(sp));
	sp.tstamp = tstamp;
	sp.ssid = ssid_ie;
	sp.rates = __DECONST(uint8_t *,
	    sr->chan <= 14 ? default_rates_2g : default_rates_5g);
	sp.chan = sr->chan;
	sp.bchan = sr->chan;
	sp.capinfo = sr->capinfo;
	sp.bintval = sr->bintval;

	if (sr->ie_len > 0)
		brcmf_parse_ies(&sp, sr->ie, sr->ie_len);

	memset(&wh, 0, sizeof(wh));
	wh.i_fc[0] = IEEE80211_FC0_TYPE_MGT | IEEE80211_FC0_SUBTYPE_BEACON;
	IEEE80211_ADDR_COPY(wh.i_addr2, sr->bssid);
	IEEE80211_ADDR_COPY(wh.i_addr3, sr->bssid);

	if (sp.rates == NULL)
		return;

	ieee80211_add_scan(vap,
	    brcmf_find_scan_channel(ic, sr->chan),
	    &sp, &wh, IEEE80211_FC0_SUBTYPE_BEACON,
	    sr->rssi - sr->noise, sr->noise);
}

void
brcmf_scan_complete_task(void *arg, int pending)
{
	struct brcmf_softc *sc = arg;
	struct ieee80211com *ic = &sc->ic;
	struct ieee80211vap *vap;
	int n;

	vap = TAILQ_FIRST(&ic->ic_vaps);
	if (vap == NULL)
		return;

	if (!sc->scan_complete)
		return;

	sc->scan_complete = 0;
	n = sc->scan_nresults;
	sc->scan_nresults = 0;

	ieee80211_scan_done(vap);

	/*
	 * Direct join only when net80211 controls roaming (not
	 * wpa_supplicant). When iv_roaming == MANUAL, the
	 * supplicant drives association via MLME ioctls.
	 */
	{
		struct ieee80211_scan_ssid des_ssid;
		uint8_t des_bssid[6];
		int do_join, i;

		IEEE80211_LOCK(ic);
		do_join = !sc->link_up &&
		    vap->iv_roaming != IEEE80211_ROAMING_MANUAL &&
		    vap->iv_des_nssid > 0 && vap->iv_des_ssid[0].len > 0;
		if (do_join) {
			des_ssid = vap->iv_des_ssid[0];
			IEEE80211_ADDR_COPY(des_bssid, vap->iv_des_bssid);
		}
		IEEE80211_UNLOCK(ic);

		if (do_join) {
			static const uint8_t zerobssid[6];
			int bssid_any =
			    IEEE80211_ADDR_EQ(des_bssid,
				ieee80211broadcastaddr) ||
			    IEEE80211_ADDR_EQ(des_bssid, zerobssid);
			for (i = 0; i < n; i++) {
				struct brcmf_scan_result *sr =
				    &sc->scan_results[i];
				if (sr->ssid_len == des_ssid.len &&
				    memcmp(sr->ssid, des_ssid.ssid,
					sr->ssid_len) == 0 &&
				    (bssid_any ||
				     IEEE80211_ADDR_EQ(sr->bssid,
					 des_bssid))) {
					brcmf_join_bss_direct(sc, sr);
					return;
				}
			}
		}
	}
}
