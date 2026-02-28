// SPDX-License-Identifier: ISC
/*
 * Copyright (c) 2010-2022 Broadcom Corporation
 * Copyright (c) brcmfmac-freebsd contributors
 *
 * Based on the Linux brcmfmac driver.
 */

/* Internal definitions shared between cfg.c, scan.c, security.c */

#ifndef _BRCMF_CFG_H_
#define _BRCMF_CFG_H_

#include "brcmfmac.h"

struct brcmf_vap {
	struct ieee80211vap vap;
	int (*newstate)(struct ieee80211vap *, enum ieee80211_state, int);
};

#define BRCMF_VAP(vap) ((struct brcmf_vap *)(vap))

/* Event codes */
#define BRCMF_E_SET_SSID	0
#define BRCMF_E_DEAUTH		5
#define BRCMF_E_DEAUTH_IND	6
#define BRCMF_E_DISASSOC	11
#define BRCMF_E_DISASSOC_IND	12
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
#define BRCMF_C_GET_CHANNEL	29
#define BRCMF_C_SET_PM		86
#define BRCMF_C_SET_WSEC_PMK	268

/* WSEC cipher flags */
#define WSEC_NONE		0x0000
#define WEP_ENABLED		0x0001
#define TKIP_ENABLED		0x0002
#define AES_ENABLED		0x0004

/* WPA auth flags */
#define WPA_AUTH_DISABLED	0x0000
#define WPA_AUTH_PSK		0x0004
#define WPA2_AUTH_PSK		0x0080
#define WPA2_AUTH_PSK_SHA256	0x8000

/* Crypto algorithm IDs for wsec_key */
#define CRYPTO_ALGO_OFF		0
#define CRYPTO_ALGO_WEP1	1
#define CRYPTO_ALGO_TKIP	2
#define CRYPTO_ALGO_WEP128	3
#define CRYPTO_ALGO_AES_CCM	4

/* Key flags */
#define BRCMF_PRIMARY_KEY	(1 << 1)

/* PMK structure */
struct brcmf_wsec_pmk_le {
	uint16_t key_len;
	uint16_t flags;
	uint8_t key[64];
} __packed;

#define BRCMF_WSEC_MAX_PSK_LEN	64
#define BRCMF_WSEC_PASSPHRASE	(1 << 0)

/* wsec_key structure */
struct brcmf_wsec_key {
	uint32_t index;
	uint32_t len;
	uint8_t data[32];
	uint32_t pad_1[18];
	uint32_t algo;
	uint32_t flags;
	uint32_t pad_2[3];
	uint32_t iv_initialized;
	uint32_t pad_3;
	struct {
		uint32_t hi;
		uint16_t lo;
	} rxiv;
	uint32_t pad_4[2];
	uint8_t ea[6];
} __packed;

/* Event mask */
#define BRCMF_EVENTING_MASK_LEN	16

/* escan */
#define WL_ESCAN_ACTION_START	1
#define WL_ESCAN_ACTION_CONTINUE 2
#define WL_ESCAN_ACTION_ABORT	3
#define BRCMF_ESCAN_REQ_VERSION 1
#define DOT11_BSSTYPE_ANY	2
#define BRCMF_E_STATUS_PARTIAL	8

/*
 * Chanspec encoding (D11AC PHY format)
 * Bits 0-7:   channel number (or center for wide channels)
 * Bits 8-10:  control sideband
 * Bits 11-13: bandwidth
 * Bits 14-15: band
 */
#define BRCMF_CHSPEC_D11AC_SB_MASK	0x0700
#define BRCMF_CHSPEC_D11AC_SB_SHIFT	8
#define BRCMF_CHSPEC_D11AC_BW_MASK	0x3800
#define BRCMF_CHSPEC_D11AC_BW_SHIFT	11
#define BRCMF_CHSPEC_CHAN_MASK		0x00ff

/* Legacy chanspec encoding */
#define BRCMF_CHANSPEC_CHAN_MASK	0x00ff
#define BRCMF_CHANSPEC_BAND_2G		0x0000
#define BRCMF_CHANSPEC_BAND_5G		0xc000
#define BRCMF_CHANSPEC_BW_20		0x1000
#define BRCMF_CHANSPEC_CTL_SB_NONE	0x0000

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

/*
 * Firmware BSS info struct. The firmware uses natural alignment
 * (matches Linux's non-packed struct). sizeof == 128 bytes, which
 * explains the "128-byte header" observed for IE offset.
 */
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
};

struct brcmf_escan_result_le {
	uint32_t buflen;
	uint32_t version;
	uint16_t sync_id;
	uint16_t bss_count;
	struct brcmf_bss_info_le bss_info_le;
} __packed;

/* Join parameters */
struct brcmf_assoc_params_le {
	uint8_t bssid[6];
	uint32_t chanspec_num;
	uint16_t chanspec_list[1];
} __packed;

struct brcmf_join_params {
	struct brcmf_ssid_le ssid_le;
	struct brcmf_assoc_params_le params_le;
} __packed;

/* scan.c */
int brcmf_chanspec_to_channel(uint16_t chanspec);
uint16_t brcmf_channel_to_chanspec(int channel);
int brcmf_do_escan(struct brcmf_softc *sc, const uint8_t *ssid, int ssid_len);
void brcmf_escan_result(struct brcmf_softc *sc, void *data, uint32_t datalen);
void brcmf_scan_complete_task(void *arg, int pending);
void brcmf_add_scan_result(struct brcmf_softc *sc,
    struct brcmf_scan_result *sr);

/* security.c */
uint32_t brcmf_detect_security(struct brcmf_scan_result *sr,
    uint32_t *wpa_auth);
int brcmf_set_security(struct brcmf_softc *sc, uint32_t wsec,
    uint32_t wpa_auth);
int brcmf_key_set(struct ieee80211vap *vap, const struct ieee80211_key *k);
int brcmf_key_delete(struct ieee80211vap *vap, const struct ieee80211_key *k);

void brcmf_security_sysctl_init(struct brcmf_softc *sc);

/* cfg.c (internal, used by scan.c) */
int brcmf_join_bss_direct(struct brcmf_softc *sc,
    struct brcmf_scan_result *sr);

#endif /* _BRCMF_CFG_H_ */
