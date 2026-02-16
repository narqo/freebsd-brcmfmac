/* Security: wsec/wpa_auth configuration, key installation */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bus.h>
#include <sys/socket.h>

#include <net/if.h>
#include <net/if_var.h>
#include <net/if_media.h>
#include <net/ethernet.h>

#include <net80211/ieee80211_var.h>

#include "cfg.h"

uint32_t
brcmf_detect_security(struct brcmf_scan_result *sr, uint32_t *wpa_auth)
{
	*wpa_auth = WPA_AUTH_DISABLED;

	if (sr->capinfo & IEEE80211_CAPINFO_PRIVACY) {
		*wpa_auth = WPA2_AUTH_PSK;
		return AES_ENABLED;
	}

	return WSEC_NONE;
}

int
brcmf_set_security(struct brcmf_softc *sc, uint32_t wsec, uint32_t wpa_auth)
{
	int error;

	error = brcmf_fil_iovar_int_set(sc, "wsec", wsec);
	if (error != 0) {
		device_printf(sc->dev, "failed to set wsec: %d\n", error);
		return error;
	}

	error = brcmf_fil_iovar_int_set(sc, "wpa_auth", wpa_auth);
	if (error != 0) {
		device_printf(sc->dev, "failed to set wpa_auth: %d\n", error);
		return error;
	}

	return 0;
}

int
brcmf_key_set(struct ieee80211vap *vap, const struct ieee80211_key *k)
{
	struct ieee80211com *ic = vap->iv_ic;
	struct brcmf_softc *sc = ic->ic_softc;
	struct brcmf_wsec_key key;
	const uint8_t *macaddr;
	int error;

	memset(&key, 0, sizeof(key));
	key.index = htole32(k->wk_keyix);
	key.len = htole32(k->wk_keylen);

	if (k->wk_keylen > sizeof(key.data))
		return 0;
	memcpy(key.data, k->wk_key, k->wk_keylen);

	switch (k->wk_cipher->ic_cipher) {
	case IEEE80211_CIPHER_WEP:
		if (k->wk_keylen == 5)
			key.algo = htole32(CRYPTO_ALGO_WEP1);
		else
			key.algo = htole32(CRYPTO_ALGO_WEP128);
		break;
	case IEEE80211_CIPHER_TKIP:
		key.algo = htole32(CRYPTO_ALGO_TKIP);
		break;
	case IEEE80211_CIPHER_AES_CCM:
		key.algo = htole32(CRYPTO_ALGO_AES_CCM);
		break;
	default:
		return 0;
	}

	if (k->wk_flags & IEEE80211_KEY_GROUP) {
		key.flags = htole32(BRCMF_PRIMARY_KEY);
		memset(key.ea, 0xff, 6);
	} else {
		macaddr = k->wk_macaddr;
		if (macaddr == NULL || IEEE80211_ADDR_EQ(macaddr, ieee80211broadcastaddr))
			macaddr = vap->iv_bss->ni_bssid;
		memcpy(key.ea, macaddr, 6);
	}

	error = brcmf_fil_iovar_data_set(sc, "wsec_key", &key, sizeof(key));
	if (error != 0)
		device_printf(sc->dev, "wsec_key set failed: %d\n", error);

	return 1;
}

int
brcmf_key_delete(struct ieee80211vap *vap, const struct ieee80211_key *k)
{
	struct ieee80211com *ic = vap->iv_ic;
	struct brcmf_softc *sc = ic->ic_softc;
	struct brcmf_wsec_key key;
	int error;

	memset(&key, 0, sizeof(key));
	key.index = htole32(k->wk_keyix);
	key.algo = htole32(CRYPTO_ALGO_OFF);
	key.flags = htole32(BRCMF_PRIMARY_KEY);

	error = brcmf_fil_iovar_data_set(sc, "wsec_key", &key, sizeof(key));
	if (error != 0)
		device_printf(sc->dev, "wsec_key delete failed: %d\n", error);

	return 1;
}
