/* Security: wsec/wpa_auth configuration, key installation, PSK */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/endian.h>
#include <sys/bus.h>
#include <sys/socket.h>
#include <sys/sysctl.h>

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
	} else {
		macaddr = k->wk_macaddr;
		if (macaddr == NULL || IEEE80211_ADDR_EQ(macaddr, ieee80211broadcastaddr))
			macaddr = vap->iv_bss->ni_bssid;
		memcpy(key.ea, macaddr, 6);
	}

	printf("brcmfmac: wsec_key idx=%d algo=%d len=%d flags=0x%x ea=%02x:%02x:%02x:%02x:%02x:%02x\n",
	    le32toh(key.index), le32toh(key.algo), le32toh(key.len),
	    le32toh(key.flags), key.ea[0], key.ea[1], key.ea[2],
	    key.ea[3], key.ea[4], key.ea[5]);
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

int
brcmf_set_pmk(struct brcmf_softc *sc, const char *psk, int psk_len)
{
	struct brcmf_wsec_pmk_le pmk;
	int error;

	if (psk_len == 0 || psk_len > BRCMF_WSEC_MAX_PSK_LEN)
		return (EINVAL);

	memset(&pmk, 0, sizeof(pmk));
	pmk.key_len = htole16(psk_len);
	pmk.flags = htole16(BRCMF_WSEC_PASSPHRASE);
	memcpy(pmk.key, psk, psk_len);

	error = brcmf_fil_cmd_data_set(sc, BRCMF_C_SET_WSEC_PMK,
	    &pmk, sizeof(pmk));
	if (error != 0)
		device_printf(sc->dev, "SET_WSEC_PMK failed: %d\n", error);

	return (error);
}

int
brcmf_enable_supplicant(struct brcmf_softc *sc)
{
	int error;

	error = brcmf_fil_iovar_int_set(sc, "sup_wpa", 1);
	if (error != 0) {
		/* Firmware may not support sup_wpa; proceed anyway. */
		device_printf(sc->dev,
		    "sup_wpa not supported (err=%d), continuing\n", error);
	}

	return (0);
}

/*
 * vndr_ie iovar format:
 *   cmd[12]       "add" or "del"
 *   pktflag[4]    frame type bitmask
 *   ie_count[4]   always 1
 *   ie_data[]     raw IE (id + len + body)
 */
#define VNDR_IE_CMD_LEN		12
#define VNDR_IE_ASSOCREQ_FLAG	0x04

static int
brcmf_vndr_ie_cmd(struct brcmf_softc *sc, const char *cmd,
    uint32_t pktflag, const uint8_t *ie, int ie_len)
{
	uint8_t buf[VNDR_IE_CMD_LEN + 4 + 4 + 256];
	uint32_t buflen;

	if (ie_len > 256)
		return (EINVAL);

	buflen = VNDR_IE_CMD_LEN + 4 + 4 + ie_len;
	memset(buf, 0, VNDR_IE_CMD_LEN);
	strncpy((char *)buf, cmd, VNDR_IE_CMD_LEN);
	*(uint32_t *)(buf + VNDR_IE_CMD_LEN) = htole32(pktflag);
	*(uint32_t *)(buf + VNDR_IE_CMD_LEN + 4) = htole32(1);
	memcpy(buf + VNDR_IE_CMD_LEN + 4 + 4, ie, ie_len);

	return brcmf_fil_bsscfg_data_set(sc, "vndr_ie", 0, buf, buflen);
}

/*
 * Set the RSN IE that the firmware will include in the 802.11
 * association request. This must match the RSN IE that
 * wpa_supplicant puts in EAPOL frame 2/4, otherwise the AP
 * rejects the handshake.
 */
int
brcmf_set_assocreq_ies(struct brcmf_softc *sc, const uint8_t *rsn_ie,
    int rsn_ie_len)
{
	int error;

	if (rsn_ie == NULL || rsn_ie_len < 2)
		return (0);

	error = brcmf_vndr_ie_cmd(sc, "add", VNDR_IE_ASSOCREQ_FLAG,
	    rsn_ie, rsn_ie_len);
	if (error != 0)
		device_printf(sc->dev, "vndr_ie add failed: %d\n", error);

	return (error);
}

/*
 * Remove a previously set RSN IE from association requests.
 */
int
brcmf_clear_assocreq_ies(struct brcmf_softc *sc, const uint8_t *rsn_ie,
    int rsn_ie_len)
{
	if (rsn_ie == NULL || rsn_ie_len < 2)
		return (0);

	/* Best-effort; ignore errors (IE may not exist) */
	brcmf_vndr_ie_cmd(sc, "del", VNDR_IE_ASSOCREQ_FLAG,
	    rsn_ie, rsn_ie_len);
	return (0);
}

static int
brcmf_sysctl_psk(SYSCTL_HANDLER_ARGS)
{
	struct brcmf_softc *sc = arg1;
	char buf[65];
	int error;

	memset(buf, 0, sizeof(buf));
	if (sc->psk_len > 0)
		memcpy(buf, sc->psk, sc->psk_len);

	error = sysctl_handle_string(oidp, buf, sizeof(buf), req);
	if (error != 0 || req->newptr == NULL)
		return (error);

	int len = strlen(buf);
	if (len < 8 || len > 63) {
		device_printf(sc->dev, "PSK must be 8-63 characters\n");
		return (EINVAL);
	}

	memcpy(sc->psk, buf, len);
	sc->psk[len] = '\0';
	sc->psk_len = len;

	return (0);
}

void
brcmf_security_sysctl_init(struct brcmf_softc *sc)
{
	struct sysctl_oid *oid;

	oid = device_get_sysctl_tree(sc->dev);
	if (oid == NULL)
		return;

	SYSCTL_ADD_PROC(&sc->sysctl_ctx, SYSCTL_CHILDREN(oid), OID_AUTO,
	    "psk", CTLTYPE_STRING | CTLFLAG_RW | CTLFLAG_MPSAFE, sc, 0,
	    brcmf_sysctl_psk, "A", "WPA PSK passphrase");
}
