// SPDX-License-Identifier: ISC
/*
 * Copyright (c) 2010-2022 Broadcom Corporation
 * Copyright (c) brcmfmac-freebsd contributors
 *
 * Based on the Linux brcmfmac driver.
 */

/* SDPCM framing + BCDC ioctl/data protocol over SDIO F2 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bus.h>
#include <sys/epoch.h>
#include <sys/kernel.h>
#include <sys/kthread.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/socket.h>
#include <sys/taskqueue.h>

#include <net/if.h>
#include <net/if_var.h>
#include <net/if_media.h>
#include <net/ethernet.h>

#include <net80211/ieee80211_var.h>

#include <dev/sdio/sdiob.h>
#include <dev/sdio/sdio_subr.h>

#include "sdio_if.h"
#include "brcmfmac.h"

/* SDPCM header size */
#define SDPCM_HDRLEN		12

/* SDPCM channels */
#define SDPCM_CONTROL_CHANNEL	0
#define SDPCM_EVENT_CHANNEL	1
#define SDPCM_DATA_CHANNEL	2
#define SDPCM_GLOM_CHANNEL	3

/* BCDC header sizes */
#define BCDC_DCMD_HDRLEN	16
#define BCDC_HEADER_LEN		4

/* BCDC flags */
#define BCDC_DCMD_ERROR		0x01
#define BCDC_DCMD_SET		0x02
#define BCDC_DCMD_IF_MASK	0xF000
#define BCDC_DCMD_IF_SHIFT	12
#define BCDC_DCMD_ID_MASK	0xFFFF0000
#define BCDC_DCMD_ID_SHIFT	16

/* BCDC data header flags */
#define BCDC_PROTO_VER		2
#define BCDC_FLAG_VER_SHIFT	4

/* Max control buffer — defined in brcmfmac.h, allocated in softc */

/* IOCTL timeout */
#define BRCMF_SDPCM_IOCTL_TIMEOUT_MS	3000

/* SDIO core interrupt bits */
#define I_HMB_FC_STATE		0x000008
#define I_HMB_FC_CHANGE		0x000010
#define I_HMB_FRAME_IND		0x000040
#define I_HMB_HOST_INT		0x000080
#define I_SMB_NAK		0x010000
#define I_SMB_INT_ACK		0x020000
#define I_SMB_USE_OOB		0x200000
#define I_SMB_DEV_INT		0x400000

/* SDIO core register offsets */
#define SD_REG_INTSTATUS	0x020
#define SD_REG_HOSTINTMASK	0x024
#define SD_REG_TOSBMAILBOX	0x040
#define SD_REG_TOHOSTMAILBOXDATA 0x044

/* To-host mailbox data bits */
#define HMB_DATA_NAKHANDLED	0x0001
#define HMB_DATA_DEVREADY	0x0002
#define HMB_DATA_FC		0x0004
#define HMB_DATA_FWREADY	0x0008
#define HMB_DATA_FWHALT		0x0010
#define HMB_DATA_VERSION_MASK	0x00FF0000
#define HMB_DATA_VERSION_SHIFT	16
#define HMB_DATA_FCDATA_MASK	0xFF000000
#define HMB_DATA_FCDATA_SHIFT	24

/* F2 transfer sizes */
#define SDPCM_MAX_FRAME_SIZE	2048
/* Round frames to F2 block size so sdiob uses block-mode CMD53.
 * Block mode keeps PIO bursts to 16 words (64 bytes) per block,
 * avoiding DATA_CRC on the Arasan SDHCI + BCM43455 F2 port. */
#define SDPCM_F2_BLKSZ		64

/* Event structures (same as msgbuf.c) */
struct brcmf_event_msg_be {
	uint16_t version;
	uint16_t flags;
	uint32_t event_type;
	uint32_t status;
	uint32_t reason;
	uint32_t auth_type;
	uint32_t datalen;
	uint8_t addr[6];
	char ifname[16];
	uint8_t ifidx;
	uint8_t bsscfgidx;
} __packed;

struct brcmf_event {
	uint8_t dst[6];
	uint8_t src[6];
	uint16_t ether_type;
	uint16_t subtype;
	uint16_t length;
	uint8_t version;
	uint8_t oui[3];
	uint16_t usr_subtype;
	struct brcmf_event_msg_be msg;
} __packed;

#define BRCM_OUI "\x00\x10\x18"

/* BCDC command header */
struct bcdc_dcmd {
	uint32_t cmd;
	uint32_t len;
	uint32_t flags;
	uint32_t status;
};

/*
 * Check whether the SDPCM transmit window allows sending.
 * Returns true if transmission is permitted.
 */
static int
brcmf_sdpcm_tx_ok(struct brcmf_softc *sc, uint8_t channel)
{
	uint8_t delta, avail, reserve;

	delta = (uint8_t)(sc->sdpcm_max_seq - sc->sdpcm_tx_seq);
	if (channel == SDPCM_CONTROL_CHANNEL)
		return (delta != 0 && (delta & 0x80) == 0);

	reserve = sc->sdpcm_ioctl_tx_pending ? 2 : 0;
	avail = (uint8_t)(delta - reserve);
	if (avail == 0 || (avail & 0x80) != 0)
		return (0);
	if (sc->sdpcm_flowctl)
		return (0);

	return (1);
}

/*
 * Build and send an SDPCM frame on F2.
 */
static int
brcmf_sdpcm_send(struct brcmf_softc *sc, uint8_t channel,
    const void *data, uint16_t len)
{
	uint8_t *frame;
	uint16_t flen;
	int error;

	if (!brcmf_sdpcm_tx_ok(sc, channel))
		return (ENOBUFS);

	flen = SDPCM_HDRLEN + len;
	if (flen > SDPCM_MAX_FRAME_SIZE)
		return (EMSGSIZE);

	/* Transfer size rounded to F2 block boundary for block-mode CMD53 */
	uint16_t txlen = (flen + SDPCM_F2_BLKSZ - 1) & ~(SDPCM_F2_BLKSZ - 1);

	frame = sc->sdpcm_txbuf;
	memset(frame, 0, txlen);

	/* HW header: actual frame length (not padded transfer size) */
	frame[0] = flen & 0xFF;
	frame[1] = (flen >> 8) & 0xFF;
	frame[2] = ~flen & 0xFF;
	frame[3] = (~flen >> 8) & 0xFF;

	/* SW header */
	frame[4] = sc->sdpcm_tx_seq++;
	frame[5] = channel;
	frame[6] = 0;
	frame[7] = SDPCM_HDRLEN;

	if (data != NULL && len > 0)
		memcpy(frame + SDPCM_HDRLEN, data, len);

	/* F2 is a FIFO — fixed address (incaddr=false) for writes. */
	error = SDIO_WRITE_EXTENDED(
	    device_get_parent(sc->sdio_func2->dev),
	    sc->sdio_func2->fn, 0x8000, txlen, frame, false);
	if (error != 0) {
		uint8_t iordy = 0, ioex = 0;
		int rerr;
		ioex = sdio_f0_read_1(sc->sdio_func1, 0x02, &rerr);
		iordy = sdio_f0_read_1(sc->sdio_func1, 0x03, &rerr);
		device_printf(sc->dev,
		    "F2 write failed: err=%d ch=%d flen=%u txlen=%u "
		    "blksz=%u IOEx=0x%02x IORdy=0x%02x\n",
		    error, channel, flen, txlen,
		    sc->sdio_func2->cur_blksize, ioex, iordy);
	}

	return (error);
}

/*
 * Read a single SDPCM frame from F2.
 * First reads the 4-byte HW header to learn the frame length,
 * then reads the full frame.
 */
static int
brcmf_sdpcm_recv(struct brcmf_softc *sc, uint8_t *buf, uint16_t bufsz,
    uint16_t *channel_out, uint16_t *datalen_out, uint8_t **payload_out)
{
	uint16_t flen, flen_comp, data_offset;
	uint32_t rdsz;
	int error;

	/* Read one 64-byte block from the F2 FIFO. Block-mode reads
	 * for more data than the FIFO holds fail, so read one block
	 * at a time. With cur_blksize=64, sdiob sends b_count=1.
	 * If the read returns an error but the buffer has a valid
	 * SDPCM header, use the data — the PIO transfer may have
	 * completed before the SDHCI reported the error. */
	{
		rdsz = 64;
		if (rdsz > bufsz)
			rdsz = bufsz;

		memset(buf, 0, rdsz);
		error = SDIO_READ_EXTENDED(
		    device_get_parent(sc->sdio_func2->dev),
		    sc->sdio_func2->fn, 0x8000, rdsz, buf, false);

		/* Accept data if header looks valid despite error */
		if (error != 0) {
			uint16_t peek = buf[0] | (buf[1] << 8);
			uint16_t comp = buf[2] | (buf[3] << 8);
			if (peek == 0 || peek == 0xFFFF ||
			    (peek ^ comp) != 0xFFFF)
				return (error);
		}
	}

	/* If frame is larger than 64 bytes, fetch the exact remainder.
	 * Use 64-byte reads throughout. Larger multiblock CMD53 reads on
	 * BCM2711's Arasan controller are the failure mode that produced
	 * repeated controller timeouts (e.g. 576/1152-byte F2 reads) and
	 * eventual CAM queue corruption. */
	{
		uint16_t peek_flen = buf[0] | (buf[1] << 8);
		if (peek_flen > 64 && peek_flen <= bufsz) {
			uint32_t remain = peek_flen - 64;
			uint32_t off = 64;

			while (remain > 0) {
				uint32_t xfer = remain > 64 ? 64 : remain;

				error = SDIO_READ_EXTENDED(
				    device_get_parent(sc->sdio_func2->dev),
				    sc->sdio_func2->fn, 0x8000, xfer,
				    buf + off, false);
				off += xfer;
				remain -= xfer;
				/* ignore error on follow-up reads if we have
				 * enough data for the frame */
			}
		}
	}

	flen = buf[0] | (buf[1] << 8);
	flen_comp = buf[2] | (buf[3] << 8);

	if (flen == 0 || flen == 0xFFFF)
		return (EAGAIN);

	if ((flen ^ flen_comp) != 0xFFFF)
		return (EIO);

	if (flen < SDPCM_HDRLEN || flen > bufsz)
		return (EIO);

	sc->sdpcm_rx_seq = buf[4];
	*channel_out = buf[5] & 0x0F;
	data_offset = buf[7];

	if (data_offset < SDPCM_HDRLEN)
		data_offset = SDPCM_HDRLEN;
	if (data_offset > flen)
		return (EIO);

	*payload_out = buf + data_offset;
	*datalen_out = flen - data_offset;
	sc->sdpcm_fcmask = buf[8];
	sc->sdpcm_max_seq = buf[9];

	return (0);
}

static uint32_t
brcmf_sdpcm_intr_rstatus(struct brcmf_softc *sc)
{
	uint32_t val;

	val = brcmf_sdio_bp_read32(sc, sc->sdiocore.base + SD_REG_INTSTATUS);
	val &= I_HMB_FC_STATE | I_HMB_FC_CHANGE | I_HMB_FRAME_IND |
	    I_HMB_HOST_INT;
	sc->sdpcm_flowctl = !!(val & I_HMB_FC_STATE);
	if (val != 0)
		brcmf_sdio_bp_write32(sc, sc->sdiocore.base + SD_REG_INTSTATUS,
		    val);
	return (val);
}

static uint32_t
brcmf_sdpcm_hostmail(struct brcmf_softc *sc)
{
	uint32_t hmb_data, intstatus;
	uint8_t fcbits;

	intstatus = 0;
	hmb_data = brcmf_sdio_bp_read32(sc,
	    sc->sdiocore.base + SD_REG_TOHOSTMAILBOXDATA);
	if (hmb_data != 0)
		brcmf_sdio_bp_write32(sc, sc->sdiocore.base + SD_REG_TOSBMAILBOX,
		    I_SMB_INT_ACK);

	if (hmb_data & HMB_DATA_FWHALT)
		sc->fw_dead = 1;

	if (hmb_data & HMB_DATA_NAKHANDLED)
		intstatus |= I_HMB_FRAME_IND;

	if (hmb_data & HMB_DATA_FC) {
		fcbits = (hmb_data & HMB_DATA_FCDATA_MASK) >>
		    HMB_DATA_FCDATA_SHIFT;
		sc->sdpcm_fcmask = fcbits;
		sc->sdpcm_flowctl = (fcbits != 0);
	}

	return (intstatus);
}

static void
brcmf_sdpcm_process_control(struct brcmf_softc *sc, uint8_t *data, uint16_t len)
{
	struct bcdc_dcmd *resp;
	uint32_t rflags, rlen;
	uint16_t rid;
	int32_t fwstatus;

	if (len < BCDC_DCMD_HDRLEN)
		return;

	resp = (struct bcdc_dcmd *)data;
	rflags = le32toh(resp->flags);
	rid = (rflags & BCDC_DCMD_ID_MASK) >> BCDC_DCMD_ID_SHIFT;
	fwstatus = (int32_t)le32toh(resp->status);
	rlen = le32toh(resp->len);
	if (rlen > len - BCDC_DCMD_HDRLEN)
		rlen = len - BCDC_DCMD_HDRLEN;

	mtx_lock(&sc->ioctl_mtx);
	if (!sc->sdpcm_ioctl_waiting || rid != sc->sdpcm_ioctl_reqid) {
		mtx_unlock(&sc->ioctl_mtx);
		return;
	}

	sc->ioctl_status = (rflags & BCDC_DCMD_ERROR) ? fwstatus : 0;
	sc->ioctl_resp_len = rlen;
	if (rlen > 0)
		memcpy(sc->sdpcm_ioctl_rx, data + BCDC_DCMD_HDRLEN, rlen);
	sc->ioctl_completed = 1;
	sc->sdpcm_ioctl_waiting = 0;
	wakeup(&sc->ioctl_completed);
	mtx_unlock(&sc->ioctl_mtx);
}

/*
 * BCDC IOCTL: prepare control frame, wake DPC thread, wait for response.
 * The DPC thread owns all F2 I/O — it sends the control frame and
 * processes the response from the control channel.
 */
int
brcmf_sdpcm_ioctl(struct brcmf_softc *sc, uint32_t cmd, int set,
    void *buf, uint32_t len, uint32_t *resp_len)
{
	uint8_t *txbuf = sc->sdpcm_ioctl_tx;
	struct bcdc_dcmd *dcmd;
	uint16_t reqid;
	uint32_t flags;
	int error, timeout;

	if (sc->fw_dead)
		return (ENXIO);

	mtx_lock(&sc->ioctl_mtx);
	reqid = sc->sdpcm_reqid++;

	dcmd = (struct bcdc_dcmd *)txbuf;
	dcmd->cmd = htole32(cmd);
	dcmd->len = htole32(len);
	flags = (reqid << BCDC_DCMD_ID_SHIFT);
	if (set)
		flags |= BCDC_DCMD_SET;
	dcmd->flags = htole32(flags);
	dcmd->status = 0;

	if (buf != NULL && len > 0) {
		if (len > BRCMF_SDPCM_CTL_BUFSZ - BCDC_DCMD_HDRLEN)
			len = BRCMF_SDPCM_CTL_BUFSZ - BCDC_DCMD_HDRLEN;
		memcpy(txbuf + BCDC_DCMD_HDRLEN, buf, len);
	}

	sc->sdpcm_ioctl_reqid = reqid;
	sc->sdpcm_ioctl_waiting = 1;
	sc->ioctl_completed = 0;
	sc->ioctl_status = 0;
	sc->ioctl_resp_len = 0;

	sc->sdpcm_ioctl_tx_len = BCDC_DCMD_HDRLEN + len;
	sc->sdpcm_ioctl_tx_pending = 1;

	timeout = BRCMF_SDPCM_IOCTL_TIMEOUT_MS * hz / 1000;
	while (!sc->ioctl_completed && !sc->fw_dead && !sc->detaching &&
	    timeout > 0) {
		wakeup(&sc->sdpcm_dpc_run);
		error = msleep(&sc->ioctl_completed, &sc->ioctl_mtx, 0,
		    "brcmio", hz / 20);
		if (error != 0 && error != EWOULDBLOCK)
			break;
		timeout -= hz / 20;
	}

	if (!sc->ioctl_completed) {
		device_printf(sc->dev, "IOCTL timeout cmd=0x%x\n", cmd);
		sc->sdpcm_ioctl_waiting = 0;
		sc->sdpcm_ioctl_tx_pending = 0;
		mtx_unlock(&sc->ioctl_mtx);
		return (ETIMEDOUT);
	}

	if (resp_len != NULL)
		*resp_len = sc->ioctl_resp_len;
	if (sc->ioctl_status != 0) {
		BRCMF_DBG(sc, "ioctl cmd=0x%x fwerr=%d\n", cmd, sc->ioctl_status);
		mtx_unlock(&sc->ioctl_mtx);
		return (EIO);
	}
	if (buf != NULL && sc->ioctl_resp_len > 0) {
		uint32_t copylen = sc->ioctl_resp_len;
		if (copylen > len)
			copylen = len;
		memcpy(buf, sc->sdpcm_ioctl_rx, copylen);
	}
	mtx_unlock(&sc->ioctl_mtx);
	return (0);
}

/*
 * Process a received event frame.
 */
void
brcmf_sdpcm_process_event(struct brcmf_softc *sc, uint8_t *data, uint16_t len)
{
	struct brcmf_event *event;
	uint32_t event_code, datalen;
	uint8_t data_offset;

	/* Strip BCDC header (4 bytes + data_offset padding) */
	if (len < BCDC_HEADER_LEN)
		return;
	data_offset = data[3];
	{
		uint16_t hdr_total = BCDC_HEADER_LEN +
		    (uint16_t)data_offset * 4;
		if (hdr_total > len)
			return;
		data += hdr_total;
		len -= hdr_total;
	}

	if (len < sizeof(*event))
		return;

	event = (struct brcmf_event *)data;

	if (memcmp(event->oui, BRCM_OUI, 3) != 0)
		return;

	event_code = be32toh(event->msg.event_type);
	datalen = be32toh(event->msg.datalen);

	BRCMF_DBG(sc, "event: code=%u status=%u datalen=%u len=%u\n",
	    event_code, be32toh(event->msg.status), datalen, len);

	switch (event_code) {
	case 0:  /* E_SET_SSID */
	case 5:  /* E_DEAUTH */
	case 6:  /* E_DEAUTH_IND */
	case 11: /* E_DISASSOC */
	case 12: /* E_DISASSOC_IND */
	case 16: /* E_LINK */
		brcmf_link_event(sc, event_code,
		    be32toh(event->msg.status),
		    be32toh(event->msg.reason),
		    be16toh(event->msg.flags));
		break;
	case 69: /* E_ESCAN_RESULT */
		if (datalen > 0 && datalen < len - sizeof(*event))
			brcmf_escan_result(sc,
			    data + sizeof(*event), datalen);
		break;
	default:
		break;
	}
}

/*
 * Process a received data frame. Strip BCDC header and deliver.
 */
void
brcmf_sdpcm_process_rx(struct brcmf_softc *sc, uint8_t *data, uint16_t len)
{
	struct ieee80211com *ic = &sc->ic;
	struct ieee80211vap *vap;
	if_t ifp;
	struct mbuf *m;
	uint8_t data_offset;

	if (len < BCDC_HEADER_LEN)
		return;

	data_offset = data[3];
	uint16_t hdr_total = BCDC_HEADER_LEN + (uint16_t)data_offset * 4;
	if (hdr_total > len)
		return;
	data += hdr_total;
	len -= hdr_total;

	if (len < ETHER_HDR_LEN)
		return;

	vap = TAILQ_FIRST(&ic->ic_vaps);
	if (vap == NULL)
		return;
	ifp = vap->iv_ifp;
	if (ifp == NULL)
		return;

	m = m_get2(len, M_NOWAIT, MT_DATA, M_PKTHDR);
	if (m == NULL)
		return;

	m_copyback(m, 0, len, data);
	m->m_pkthdr.len = m->m_len = len;
	m->m_pkthdr.rcvif = ifp;

	{
		struct epoch_tracker et;
		NET_EPOCH_ENTER(et);
		if_input(ifp, m);
		NET_EPOCH_EXIT(et);
	}
}

/*
 * TX data frame via SDPCM. Implements bus_ops->tx.
 * Prepares the frame and wakes the DPC thread to send it.
 */
int
brcmf_sdpcm_tx(struct brcmf_softc *sc, struct mbuf *m)
{
	uint8_t *frame = sc->sdpcm_data_tx;
	uint16_t pktlen;

	if (sc->fw_dead || sc->sdio_func2 == NULL) {
		m_freem(m);
		return (ENXIO);
	}

	pktlen = m->m_pkthdr.len;
	if (BCDC_HEADER_LEN + pktlen > SDPCM_MAX_FRAME_SIZE - SDPCM_HDRLEN) {
		m_freem(m);
		return (EMSGSIZE);
	}

	/* Drop if a data frame is already pending */
	if (sc->sdpcm_data_tx_len != 0) {
		m_freem(m);
		return (ENOBUFS);
	}

	frame[0] = BCDC_PROTO_VER << BCDC_FLAG_VER_SHIFT;
	frame[1] = 0;
	frame[2] = 0;
	frame[3] = 0;

	m_copydata(m, 0, pktlen, frame + BCDC_HEADER_LEN);
	m_freem(m);

	sc->sdpcm_data_tx_len = BCDC_HEADER_LEN + pktlen;
	wakeup(&sc->sdpcm_dpc_run);

	return (0);
}

/*
 * RX poll task — runs on taskqueue_thread so SDIO I/O can sleep.
 * Drains all pending frames from the F2 FIFO.
 */
static void
brcmf_sdpcm_rx_task(void *arg, int pending)
{
	struct brcmf_softc *sc = arg;
	uint8_t *rxbuf = sc->sdpcm_poll_rx;
	uint16_t chan, dlen;
	uint8_t *payload;
	int i;

	if (sc->fw_dead || sc->detaching)
		return;

	if (!atomic_cmpset_int(&sc->sdpcm_rx_busy, 0, 1))
		return;

	if (sc->sdpcm_worker_mode) {
		uint16_t txlen = 0;

		mtx_lock(&sc->ioctl_mtx);
		if (sc->sdpcm_ioctl_tx_pending) {
			txlen = sc->sdpcm_ioctl_tx_len;
			sc->sdpcm_ioctl_tx_pending = 0;
		}
		mtx_unlock(&sc->ioctl_mtx);

		if (txlen != 0) {
			int error, retries;
			/* Drain pending RX first to refresh TX credits */
			for (retries = 0; retries < 50; retries++) {
				error = brcmf_sdpcm_send(sc,
				    SDPCM_CONTROL_CHANNEL,
				    sc->sdpcm_ioctl_tx, txlen);
				if (error != ENOBUFS)
					break;
				brcmf_sdpcm_recv(sc, rxbuf,
				    BRCMF_SDPCM_CTL_BUFSZ,
				    &chan, &dlen, &payload);
				pause_sbt("brcmtx", mstosbt(10), 0, 0);
			}
			BRCMF_DBG(sc, "rx_task: TX ioctl len=%u err=%d\n", txlen, error);
			if (error != 0) {
				mtx_lock(&sc->ioctl_mtx);
				sc->ioctl_status = error;
				sc->ioctl_completed = 1;
				sc->sdpcm_ioctl_waiting = 0;
				wakeup(&sc->ioctl_completed);
				mtx_unlock(&sc->ioctl_mtx);
				atomic_store_rel_int(&sc->sdpcm_rx_busy, 0);
				return;
			}
		}
	}

	for (i = 0; i < 16; i++) {
		int error = brcmf_sdpcm_recv(sc, rxbuf,
		    BRCMF_SDPCM_CTL_BUFSZ, &chan, &dlen, &payload);
		if (error != 0) {
			if (i == 0 && error != EAGAIN)
				BRCMF_DBG(sc,
				    "rx_task: recv err=%d\n", error);
			break;
		}

		BRCMF_DBG(sc, "rx_task: ch=%u dlen=%u\n", chan, dlen);
		if (chan == SDPCM_CONTROL_CHANNEL)
			brcmf_sdpcm_process_control(sc, payload, dlen);
		else if (chan == SDPCM_EVENT_CHANNEL)
			brcmf_sdpcm_process_event(sc, payload, dlen);
		else if (chan == SDPCM_DATA_CHANNEL)
			brcmf_sdpcm_process_rx(sc, payload, dlen);
	}
	atomic_store_rel_int(&sc->sdpcm_rx_busy, 0);
}

/*
 * DPC thread — central SDIO runtime engine.
 * Single thread owns all F2 I/O. Matches Linux's DPC loop order:
 * interrupt status -> mailbox -> FC -> RX -> control TX -> data TX.
 */
static void
brcmf_sdpcm_dpc_thread(void *arg)
{
	struct brcmf_softc *sc = arg;
	uint8_t *rxbuf = sc->sdpcm_poll_rx;
	uint16_t chan, dlen;
	uint8_t *payload;
	uint32_t intstatus, newstatus;
	int i, more_work;

	while (sc->sdpcm_dpc_run) {
		if (sc->fw_dead || sc->detaching)
			break;

		more_work = 0;

		intstatus = brcmf_sdpcm_intr_rstatus(sc);
		if (intstatus & I_HMB_FC_CHANGE) {
			newstatus = brcmf_sdio_bp_read32(sc,
			    sc->sdiocore.base + SD_REG_INTSTATUS);
			sc->sdpcm_flowctl = !!(newstatus &
			    (I_HMB_FC_STATE | I_HMB_FC_CHANGE));
			intstatus |= newstatus & (I_HMB_FC_STATE | I_HMB_FC_CHANGE |
			    I_HMB_FRAME_IND | I_HMB_HOST_INT);
		}
		if (intstatus & I_HMB_HOST_INT)
			intstatus |= brcmf_sdpcm_hostmail(sc);
		if (intstatus != 0)
			more_work = 1;

		/* --- RX --- */
		for (i = 0; i < 50; i++) {
			int error = brcmf_sdpcm_recv(sc, rxbuf,
			    BRCMF_SDPCM_CTL_BUFSZ, &chan, &dlen, &payload);
			if (error != 0)
				break;

			if (chan == SDPCM_CONTROL_CHANNEL)
				brcmf_sdpcm_process_control(sc, payload, dlen);
			else if (chan == SDPCM_EVENT_CHANNEL)
				brcmf_sdpcm_process_event(sc, payload, dlen);
			else if (chan == SDPCM_DATA_CHANNEL)
				brcmf_sdpcm_process_rx(sc, payload, dlen);

			if (i == 49)
				more_work = 1;
		}

		/* --- 5. Control TX --- */
		{
			uint16_t txlen = 0;

			mtx_lock(&sc->ioctl_mtx);
			if (sc->sdpcm_ioctl_tx_pending) {
				txlen = sc->sdpcm_ioctl_tx_len;
				sc->sdpcm_ioctl_tx_pending = 0;
			}
			mtx_unlock(&sc->ioctl_mtx);

			if (txlen != 0) {
				int error, retries;
				for (retries = 0; retries < 50; retries++) {
					error = brcmf_sdpcm_send(sc,
					    SDPCM_CONTROL_CHANNEL,
					    sc->sdpcm_ioctl_tx, txlen);
					if (error != ENOBUFS)
						break;
					brcmf_sdpcm_recv(sc, rxbuf,
					    BRCMF_SDPCM_CTL_BUFSZ,
					    &chan, &dlen, &payload);
					DELAY(1000);
				}
				if (error != 0) {
					mtx_lock(&sc->ioctl_mtx);
					sc->ioctl_status = error;
					sc->ioctl_completed = 1;
					sc->sdpcm_ioctl_waiting = 0;
					wakeup(&sc->ioctl_completed);
					mtx_unlock(&sc->ioctl_mtx);
				}
				more_work = 1;
			}
		}

		/* --- 6. Data TX --- */
		if (sc->sdpcm_data_tx_len != 0 &&
		    brcmf_sdpcm_tx_ok(sc, SDPCM_DATA_CHANNEL)) {
			brcmf_sdpcm_send(sc, SDPCM_DATA_CHANNEL,
			    sc->sdpcm_data_tx, sc->sdpcm_data_tx_len);
			sc->sdpcm_data_tx_len = 0;
		}

		if (more_work)
			continue;

		tsleep(&sc->sdpcm_dpc_run, 0, "brcmdpc", hz / 20);
	}

	kproc_exit(0);
}

/*
 * Callout handler — wakes DPC thread periodically.
 */
static void
brcmf_sdpcm_poll(void *arg)
{
	struct brcmf_softc *sc = arg;

	if (sc->fw_dead || sc->detaching)
		return;

	wakeup(&sc->sdpcm_dpc_run);
	callout_reset(&sc->sdpcm_callout, hz / 20, brcmf_sdpcm_poll, sc);
}

void
brcmf_sdpcm_init(struct brcmf_softc *sc)
{
	TASK_INIT(&sc->sdpcm_rx_task, 0, brcmf_sdpcm_rx_task, sc);
	callout_init(&sc->sdpcm_callout, 1);

	sc->sdpcm_tq = taskqueue_create("brcmfmac_sdpcm", M_WAITOK,
	    taskqueue_thread_enqueue, &sc->sdpcm_tq);
	taskqueue_start_threads(&sc->sdpcm_tq, 1, PI_NET, "brcmfmac_sdpcm");
}

/*
 * Start the DPC polling callout.
 */
void
brcmf_sdpcm_start_poll(struct brcmf_softc *sc)
{
	if (sc->sdpcm_poll_started)
		return;
	sc->sdpcm_poll_started = 1;

	sc->sdpcm_dpc_run = 1;
	{
		int err = kproc_create(brcmf_sdpcm_dpc_thread, sc,
		    &sc->sdpcm_dpc_proc, 0, 0, "brcmfmac_dpc");
		if (err != 0)
			device_printf(sc->dev,
			    "DPC thread creation failed: %d\n", err);
	}

	callout_reset(&sc->sdpcm_callout, hz / 20, brcmf_sdpcm_poll, sc);
}

/*
 * Stop polling and drain.
 */
void
brcmf_sdpcm_stop_poll(struct brcmf_softc *sc)
{
	if (!sc->sdpcm_poll_started)
		return;
	sc->sdpcm_poll_started = 0;
	callout_drain(&sc->sdpcm_callout);

	/* Stop DPC thread */
	if (sc->sdpcm_dpc_proc != NULL) {
		sc->sdpcm_dpc_run = 0;
		wakeup(&sc->sdpcm_dpc_run);
		tsleep(&sc->sdpcm_dpc_proc, 0, "brcmwt", hz * 2);
		sc->sdpcm_dpc_proc = NULL;
	}

	if (sc->sdpcm_tq != NULL)
		taskqueue_drain(sc->sdpcm_tq, &sc->sdpcm_rx_task);
}

/*
 * SDPCM cleanup. Implements bus_ops->cleanup.
 */
void
brcmf_sdpcm_cleanup(struct brcmf_softc *sc)
{
	brcmf_sdpcm_stop_poll(sc);
	if (sc->sdpcm_tq != NULL) {
		taskqueue_free(sc->sdpcm_tq);
		sc->sdpcm_tq = NULL;
	}
}

/*
 * Bus ops for SDIO.
 */
const struct brcmf_bus_ops brcmf_sdio_bus_ops = {
	.ioctl		= brcmf_sdpcm_ioctl,
	.tx		= brcmf_sdpcm_tx,
	.flowring_create = NULL,
	.flowring_delete = NULL,
	.cleanup	= brcmf_sdpcm_cleanup,
};
