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


/* F2 transfer sizes */
#define SDPCM_MAX_FRAME_SIZE	2048
/* Round frames to F2 block size so sdiob uses block-mode CMD53.
 * Block mode keeps PIO bursts to 16 words (64 bytes) per block,
 * avoiding DATA_CRC on the Arasan SDHCI + BCM43455 F2 port. */
#define SDPCM_F2_BLKSZ		64

/* Forward declarations */
static struct mbuf *brcmf_sdpcm_rx_mbuf(struct brcmf_softc *sc,
    uint8_t *data, uint16_t len);

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

/* Forward declarations */
static void brcmf_sdpcm_poll(void *arg);

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
	uint8_t delta;

	delta = (uint8_t)(sc->sdpcm_max_seq - sc->sdpcm_tx_seq);

	/* Need at least one credit available */
	if (delta == 0 || (delta & 0x80) != 0)
		return (0);

	/* For data channel, also check flow control */
	if (channel == SDPCM_DATA_CHANNEL && sc->sdpcm_flowctl)
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
brcmf_sdpcm_hostmail(struct brcmf_softc *sc)
{
	uint32_t hmb_data, intstatus;
	uint8_t fcbits;

	intstatus = 0;
	hmb_data = brcmf_sdio_bp_read32(sc,
	    sc->sdiocore.base + SD_REG_TOHOSTMAILBOXDATA);
	if (hmb_data != 0)
		brcmf_sdio_bp_write32(sc, sc->sdiocore.base + SD_REG_TOSBMAILBOX,
		    SMB_INT_ACK);

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

/*
 * BCDC IOCTL: synchronous send + poll.
 * Stops poll callout and drains rx_task for exclusive F2 access.
 */
int
brcmf_sdpcm_ioctl(struct brcmf_softc *sc, uint32_t cmd, int set,
    void *buf, uint32_t len, uint32_t *resp_len)
{
	uint8_t *txbuf = sc->sdpcm_ioctl_tx;
	uint8_t *rxbuf = sc->sdpcm_ioctl_rx;
	struct bcdc_dcmd *dcmd;
	struct mbuf *rx_list = NULL;
	struct mbuf **rx_tail = &rx_list;
	uint16_t reqid;
	uint32_t flags;
	int error, i;

	if (sc->fw_dead)
		return (ENXIO);

	/* Serialize all F2 access */
	sx_xlock(&sc->sdio_lock);

	reqid = sc->sdpcm_reqid++;

	/* Build BCDC command */
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

	/* Send command — retry if no TX credits */
	for (i = 0; i < 100; i++) {
		error = brcmf_sdpcm_send(sc, SDPCM_CONTROL_CHANNEL,
		    txbuf, BCDC_DCMD_HDRLEN + len);
		if (error != ENOBUFS)
			break;
		/* Drain RX to get TX credits */
		{
			uint16_t chan, dlen;
			uint8_t *payload;
			brcmf_sdpcm_recv(sc, rxbuf, BRCMF_SDPCM_CTL_BUFSZ,
			    &chan, &dlen, &payload);
		}
		pause_sbt("ioctx", mstosbt(10), 0, 0);
	}
	if (error != 0)
		goto done;

	/* Poll for response — queue data mbufs for delivery after unlock */
	for (i = 0; i < 300; i++) {
		uint16_t chan, dlen;
		uint8_t *payload;

		error = brcmf_sdpcm_recv(sc, rxbuf, BRCMF_SDPCM_CTL_BUFSZ,
		    &chan, &dlen, &payload);
		if (error == EAGAIN) {
			pause_sbt("iocrx", mstosbt(10), 0, 0);
			continue;
		}
		if (error != 0)
			continue;

		/* Process any frame we receive */
		if (chan == SDPCM_EVENT_CHANNEL)
			brcmf_sdpcm_process_event(sc, payload, dlen);
		else if (chan == SDPCM_DATA_CHANNEL) {
			struct mbuf *m = brcmf_sdpcm_rx_mbuf(sc, payload, dlen);
			if (m != NULL) {
				*rx_tail = m;
				rx_tail = &m->m_nextpkt;
			}
		} else if (chan == SDPCM_CONTROL_CHANNEL) {
			/* Check if this is our response */
			struct bcdc_dcmd *resp = (struct bcdc_dcmd *)payload;
			uint32_t rflags, rlen;
			uint16_t rid;
			int32_t fwstatus;

			if (dlen < BCDC_DCMD_HDRLEN)
				continue;

			rflags = le32toh(resp->flags);
			rid = (rflags & BCDC_DCMD_ID_MASK) >> BCDC_DCMD_ID_SHIFT;

			if (rid != reqid)
				continue;

			/* Got our response */
			fwstatus = (int32_t)le32toh(resp->status);
			rlen = le32toh(resp->len);
			if (rlen > dlen - BCDC_DCMD_HDRLEN)
				rlen = dlen - BCDC_DCMD_HDRLEN;

			if (resp_len != NULL)
				*resp_len = rlen;

			if (rflags & BCDC_DCMD_ERROR) {
				BRCMF_DBG(sc, "ioctl cmd=0x%x fwerr=%d\n",
				    cmd, fwstatus);
				error = EIO;
				goto done;
			}

			if (buf != NULL && rlen > 0) {
				uint32_t copylen = rlen;
				if (copylen > len)
					copylen = len;
				memcpy(buf, payload + BCDC_DCMD_HDRLEN, copylen);
			}
			error = 0;
			goto done;
		}
	}

	device_printf(sc->dev, "IOCTL timeout cmd=0x%x\n", cmd);
	error = ETIMEDOUT;

done:
	sx_xunlock(&sc->sdio_lock);

	/* Deliver queued RX mbufs outside sdio_lock */
	while (rx_list != NULL) {
		struct mbuf *m = rx_list;
		rx_list = m->m_nextpkt;
		m->m_nextpkt = NULL;

		struct epoch_tracker et;
		NET_EPOCH_ENTER(et);
		if_input(m->m_pkthdr.rcvif, m);
		NET_EPOCH_EXIT(et);
	}

	return (error);
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
 * Build an mbuf from RX data. Returns mbuf or NULL.
 * Does NOT call if_input — caller must do that outside sdio_lock.
 */
static struct mbuf *
brcmf_sdpcm_rx_mbuf(struct brcmf_softc *sc, uint8_t *data, uint16_t len)
{
	struct ieee80211com *ic = &sc->ic;
	struct ieee80211vap *vap;
	if_t ifp;
	struct mbuf *m;
	uint8_t data_offset;

	device_printf(sc->dev, "rx_data: len=%u\n", len);

	if (len < BCDC_HEADER_LEN)
		return (NULL);

	data_offset = data[3];
	uint16_t hdr_total = BCDC_HEADER_LEN + (uint16_t)data_offset * 4;
	if (hdr_total > len)
		return (NULL);
	data += hdr_total;
	len -= hdr_total;

	if (len < ETHER_HDR_LEN)
		return (NULL);

	vap = TAILQ_FIRST(&ic->ic_vaps);
	if (vap == NULL)
		return (NULL);
	ifp = vap->iv_ifp;
	if (ifp == NULL)
		return (NULL);

	m = m_get2(len, M_NOWAIT, MT_DATA, M_PKTHDR);
	if (m == NULL)
		return (NULL);

	m_copyback(m, 0, len, data);
	m->m_pkthdr.len = m->m_len = len;
	m->m_pkthdr.rcvif = ifp;

	return (m);
}

/*
 * TX data frame via SDPCM. Implements bus_ops->tx.
 * Queue mbuf and schedule TX task — cannot sleep in network output path.
 */
int
brcmf_sdpcm_tx(struct brcmf_softc *sc, struct mbuf *m)
{
	if (sc->fw_dead || sc->sdio_func2 == NULL) {
		m_freem(m);
		return (ENXIO);
	}

	if (m->m_pkthdr.len > SDPCM_MAX_FRAME_SIZE - SDPCM_HDRLEN - BCDC_HEADER_LEN) {
		m_freem(m);
		return (EMSGSIZE);
	}

	/* Queue mbuf for TX task */
	mtx_lock(&sc->tx_queue_mtx);
	*sc->tx_queue_tail = m;
	sc->tx_queue_tail = &m->m_nextpkt;
	m->m_nextpkt = NULL;
	mtx_unlock(&sc->tx_queue_mtx);

	taskqueue_enqueue(sc->sdpcm_tq, &sc->sdpcm_tx_task);
	return (0);
}

/*
 * TX task — send queued mbufs. Runs in taskqueue context where sleeping is OK.
 */
static void
brcmf_sdpcm_tx_task(void *arg, int pending)
{
	struct brcmf_softc *sc = arg;
	struct mbuf *m, *tx_list;
	uint8_t *frame = sc->sdpcm_data_tx;
	int error, i;

	if (sc->fw_dead || sc->detaching)
		return;

	/* Grab queued mbufs */
	mtx_lock(&sc->tx_queue_mtx);
	tx_list = sc->tx_queue_head;
	sc->tx_queue_head = NULL;
	sc->tx_queue_tail = &sc->tx_queue_head;
	mtx_unlock(&sc->tx_queue_mtx);

	if (tx_list == NULL)
		return;

	sx_xlock(&sc->sdio_lock);

	while ((m = tx_list) != NULL) {
		uint16_t pktlen = m->m_pkthdr.len;
		tx_list = m->m_nextpkt;
		m->m_nextpkt = NULL;

		/* BCDC header */
		frame[0] = BCDC_PROTO_VER << BCDC_FLAG_VER_SHIFT;
		frame[1] = 0;
		frame[2] = 0;
		frame[3] = 0;

		m_copydata(m, 0, pktlen, frame + BCDC_HEADER_LEN);

		/* Debug: log TX with ethertype */
		{
			uint16_t etype = (frame[BCDC_HEADER_LEN + 12] << 8) |
			    frame[BCDC_HEADER_LEN + 13];
			device_printf(sc->dev, "tx_data: len=%u etype=0x%04x\n",
			    pktlen, etype);
		}

		m_freem(m);

		/* Send — retry if no TX credits */
		for (i = 0; i < 50; i++) {
			error = brcmf_sdpcm_send(sc, SDPCM_DATA_CHANNEL,
			    frame, BCDC_HEADER_LEN + pktlen);
			if (error != ENOBUFS)
				break;
			/* Drain RX to get TX credits */
			{
				uint16_t chan, dlen;
				uint8_t *payload;
				brcmf_sdpcm_recv(sc, sc->sdpcm_poll_rx,
				    BRCMF_SDPCM_CTL_BUFSZ, &chan, &dlen, &payload);
			}
			DELAY(1000);
		}
	}

	sx_xunlock(&sc->sdio_lock);
}

/*
 * RX poll task — runs on taskqueue so SDIO I/O can sleep.
 * Drains pending frames and processes events.
 */
static void
brcmf_sdpcm_rx_task(void *arg, int pending)
{
	struct brcmf_softc *sc = arg;
	uint8_t *rxbuf = sc->sdpcm_poll_rx;
	uint16_t chan, dlen;
	uint8_t *payload;
	struct mbuf *rx_list = NULL;
	struct mbuf **rx_tail = &rx_list;
	int i;

	if (sc->fw_dead || sc->detaching)
		return;

	/* Try to acquire F2 lock; skip if busy (ioctl in progress) */
	if (sx_try_xlock(&sc->sdio_lock) == 0)
		return;

	/* Check mailbox for firmware messages */
	brcmf_sdpcm_hostmail(sc);

	/* Drain RX FIFO — queue mbufs for later delivery */
	for (i = 0; i < 50; i++) {
		int error = brcmf_sdpcm_recv(sc, rxbuf,
		    BRCMF_SDPCM_CTL_BUFSZ, &chan, &dlen, &payload);
		if (error != 0)
			break;

		if (chan == SDPCM_EVENT_CHANNEL)
			brcmf_sdpcm_process_event(sc, payload, dlen);
		else if (chan == SDPCM_DATA_CHANNEL) {
			struct mbuf *m = brcmf_sdpcm_rx_mbuf(sc, payload, dlen);
			if (m != NULL) {
				*rx_tail = m;
				rx_tail = &m->m_nextpkt;
			}
		}
		/* Control channel responses handled inline in ioctl */
	}

	sx_xunlock(&sc->sdio_lock);

	/*
	 * Deliver RX mbufs outside sdio_lock. if_input may trigger
	 * TCP processing which calls back into our TX path, and TX
	 * needs sdio_lock.
	 */
	while (rx_list != NULL) {
		struct mbuf *m = rx_list;
		rx_list = m->m_nextpkt;
		m->m_nextpkt = NULL;

		struct epoch_tracker et;
		NET_EPOCH_ENTER(et);
		if_input(m->m_pkthdr.rcvif, m);
		NET_EPOCH_EXIT(et);
	}
}

/*
 * Callout handler — enqueues RX poll task.
 */
static void
brcmf_sdpcm_poll(void *arg)
{
	struct brcmf_softc *sc = arg;

	if (sc->fw_dead || sc->detaching)
		return;

	taskqueue_enqueue(sc->sdpcm_tq, &sc->sdpcm_rx_task);
	callout_reset(&sc->sdpcm_callout, hz / 20, brcmf_sdpcm_poll, sc);
}

void
brcmf_sdpcm_init(struct brcmf_softc *sc)
{
	sx_init(&sc->sdio_lock, "brcmfmac_sdio");
	mtx_init(&sc->tx_queue_mtx, "brcmfmac_txq", NULL, MTX_DEF);
	sc->tx_queue_head = NULL;
	sc->tx_queue_tail = &sc->tx_queue_head;

	TASK_INIT(&sc->sdpcm_rx_task, 0, brcmf_sdpcm_rx_task, sc);
	TASK_INIT(&sc->sdpcm_tx_task, 0, brcmf_sdpcm_tx_task, sc);
	callout_init(&sc->sdpcm_callout, 1);

	sc->sdpcm_tq = taskqueue_create("brcmfmac_sdpcm", M_WAITOK,
	    taskqueue_thread_enqueue, &sc->sdpcm_tq);
	taskqueue_start_threads(&sc->sdpcm_tq, 1, PI_NET, "brcmfmac_sdpcm");
}

void
brcmf_sdpcm_start_poll(struct brcmf_softc *sc)
{
	if (sc->sdpcm_poll_started)
		return;
	sc->sdpcm_poll_started = 1;
	callout_reset(&sc->sdpcm_callout, hz / 20, brcmf_sdpcm_poll, sc);
}

void
brcmf_sdpcm_stop_poll(struct brcmf_softc *sc)
{
	if (!sc->sdpcm_poll_started)
		return;
	sc->sdpcm_poll_started = 0;
	callout_drain(&sc->sdpcm_callout);

	if (sc->sdpcm_tq != NULL) {
		taskqueue_drain(sc->sdpcm_tq, &sc->sdpcm_rx_task);
		taskqueue_drain(sc->sdpcm_tq, &sc->sdpcm_tx_task);
	}
}

/*
 * SDPCM cleanup. Implements bus_ops->cleanup.
 */
void
brcmf_sdpcm_cleanup(struct brcmf_softc *sc)
{
	struct mbuf *m;

	brcmf_sdpcm_stop_poll(sc);
	if (sc->sdpcm_tq != NULL) {
		taskqueue_free(sc->sdpcm_tq);
		sc->sdpcm_tq = NULL;
	}

	/* Free any queued TX mbufs */
	mtx_lock(&sc->tx_queue_mtx);
	while ((m = sc->tx_queue_head) != NULL) {
		sc->tx_queue_head = m->m_nextpkt;
		m_freem(m);
	}
	sc->tx_queue_tail = &sc->tx_queue_head;
	mtx_unlock(&sc->tx_queue_mtx);
	mtx_destroy(&sc->tx_queue_mtx);
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
