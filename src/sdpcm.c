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
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/mutex.h>
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
 * Build and send an SDPCM frame on F2.
 */
static int
brcmf_sdpcm_send(struct brcmf_softc *sc, uint8_t channel,
    const void *data, uint16_t len)
{
	uint8_t *frame;
	uint16_t flen;
	int error;

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
	if (error != 0)
		device_printf(sc->dev,
		    "F2 write failed: err=%d ch=%d flen=%u txlen=%u\n",
		    error, channel, flen, txlen);

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

	/* Acknowledge pending interrupts. The firmware uses
	 * I_HMB_FRAME_IND to signal data availability; without ack
	 * it may stop sending more frames. I_HMB_HOST_INT signals
	 * firmware mailbox data — must be read and acked or the
	 * firmware won't transition to connection-ready state. */
	if (sc->sdiocore.base != 0) {
		uint32_t intst = brcmf_sdio_bp_read32(sc,
		    sc->sdiocore.base + SD_REG_INTSTATUS);
		uint32_t ack = intst & (I_HMB_FRAME_IND | I_HMB_HOST_INT |
		    I_HMB_FC_CHANGE);
		if (ack != 0) {
			brcmf_sdio_bp_write32(sc,
			    sc->sdiocore.base + SD_REG_INTSTATUS, ack);
		}
		if (intst & I_HMB_HOST_INT) {
			uint32_t mbox = brcmf_sdio_bp_read32(sc,
			    sc->sdiocore.base + SD_REG_TOHOSTMAILBOXDATA);
			BRCMF_DBG(sc, "mailbox: 0x%08x\n", mbox);
			/* Ack by writing to tosbmailbox */
			brcmf_sdio_bp_write32(sc,
			    sc->sdiocore.base + SD_REG_TOSBMAILBOX,
			    I_SMB_INT_ACK);
		}
	}

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

	/* If frame is larger than 64 bytes, fetch the exact remainder. */
	{
		uint16_t peek_flen = buf[0] | (buf[1] << 8);
		if (peek_flen > 64 && peek_flen <= bufsz) {
			uint32_t remain = peek_flen - 64;
			uint32_t blk = remain & ~63U;
			uint32_t tail = remain - blk;
			uint32_t off = 64;

			if (blk > 0) {
				error = SDIO_READ_EXTENDED(
				    device_get_parent(sc->sdio_func2->dev),
				    sc->sdio_func2->fn, 0x8000, blk,
				    buf + off, false);
				off += blk;
			}
			if (tail > 0) {
				error = SDIO_READ_EXTENDED(
				    device_get_parent(sc->sdio_func2->dev),
				    sc->sdio_func2->fn, 0x8000, tail,
				    buf + off, false);
			}
			/* ignore error on follow-up reads if we have
			 * enough data for the frame */
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
	sc->sdpcm_max_seq = buf[9];

	return (0);
}

/*
 * BCDC IOCTL: send command, wait for response on control channel.
 * Implements bus_ops->ioctl.
 */
int
brcmf_sdpcm_ioctl(struct brcmf_softc *sc, uint32_t cmd,
    void *buf, uint32_t len, uint32_t *resp_len)
{
	uint8_t *txbuf = sc->sdpcm_ioctl_tx;
	uint8_t *rxbuf = sc->sdpcm_ioctl_rx;
	struct bcdc_dcmd *dcmd;
	uint16_t reqid;
	uint32_t flags;
	int error, i;
	int is_set;

	if (sc->fw_dead)
		return (ENXIO);

	mtx_lock(&sc->ioctl_mtx);
	/* Block RX poll task from reading F2 while ioctl is in progress */
	while (!atomic_cmpset_int(&sc->sdpcm_rx_busy, 0, 1))
		DELAY(100);

	reqid = sc->sdpcm_reqid++;
	is_set = (cmd != 262); /* 262 = C_GET_VAR; everything else is a set or non-var cmd */

	/* For C_GET_VAR (262), it's a query. For C_SET_VAR (263), it's a set.
	 * For other commands, check if buf has input data. */
	if (cmd == 263)
		is_set = 1;
	else if (cmd == 262)
		is_set = 0;

	/* Build BCDC header */
	dcmd = (struct bcdc_dcmd *)txbuf;
	dcmd->cmd = htole32(cmd);
	dcmd->len = htole32(len);
	flags = (reqid << BCDC_DCMD_ID_SHIFT);
	if (is_set)
		flags |= BCDC_DCMD_SET;
	dcmd->flags = htole32(flags);
	dcmd->status = 0;

	if (buf != NULL && len > 0) {
		if (len > BRCMF_SDPCM_CTL_BUFSZ - BCDC_DCMD_HDRLEN)
			len = BRCMF_SDPCM_CTL_BUFSZ - BCDC_DCMD_HDRLEN;
		memcpy(txbuf + BCDC_DCMD_HDRLEN, buf, len);
	}

	error = brcmf_sdpcm_send(sc, SDPCM_CONTROL_CHANNEL,
	    txbuf, BCDC_DCMD_HDRLEN + len);
	if (error != 0) {
		device_printf(sc->dev, "SDPCM send failed: %d\n", error);
		atomic_store_rel_int(&sc->sdpcm_rx_busy, 0);
		mtx_unlock(&sc->ioctl_mtx);
		return (error);
	}

	/* Poll for response on control channel */
	int ctrl_frames = 0, event_frames = 0, data_frames = 0;
	int recv_errors = 0, recv_empty = 0;
	for (i = 0; i < BRCMF_SDPCM_IOCTL_TIMEOUT_MS / 10; i++) {
		uint16_t chan, dlen;
		uint8_t *payload;

		pause_sbt("brcmio", mstosbt(10), 0, 0);

		error = brcmf_sdpcm_recv(sc, rxbuf, BRCMF_SDPCM_CTL_BUFSZ,
		    &chan, &dlen, &payload);
		if (error == EAGAIN) {
			recv_empty++;
			continue;
		}
		if (error != 0) {
			recv_errors++;
			continue;
		}

		if (chan == SDPCM_CONTROL_CHANNEL &&
		    dlen >= BCDC_DCMD_HDRLEN) {
			ctrl_frames++;
			struct bcdc_dcmd *resp = (struct bcdc_dcmd *)payload;
			uint32_t rflags = le32toh(resp->flags);
			uint16_t rid = (rflags & BCDC_DCMD_ID_MASK) >>
			    BCDC_DCMD_ID_SHIFT;

			if (rid != reqid)
				continue;

			uint32_t rlen = le32toh(resp->len);
			if (rlen > dlen - BCDC_DCMD_HDRLEN)
				rlen = dlen - BCDC_DCMD_HDRLEN;

			if (resp_len != NULL)
				*resp_len = rlen;

			if (rflags & BCDC_DCMD_ERROR) {
				int32_t fwstatus =
				    (int32_t)le32toh(resp->status);
				BRCMF_DBG(sc,
				    "ioctl cmd=0x%x fwerr=%d\n",
				    cmd, fwstatus);
				atomic_store_rel_int(&sc->sdpcm_rx_busy, 0);
				mtx_unlock(&sc->ioctl_mtx);
				return (EIO);
			}

			if (buf != NULL && rlen > 0) {
				if (rlen > len)
					rlen = len;
				memcpy(buf, payload + BCDC_DCMD_HDRLEN, rlen);
			}

			atomic_store_rel_int(&sc->sdpcm_rx_busy, 0);
			mtx_unlock(&sc->ioctl_mtx);
			return (0);
		}

		/* Non-control frames during ioctl poll — process them */
		if (chan == SDPCM_EVENT_CHANNEL) {
			event_frames++;
			brcmf_sdpcm_process_event(sc, payload, dlen);
		} else if (chan == SDPCM_DATA_CHANNEL) {
			data_frames++;
			brcmf_sdpcm_process_rx(sc, payload, dlen);
		}
	}

	{
		uint32_t intst = 0;
		if (sc->sdiocore.base != 0)
			intst = brcmf_sdio_bp_read32(sc,
			    sc->sdiocore.base + SD_REG_INTSTATUS);
		device_printf(sc->dev,
		    "IOCTL timeout cmd=0x%x intst=0x%08x "
		    "ctrl=%d evt=%d data=%d empty=%d err=%d\n",
		    cmd, intst, ctrl_frames, event_frames,
		    data_frames, recv_empty, recv_errors);
	}
	atomic_store_rel_int(&sc->sdpcm_rx_busy, 0);
	mtx_unlock(&sc->ioctl_mtx);
	return (ETIMEDOUT);
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
 */
int
brcmf_sdpcm_tx(struct brcmf_softc *sc, struct mbuf *m)
{
	uint8_t *frame = sc->sdpcm_data_tx;
	uint16_t pktlen;
	int error;

	if (sc->fw_dead || sc->sdio_func2 == NULL) {
		m_freem(m);
		return (ENXIO);
	}

	pktlen = m->m_pkthdr.len;
	if (BCDC_HEADER_LEN + pktlen > SDPCM_MAX_FRAME_SIZE - SDPCM_HDRLEN) {
		m_freem(m);
		return (EMSGSIZE);
	}

	/* BCDC data header */
	frame[0] = BCDC_PROTO_VER << BCDC_FLAG_VER_SHIFT;
	frame[1] = 0; /* priority */
	frame[2] = 0; /* ifidx */
	frame[3] = 0; /* data_offset */

	m_copydata(m, 0, pktlen, frame + BCDC_HEADER_LEN);
	m_freem(m);

	error = brcmf_sdpcm_send(sc, SDPCM_DATA_CHANNEL,
	    frame, BCDC_HEADER_LEN + pktlen);

	return (error);
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

	/*
	 * Skip if an ioctl is in progress — the ioctl poll loop
	 * reads the F2 FIFO and handles events/data inline.
	 * Running concurrently would interleave partial FIFO reads.
	 */
	if (!atomic_cmpset_int(&sc->sdpcm_rx_busy, 0, 1))
		return;

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
		if (chan == SDPCM_EVENT_CHANNEL)
			brcmf_sdpcm_process_event(sc, payload, dlen);
		else if (chan == SDPCM_DATA_CHANNEL)
			brcmf_sdpcm_process_rx(sc, payload, dlen);
	}
	atomic_store_rel_int(&sc->sdpcm_rx_busy, 0);
}

/*
 * Callout handler — enqueues rx_task.
 * Cannot do SDIO I/O directly (callout context can't sleep).
 */
static void
brcmf_sdpcm_poll(void *arg)
{
	struct brcmf_softc *sc = arg;

	if (sc->fw_dead || sc->detaching)
		return;

	taskqueue_enqueue(taskqueue_thread, &sc->sdpcm_rx_task);
	callout_reset(&sc->sdpcm_callout, hz / 20, brcmf_sdpcm_poll, sc);
}

/*
 * Start the RX polling callout. Called after attach is complete.
 */
void
brcmf_sdpcm_start_poll(struct brcmf_softc *sc)
{
	TASK_INIT(&sc->sdpcm_rx_task, 0, brcmf_sdpcm_rx_task, sc);
	callout_init(&sc->sdpcm_callout, 1);
	sc->sdpcm_poll_started = 1;
	callout_reset(&sc->sdpcm_callout, hz / 20, brcmf_sdpcm_poll, sc);
}

/*
 * Stop the RX polling callout and drain pending tasks.
 */
void
brcmf_sdpcm_stop_poll(struct brcmf_softc *sc)
{
	if (!sc->sdpcm_poll_started)
		return;
	sc->sdpcm_poll_started = 0;
	callout_drain(&sc->sdpcm_callout);
	taskqueue_drain(taskqueue_thread, &sc->sdpcm_rx_task);
}

/*
 * SDPCM cleanup. Implements bus_ops->cleanup.
 */
void
brcmf_sdpcm_cleanup(struct brcmf_softc *sc)
{
	brcmf_sdpcm_stop_poll(sc);
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
