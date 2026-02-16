/* Message buffer protocol: ring operations, D2H processing, IOCTL handling */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bus.h>
#include <sys/epoch.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/socket.h>

#include <net/if.h>
#include <net/if_var.h>
#include <net/if_media.h>
#include <net/ethernet.h>

#include <net80211/ieee80211_var.h>

#include "brcmfmac.h"

/* PCIe register offsets */
#define BRCMF_PCIE_PCIE2REG_H2D_MAILBOX_0 0x140

/* Buffer sizes */
#define BRCMF_MSGBUF_MAX_CTL_PKT_SIZE	   8192
#define BRCMF_MSGBUF_MAX_IOCTLRESPBUF_POST 8
#define BRCMF_MSGBUF_MAX_EVENTBUF_POST	   8
#define BRCMF_MSGBUF_MAX_PKT_SIZE	   2048

/* IOCTL */
#define BRCMF_IOCTL_REQ_PKTID  0xFFFE
#define BRCMF_IOCTL_TIMEOUT_MS 2000

/* msgbuf message types */
#define MSGBUF_TYPE_GEN_STATUS		 0x01
#define MSGBUF_TYPE_RING_STATUS		 0x02
#define MSGBUF_TYPE_IOCTLPTR_REQ	 0x09
#define MSGBUF_TYPE_IOCTLPTR_REQ_ACK	 0x0a
#define MSGBUF_TYPE_IOCTLRESP_BUF_POST	 0x0b
#define MSGBUF_TYPE_IOCTL_CMPLT		 0x0c
#define MSGBUF_TYPE_EVENT_BUF_POST	 0x0d
#define MSGBUF_TYPE_WL_EVENT		 0x0e
#define MSGBUF_TYPE_TX_POST		 0x0f
#define MSGBUF_TYPE_TX_STATUS		 0x10
#define MSGBUF_TYPE_RXBUF_POST		 0x11
#define MSGBUF_TYPE_RX_CMPLT		 0x12

/* Event codes (for brcmf_link_event) */
#define BRCMF_E_SET_SSID	0
#define BRCMF_E_LINK		16

/*
 * msgbuf structures
 */
struct msgbuf_common_hdr {
	uint8_t msgtype;
	uint8_t ifidx;
	uint8_t flags;
	uint8_t rsvd0;
	uint32_t request_id;
} __packed;

struct msgbuf_buf_addr {
	uint32_t low_addr;
	uint32_t high_addr;
} __packed;

struct msgbuf_completion_hdr {
	uint16_t status;
	uint16_t flow_ring_id;
} __packed;

struct msgbuf_rx_ioctl_resp_or_event {
	struct msgbuf_common_hdr msg;
	uint16_t host_buf_len;
	uint16_t rsvd0[3];
	struct msgbuf_buf_addr host_buf_addr;
	uint32_t rsvd1[4];
} __packed;

struct msgbuf_rx_bufpost {
	struct msgbuf_common_hdr msg;
	uint16_t metadata_buf_len;
	uint16_t data_buf_len;
	uint32_t rsvd0;
	struct msgbuf_buf_addr metadata_buf_addr;
	struct msgbuf_buf_addr data_buf_addr;
} __packed;

struct msgbuf_ioctl_req_hdr {
	struct msgbuf_common_hdr msg;
	uint32_t cmd;
	uint16_t trans_id;
	uint16_t input_buf_len;
	uint16_t output_buf_len;
	uint16_t rsvd0[3];
	struct msgbuf_buf_addr req_buf_addr;
	uint32_t rsvd1[2];
} __packed;

struct msgbuf_ioctl_resp_hdr {
	struct msgbuf_common_hdr msg;
	struct msgbuf_completion_hdr compl_hdr;
	uint16_t resp_len;
	uint16_t trans_id;
	uint32_t cmd;
	uint32_t rsvd0;
} __packed;

struct msgbuf_rx_event {
	struct msgbuf_common_hdr msg;
	struct msgbuf_completion_hdr compl_hdr;
	uint16_t event_data_len;
	uint16_t seqnum;
	uint16_t rsvd0[4];
} __packed;

struct msgbuf_gen_status {
	struct msgbuf_common_hdr msg;
	struct msgbuf_completion_hdr compl_hdr;
	uint16_t write_idx;
	uint32_t rsvd0[3];
} __packed;

struct msgbuf_ring_status {
	struct msgbuf_common_hdr msg;
	struct msgbuf_completion_hdr compl_hdr;
	uint16_t write_idx;
	uint16_t rsvd0[5];
} __packed;

struct msgbuf_rx_complete {
	struct msgbuf_common_hdr msg;
	struct msgbuf_completion_hdr compl_hdr;
	uint16_t metadata_len;
	uint16_t data_len;
	uint16_t data_offset;
	uint16_t flags;
	uint32_t rx_status_0;
	uint32_t rx_status_1;
	uint32_t rsvd0;
} __packed;

struct msgbuf_tx_status {
	struct msgbuf_common_hdr msg;
	struct msgbuf_completion_hdr compl_hdr;
	uint16_t metadata_len;
	uint16_t tx_status;
} __packed;

#define BRCMF_MSGBUF_PKT_FLAGS_FRAME_802_3	0x01
#define BRCMF_MSGBUF_PKT_FLAGS_FRAME_802_11	0x02
#define BRCMF_MSGBUF_PKT_FLAGS_FRAME_MASK	0x07
#define BRCMF_MSGBUF_PKT_FLAGS_PRIO_SHIFT	5

#define ETH_HLEN	14

struct msgbuf_tx_msghdr {
	struct msgbuf_common_hdr msg;
	uint8_t txhdr[ETH_HLEN];
	uint8_t flags;
	uint8_t seg_cnt;
	struct msgbuf_buf_addr metadata_buf_addr;
	struct msgbuf_buf_addr data_buf_addr;
	uint16_t metadata_buf_len;
	uint16_t data_len;
	uint32_t rsvd0;
} __packed;

struct msgbuf_flowring_create {
	struct msgbuf_common_hdr msg;
	uint8_t da[6];
	uint8_t sa[6];
	uint8_t tid;
	uint8_t if_flags;
	uint16_t flow_ring_id;
	uint8_t tc;
	uint8_t priority;
	uint16_t int_vector;
	uint16_t max_items;
	uint16_t len_item;
	struct msgbuf_buf_addr flow_ring_addr;
} __packed;

struct msgbuf_flowring_create_cmplt {
	struct msgbuf_common_hdr msg;
	struct msgbuf_completion_hdr compl_hdr;
	uint32_t rsvd0;
} __packed;

#define MSGBUF_TYPE_FLOW_RING_CREATE		0x03
#define MSGBUF_TYPE_FLOW_RING_CREATE_CMPLT	0x04

#define BRCMF_FLOWRING_SIZE	512
#define BRCMF_FLOWRING_ITEM_SIZE sizeof(struct msgbuf_tx_msghdr)

/* Event packet structures */
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

#define BRCM_OUI "\x00\x10\x18"

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

/* Event codes */
#define BRCMF_E_ESCAN_RESULT 69

/*
 * Ring the H2D doorbell to notify firmware.
 */
void
brcmf_msgbuf_ring_doorbell(struct brcmf_softc *sc)
{
	brcmf_pcie_select_core(sc, &sc->pciecore);
	brcmf_reg_write(sc, BRCMF_PCIE_PCIE2REG_H2D_MAILBOX_0, 1);
}

/*
 * Update write index in TCM after writing to ring.
 */
static void
brcmf_ring_write_wptr(struct brcmf_softc *sc, struct brcmf_pcie_ringbuf *ring)
{
	brcmf_tcm_write16(sc, ring->w_idx_addr, ring->w_ptr);
}

/*
 * Read current read index from TCM.
 */
static uint16_t
brcmf_ring_read_rptr(struct brcmf_softc *sc, struct brcmf_pcie_ringbuf *ring)
{
	ring->r_ptr = brcmf_tcm_read16(sc, ring->r_idx_addr);
	return (ring->r_ptr);
}

/*
 * Read current write index from TCM (for D2H rings).
 */
static uint16_t
brcmf_ring_read_wptr(struct brcmf_softc *sc, struct brcmf_pcie_ringbuf *ring)
{
	ring->w_ptr = brcmf_tcm_read16(sc, ring->w_idx_addr);
	return (ring->w_ptr);
}

/*
 * Update read index in TCM after reading from ring.
 */
static void
brcmf_ring_write_rptr(struct brcmf_softc *sc, struct brcmf_pcie_ringbuf *ring)
{
	brcmf_tcm_write16(sc, ring->r_idx_addr, ring->r_ptr);
}

/*
 * Reserve space in a ring for writing.
 */
void *
brcmf_msgbuf_ring_reserve(struct brcmf_softc *sc, struct brcmf_pcie_ringbuf *ring)
{
	uint16_t available;
	void *ret;

	brcmf_ring_read_rptr(sc, ring);

	if (ring->r_ptr <= ring->w_ptr)
		available = ring->depth - ring->w_ptr + ring->r_ptr;
	else
		available = ring->r_ptr - ring->w_ptr;

	if (available < 2)
		return (NULL);

	ret = (char *)ring->buf + ring->w_ptr * ring->item_len;
	ring->w_ptr++;
	if (ring->w_ptr >= ring->depth)
		ring->w_ptr = 0;

	return (ret);
}

/*
 * Commit writes to ring and notify firmware.
 */
void
brcmf_msgbuf_ring_submit(struct brcmf_softc *sc, struct brcmf_pcie_ringbuf *ring)
{
	brcmf_ring_write_wptr(sc, ring);
	brcmf_msgbuf_ring_doorbell(sc);
}

static int brcmf_msgbuf_post_ctrlbuf(struct brcmf_softc *, uint8_t,
    struct brcmf_ctrlbuf *);

/*
 * Process firmware event from event buffer.
 */
static void
brcmf_msgbuf_process_event(struct brcmf_softc *sc, struct msgbuf_common_hdr *msg)
{
	struct brcmf_ctrlbuf *cb;
	struct brcmf_event *event;
	uint32_t pktid, event_code, datalen;
	int idx;

	pktid = le32toh(msg->request_id);

	if (pktid < 0x20000 || pktid >= 0x20000 + BRCMF_MSGBUF_MAX_EVENTBUF_POST) {
		printf("brcmfmac: event with invalid pktid 0x%x\n", pktid);
		return;
	}

	idx = pktid - 0x20000;
	cb = &sc->event_buf[idx];

	if (cb->buf == NULL) {
		printf("brcmfmac: event buffer %d is NULL\n", idx);
		return;
	}

	/* Sync DMA before reading */
	bus_dmamap_sync(cb->dma_tag, cb->dma_map, BUS_DMASYNC_POSTREAD);

	event = cb->buf;

	if (memcmp(event->oui, BRCM_OUI, 3) != 0) {
		printf("brcmfmac: event with invalid OUI %02x:%02x:%02x\n",
		    event->oui[0], event->oui[1], event->oui[2]);
		goto repost;
	}

	event_code = be32toh(event->msg.event_type);
	datalen = be32toh(event->msg.datalen);

	switch (event_code) {
	case BRCMF_E_SET_SSID:
	case BRCMF_E_LINK:
		brcmf_link_event(sc, event_code, be32toh(event->msg.status),
		    be16toh(event->msg.flags));
		break;
	case BRCMF_E_ESCAN_RESULT:
		if (datalen > 0 && datalen < BRCMF_MSGBUF_MAX_CTL_PKT_SIZE - sizeof(*event))
			brcmf_escan_result(sc, (uint8_t *)cb->buf + sizeof(*event), datalen);
		break;
	case 54: /* BRCMF_E_IF - interface event, ignored */
		break;
	default:
		break;
	}

repost:
	/* Re-post the event buffer for reuse */
	brcmf_msgbuf_post_ctrlbuf(sc, MSGBUF_TYPE_EVENT_BUF_POST, cb);
}

/*
 * Process control complete ring.
 */
static void
brcmf_msgbuf_process_ctrl_complete(struct brcmf_softc *sc)
{
	struct brcmf_pcie_ringbuf *ring;
	struct msgbuf_common_hdr *msg;
	struct msgbuf_ioctl_resp_hdr *ioctl_resp;
	uint32_t pktid;
	uint16_t avail, i, resp_len;

	ring = sc->commonrings[BRCMF_D2H_MSGRING_CONTROL_COMPLETE];

	brcmf_ring_read_wptr(sc, ring);

	if (ring->w_ptr >= ring->r_ptr)
		avail = ring->w_ptr - ring->r_ptr;
	else
		avail = ring->depth - ring->r_ptr;

	if (avail == 0)
		return;

	for (i = 0; i < avail; i++) {
		msg = (struct msgbuf_common_hdr *)((char *)ring->buf +
		    ring->r_ptr * ring->item_len);

		switch (msg->msgtype) {
		case MSGBUF_TYPE_IOCTL_CMPLT:
			ioctl_resp = (struct msgbuf_ioctl_resp_hdr *)msg;
			sc->ioctl_status = le16toh(ioctl_resp->compl_hdr.status);
			resp_len = le16toh(ioctl_resp->resp_len);
			sc->ioctl_resp_len = resp_len;

			pktid = le32toh(msg->request_id);
			if (pktid >= 0x10000 &&
			    pktid < 0x10000 + BRCMF_MSGBUF_MAX_IOCTLRESPBUF_POST) {
				int idx = pktid - 0x10000;
				if (resp_len > 0 &&
				    resp_len <= BRCMF_MSGBUF_MAX_CTL_PKT_SIZE)
					memcpy(sc->ioctlbuf,
					    sc->ioctlresp_buf[idx].buf, resp_len);
				/* Re-post the IOCTL response buffer */
				brcmf_msgbuf_post_ctrlbuf(sc,
				    MSGBUF_TYPE_IOCTLRESP_BUF_POST,
				    &sc->ioctlresp_buf[idx]);
			}

			sc->ioctl_completed = 1;
			wakeup(&sc->ioctl_completed);
			break;

		case MSGBUF_TYPE_WL_EVENT:
			brcmf_msgbuf_process_event(sc, msg);
			break;

		case MSGBUF_TYPE_IOCTLPTR_REQ_ACK:
			break;

		case MSGBUF_TYPE_GEN_STATUS:
		case MSGBUF_TYPE_RING_STATUS:
			/* Firmware status messages - just consume them */
			break;

		case MSGBUF_TYPE_FLOW_RING_CREATE_CMPLT:
			sc->flowring_create_status =
			    le16toh(((struct msgbuf_flowring_create_cmplt *)msg)->compl_hdr.status);
			sc->flowring_create_done = 1;
			wakeup(&sc->flowring_create_done);
			break;

		default:
			printf("brcmfmac: ctrl complete unknown msgtype 0x%x\n",
			    msg->msgtype);
			break;
		}

		ring->r_ptr++;
		if (ring->r_ptr >= ring->depth)
			ring->r_ptr = 0;
	}

	brcmf_ring_write_rptr(sc, ring);
}

/*
 * Process TX complete ring.
 */
static void
brcmf_msgbuf_process_tx_complete(struct brcmf_softc *sc)
{
	struct brcmf_pcie_ringbuf *ring;
	struct msgbuf_tx_status *tx;
	uint32_t pktid;
	uint16_t avail, i;
	int idx;

	ring = sc->commonrings[BRCMF_D2H_MSGRING_TX_COMPLETE];

	brcmf_ring_read_wptr(sc, ring);

	if (ring->w_ptr >= ring->r_ptr)
		avail = ring->w_ptr - ring->r_ptr;
	else
		avail = ring->depth - ring->r_ptr;

	if (avail == 0)
		return;

	for (i = 0; i < avail; i++) {
		tx = (struct msgbuf_tx_status *)((char *)ring->buf +
		    ring->r_ptr * ring->item_len);

		if (tx->msg.msgtype != MSGBUF_TYPE_TX_STATUS) {
			ring->r_ptr++;
			if (ring->r_ptr >= ring->depth)
				ring->r_ptr = 0;
			continue;
		}

		pktid = le32toh(tx->msg.request_id);

		printf("brcmfmac: TX_STATUS pktid=0x%x status=%d msgtype=0x%x\n",
		    pktid, le16toh(tx->tx_status), tx->msg.msgtype);

		/* Validate and free TX buffer */
		if (pktid >= 0x40000 && pktid < 0x40000 + BRCMF_TX_RING_SIZE) {
			idx = pktid - 0x40000;
			if (sc->txbuf[idx].m != NULL) {
				bus_dmamap_sync(sc->txbuf[idx].dma_tag,
				    sc->txbuf[idx].dma_map,
				    BUS_DMASYNC_POSTWRITE);
				bus_dmamap_unload(sc->txbuf[idx].dma_tag,
				    sc->txbuf[idx].dma_map);
				m_freem(sc->txbuf[idx].m);
				sc->txbuf[idx].m = NULL;
			}
		}

		ring->r_ptr++;
		if (ring->r_ptr >= ring->depth)
			ring->r_ptr = 0;
	}

	brcmf_ring_write_rptr(sc, ring);
}

static int brcmf_msgbuf_post_rxbuf(struct brcmf_softc *, struct brcmf_ctrlbuf *);

/*
 * Deliver received Ethernet frame to net80211.
 */
static void
brcmf_rx_deliver(struct brcmf_softc *sc, void *data, uint16_t len)
{
	struct ieee80211com *ic = &sc->ic;
	struct ieee80211vap *vap;
	if_t ifp;
	struct mbuf *m;

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
		uint8_t *eh = data;
		static int rx_count = 0;
		if (rx_count < 10)
			printf("brcmfmac: RX #%d len=%u dst=%02x:%02x:%02x:%02x:%02x:%02x "
			    "src=%02x:%02x:%02x:%02x:%02x:%02x type=%02x%02x\n",
			    rx_count, len,
			    eh[0],eh[1],eh[2],eh[3],eh[4],eh[5],
			    eh[6],eh[7],eh[8],eh[9],eh[10],eh[11],
			    eh[12],eh[13]);
		rx_count++;
	}

	/* Deliver as Ethernet frame */
	{
		struct epoch_tracker et;
		NET_EPOCH_ENTER(et);
		if_input(ifp, m);
		NET_EPOCH_EXIT(et);
	}
}

/*
 * Process RX complete ring.
 */
static void
brcmf_msgbuf_process_rx_complete(struct brcmf_softc *sc)
{
	struct brcmf_pcie_ringbuf *ring, *rxpost_ring;
	struct msgbuf_rx_complete *rx;
	struct brcmf_ctrlbuf *cb;
	uint32_t pktid;
	uint16_t avail, i, data_len, data_offset, flags;
	int idx, repost_count = 0;

	ring = sc->commonrings[BRCMF_D2H_MSGRING_RX_COMPLETE];

	brcmf_ring_read_wptr(sc, ring);

	if (ring->w_ptr >= ring->r_ptr)
		avail = ring->w_ptr - ring->r_ptr;
	else
		avail = ring->depth - ring->r_ptr;

	if (avail == 0)
		return;

	for (i = 0; i < avail; i++) {
		rx = (struct msgbuf_rx_complete *)((char *)ring->buf +
		    ring->r_ptr * ring->item_len);

		if (rx->msg.msgtype != MSGBUF_TYPE_RX_CMPLT) {
			ring->r_ptr++;
			if (ring->r_ptr >= ring->depth)
				ring->r_ptr = 0;
			continue;
		}

		pktid = le32toh(rx->msg.request_id);
		data_len = le16toh(rx->data_len);
		data_offset = le16toh(rx->data_offset);
		flags = le16toh(rx->flags);

		/* Validate pktid */
		if (pktid < 0x30000 || pktid >= 0x30000 + sc->rxbufpost) {
			printf("brcmfmac: RX with invalid pktid 0x%x\n", pktid);
			goto next;
		}

		idx = pktid - 0x30000;
		cb = &sc->rxbuf[idx];

		if (cb->buf == NULL) {
			printf("brcmfmac: RX buffer %d is NULL\n", idx);
			goto next;
		}

		/* Sync DMA before reading */
		bus_dmamap_sync(cb->dma_tag, cb->dma_map, BUS_DMASYNC_POSTREAD);

		/* Only deliver 802.3 frames */
		if ((flags & BRCMF_MSGBUF_PKT_FLAGS_FRAME_MASK) ==
		    BRCMF_MSGBUF_PKT_FLAGS_FRAME_802_3) {
			if (data_len > 0 && data_len <= BRCMF_MSGBUF_MAX_PKT_SIZE) {
				brcmf_rx_deliver(sc,
				    (char *)cb->buf + data_offset, data_len);
			}
		}

		/* Repost the buffer */
		brcmf_msgbuf_post_rxbuf(sc, cb);
		repost_count++;

next:
		ring->r_ptr++;
		if (ring->r_ptr >= ring->depth)
			ring->r_ptr = 0;
	}

	brcmf_ring_write_rptr(sc, ring);

	/* Submit reposted buffers */
	if (repost_count > 0) {
		rxpost_ring = sc->commonrings[BRCMF_H2D_MSGRING_RXPOST_SUBMIT];
		brcmf_msgbuf_ring_submit(sc, rxpost_ring);
	}
}

/*
 * Process D2H completion rings.
 */
void
brcmf_msgbuf_process_d2h(struct brcmf_softc *sc)
{
	struct brcmf_pcie_ringbuf *tx_ring, *rx_ring;
	uint16_t tx_w, rx_w;
	static int dbg_count = 0;

	tx_ring = sc->commonrings[BRCMF_D2H_MSGRING_TX_COMPLETE];
	rx_ring = sc->commonrings[BRCMF_D2H_MSGRING_RX_COMPLETE];

	/* Sync DMA before checking indices */
	bus_dmamap_sync(rx_ring->dma_tag, rx_ring->dma_map,
	    BUS_DMASYNC_POSTREAD);

	/* Read write pointers from TCM */
	tx_w = brcmf_tcm_read16(sc, tx_ring->w_idx_addr);
	rx_w = brcmf_tcm_read16(sc, rx_ring->w_idx_addr);

	/* Check if firmware wrote to RX data buffers */
	if (dbg_count < 3 && tx_w != 0 && sc->rxbuf != NULL) {
		uint8_t *p;
		int j;
		for (j = 0; j < 3 && j < (int)sc->rxbufpost; j++) {
			if (sc->rxbuf[j].buf == NULL)
				continue;
			bus_dmamap_sync(sc->rxbuf[j].dma_tag,
			    sc->rxbuf[j].dma_map, BUS_DMASYNC_POSTREAD);
			p = (uint8_t *)sc->rxbuf[j].buf;
			if (p[0] != 0 || p[1] != 0 || p[2] != 0 || p[3] != 0) {
				printf("brcmfmac: rxbuf[%d] has data: %02x%02x%02x%02x %02x%02x%02x%02x\n",
				    j, p[0],p[1],p[2],p[3],p[4],p[5],p[6],p[7]);
			}
		}
	}

	/* Also check ringupd buffer for D2H write indices */
	if (sc->ringupd_buf != NULL && dbg_count < 5) {
		uint32_t *rupd = (uint32_t *)sc->ringupd_buf;
		bus_dmamap_sync(sc->ringupd_dma_tag, sc->ringupd_dma_map,
		    BUS_DMASYNC_POSTREAD);
		if (rupd[0] != 0 || rupd[1] != 0 || rupd[2] != 0) {
			printf("brcmfmac: ringupd buf[0..7]: %u %u %u %u %u %u %u %u\n",
			    rupd[0], rupd[1], rupd[2], rupd[3],
			    rupd[4], rupd[5], rupd[6], rupd[7]);
		}
	}
	if (tx_w != 0 && dbg_count == 0) {
		uint32_t base = sc->d2h_w_idx_addr;
		int j;
		printf("brcmfmac: d2h_w_idx base=0x%x, dumping 16 uint32s:\n", base);
		for (j = 0; j < 16; j++) {
			uint32_t v = brcmf_tcm_read32(sc, base + j * 4);
			printf("  [%d] 0x%x+%d = 0x%08x (%u)\n",
			    j, base, j * 4, v, v);
		}
		printf("brcmfmac: d2h_r_idx base=0x%x:\n", sc->d2h_r_idx_addr);
		for (j = 0; j < 8; j++) {
			uint32_t v = brcmf_tcm_read32(sc, sc->d2h_r_idx_addr + j * 4);
			printf("  [%d] 0x%x+%d = 0x%08x\n",
			    j, sc->d2h_r_idx_addr, j * 4, v);
		}
		printf("brcmfmac: ring addrs: ctrl_w=0x%x tx_w=0x%x rx_w=0x%x\n",
		    sc->commonrings[BRCMF_D2H_MSGRING_CONTROL_COMPLETE]->w_idx_addr,
		    tx_ring->w_idx_addr, rx_ring->w_idx_addr);
		printf("brcmfmac: rx_dataoffset=%d\n", sc->shared.rx_dataoffset);
		/* Dump first RXPOST entry to verify format */
		{
			struct brcmf_pcie_ringbuf *rp =
			    sc->commonrings[BRCMF_H2D_MSGRING_RXPOST_SUBMIT];
			uint8_t *p = (uint8_t *)rp->buf;
			printf("brcmfmac: RXPOST buf[0..31]: "
			    "%02x%02x%02x%02x %02x%02x%02x%02x "
			    "%02x%02x%02x%02x %02x%02x%02x%02x "
			    "%02x%02x%02x%02x %02x%02x%02x%02x "
			    "%02x%02x%02x%02x %02x%02x%02x%02x\n",
			    p[0],p[1],p[2],p[3],p[4],p[5],p[6],p[7],
			    p[8],p[9],p[10],p[11],p[12],p[13],p[14],p[15],
			    p[16],p[17],p[18],p[19],p[20],p[21],p[22],p[23],
			    p[24],p[25],p[26],p[27],p[28],p[29],p[30],p[31]);
		}
		/* Dump first entry of TX_COMPLETE ring */
		{
			uint8_t *p = (uint8_t *)tx_ring->buf;
			printf("brcmfmac: TX_CMPLT buf[0..15]: "
			    "%02x%02x%02x%02x %02x%02x%02x%02x "
			    "%02x%02x%02x%02x %02x%02x%02x%02x\n",
			    p[0],p[1],p[2],p[3],p[4],p[5],p[6],p[7],
			    p[8],p[9],p[10],p[11],p[12],p[13],p[14],p[15]);
		}
		/* Dump first entry of CTRL_COMPLETE ring */
		{
			struct brcmf_pcie_ringbuf *cr =
			    sc->commonrings[BRCMF_D2H_MSGRING_CONTROL_COMPLETE];
			uint8_t *p = (uint8_t *)cr->buf;
			printf("brcmfmac: CTRL_CMPLT buf[0..23]: "
			    "%02x%02x%02x%02x %02x%02x%02x%02x "
			    "%02x%02x%02x%02x %02x%02x%02x%02x "
			    "%02x%02x%02x%02x %02x%02x%02x%02x\n",
			    p[0],p[1],p[2],p[3],p[4],p[5],p[6],p[7],
			    p[8],p[9],p[10],p[11],p[12],p[13],p[14],p[15],
			    p[16],p[17],p[18],p[19],p[20],p[21],p[22],p[23]);
		}
		/* Dump ring descriptors for rings 0-4 */
		{
			uint32_t rm = sc->ringmem_addr;
			int k;
			for (k = 0; k < 5; k++) {
				uint32_t da = rm + k * 16;
				uint16_t depth = brcmf_tcm_read16(sc, da + 4);
				uint16_t ilen = brcmf_tcm_read16(sc, da + 6);
				uint32_t lo = brcmf_tcm_read32(sc, da + 8);
				uint32_t hi = brcmf_tcm_read32(sc, da + 12);
				printf("brcmfmac: ringdesc[%d] depth=%d ilen=%d base=0x%x%08x\n",
				    k, depth, ilen, hi, lo);
			}
		}
		/* Check RXPOST w/r pointers */
		{
			struct brcmf_pcie_ringbuf *rxpost;
			rxpost = sc->commonrings[BRCMF_H2D_MSGRING_RXPOST_SUBMIT];
			printf("brcmfmac: RXPOST w_idx=0x%x(%d) r_idx=0x%x(%d)\n",
			    rxpost->w_idx_addr,
			    brcmf_tcm_read16(sc, rxpost->w_idx_addr),
			    rxpost->r_idx_addr,
			    brcmf_tcm_read16(sc, rxpost->r_idx_addr));
		}
		/* Also dump first 64 bytes of RX complete ring buffer */
		{
			uint8_t *p = (uint8_t *)rx_ring->buf;
			printf("brcmfmac: RX_CMPLT ring buf[0..31]: "
			    "%02x%02x%02x%02x %02x%02x%02x%02x "
			    "%02x%02x%02x%02x %02x%02x%02x%02x "
			    "%02x%02x%02x%02x %02x%02x%02x%02x "
			    "%02x%02x%02x%02x %02x%02x%02x%02x\n",
			    p[0],p[1],p[2],p[3],p[4],p[5],p[6],p[7],
			    p[8],p[9],p[10],p[11],p[12],p[13],p[14],p[15],
			    p[16],p[17],p[18],p[19],p[20],p[21],p[22],p[23],
			    p[24],p[25],p[26],p[27],p[28],p[29],p[30],p[31]);
		}
		dbg_count++;
	}
	if (tx_w != 0 && dbg_count < 10) {
		printf("brcmfmac: D2H TX_w=%d RX_w=%d\n", tx_w, rx_w);
		dbg_count++;
	}

	brcmf_pcie_console_read(sc);
	brcmf_msgbuf_process_ctrl_complete(sc);
	brcmf_msgbuf_process_tx_complete(sc);
	brcmf_msgbuf_process_rx_complete(sc);
}

/*
 * Allocate a single control buffer.
 */
static int
brcmf_alloc_ctrlbuf(struct brcmf_softc *sc, struct brcmf_ctrlbuf *cb,
    size_t size, uint32_t pktid)
{
	int error;

	error = brcmf_alloc_dma_buf(sc->dev, size, &cb->dma_tag, &cb->dma_map,
	    &cb->buf, &cb->paddr);
	if (error != 0)
		return (error);

	cb->pktid = pktid;
	return (0);
}

/*
 * Free a single control buffer.
 */
static void
brcmf_free_ctrlbuf(struct brcmf_ctrlbuf *cb)
{
	brcmf_free_dma_buf(cb->dma_tag, cb->dma_map, cb->buf);
	cb->dma_tag = NULL;
	cb->buf = NULL;
}

/*
 * Post a single IOCTL response or event buffer to control submit ring.
 */
static int
brcmf_msgbuf_post_ctrlbuf(struct brcmf_softc *sc, uint8_t msgtype,
    struct brcmf_ctrlbuf *cb)
{
	struct brcmf_pcie_ringbuf *ring;
	struct msgbuf_rx_ioctl_resp_or_event *msg;

	ring = sc->commonrings[BRCMF_H2D_MSGRING_CONTROL_SUBMIT];
	msg = brcmf_msgbuf_ring_reserve(sc, ring);
	if (msg == NULL)
		return (ENOBUFS);

	memset(msg, 0, sizeof(*msg));
	msg->msg.msgtype = msgtype;
	msg->msg.request_id = htole32(cb->pktid);
	msg->host_buf_len = htole16(BRCMF_MSGBUF_MAX_CTL_PKT_SIZE);
	msg->host_buf_addr.low_addr = htole32((uint32_t)cb->paddr);
	msg->host_buf_addr.high_addr = htole32((uint32_t)(cb->paddr >> 32));

	brcmf_msgbuf_ring_submit(sc, ring);
	return (0);
}

/*
 * Allocate and post initial IOCTL response buffers.
 */
static int
brcmf_msgbuf_init_ioctlresp(struct brcmf_softc *sc)
{
	int i, error;

	sc->ioctlresp_buf = malloc(
	    BRCMF_MSGBUF_MAX_IOCTLRESPBUF_POST * sizeof(struct brcmf_ctrlbuf),
	    M_BRCMFMAC, M_NOWAIT | M_ZERO);
	if (sc->ioctlresp_buf == NULL)
		return (ENOMEM);

	for (i = 0; i < BRCMF_MSGBUF_MAX_IOCTLRESPBUF_POST; i++) {
		error = brcmf_alloc_ctrlbuf(sc, &sc->ioctlresp_buf[i],
		    BRCMF_MSGBUF_MAX_CTL_PKT_SIZE, 0x10000 + i);
		if (error != 0)
			return (error);

		error = brcmf_msgbuf_post_ctrlbuf(sc,
		    MSGBUF_TYPE_IOCTLRESP_BUF_POST, &sc->ioctlresp_buf[i]);
		if (error != 0)
			return (error);
	}

	sc->cur_ioctlrespbuf = BRCMF_MSGBUF_MAX_IOCTLRESPBUF_POST;
	device_printf(sc->dev, "posted %d IOCTL response buffers\n",
	    BRCMF_MSGBUF_MAX_IOCTLRESPBUF_POST);
	return (0);
}

/*
 * Allocate and post initial event buffers.
 */
static int
brcmf_msgbuf_init_event(struct brcmf_softc *sc)
{
	int i, error;

	sc->event_buf = malloc(
	    BRCMF_MSGBUF_MAX_EVENTBUF_POST * sizeof(struct brcmf_ctrlbuf),
	    M_BRCMFMAC, M_NOWAIT | M_ZERO);
	if (sc->event_buf == NULL)
		return (ENOMEM);

	for (i = 0; i < BRCMF_MSGBUF_MAX_EVENTBUF_POST; i++) {
		error = brcmf_alloc_ctrlbuf(sc, &sc->event_buf[i],
		    BRCMF_MSGBUF_MAX_CTL_PKT_SIZE, 0x20000 + i);
		if (error != 0)
			return (error);

		error = brcmf_msgbuf_post_ctrlbuf(sc,
		    MSGBUF_TYPE_EVENT_BUF_POST, &sc->event_buf[i]);
		if (error != 0)
			return (error);
	}

	sc->cur_eventbuf = BRCMF_MSGBUF_MAX_EVENTBUF_POST;
	device_printf(sc->dev, "posted %d event buffers\n",
	    BRCMF_MSGBUF_MAX_EVENTBUF_POST);
	return (0);
}

/*
 * Post a single RX data buffer to RX post ring.
 */
static int
brcmf_msgbuf_post_rxbuf(struct brcmf_softc *sc, struct brcmf_ctrlbuf *cb)
{
	struct brcmf_pcie_ringbuf *ring;
	struct msgbuf_rx_bufpost *msg;

	ring = sc->commonrings[BRCMF_H2D_MSGRING_RXPOST_SUBMIT];
	msg = brcmf_msgbuf_ring_reserve(sc, ring);
	if (msg == NULL)
		return (ENOBUFS);

	memset(msg, 0, sizeof(*msg));
	msg->msg.msgtype = MSGBUF_TYPE_RXBUF_POST;
	msg->msg.request_id = htole32(cb->pktid);
	msg->data_buf_len = htole16(BRCMF_MSGBUF_MAX_PKT_SIZE);
	msg->data_buf_addr.low_addr = htole32((uint32_t)cb->paddr);
	msg->data_buf_addr.high_addr = htole32((uint32_t)(cb->paddr >> 32));

	return (0);
}

/*
 * Allocate and post initial RX data buffers.
 */
static int
brcmf_msgbuf_init_rxbuf(struct brcmf_softc *sc)
{
	struct brcmf_pcie_ringbuf *ring;
	uint32_t count;
	int i, error;

	count = sc->shared.max_rxbufpost;
	if (count == 0)
		count = 255;

	sc->rxbuf = malloc(count * sizeof(struct brcmf_ctrlbuf),
	    M_BRCMFMAC, M_NOWAIT | M_ZERO);
	if (sc->rxbuf == NULL)
		return (ENOMEM);

	ring = sc->commonrings[BRCMF_H2D_MSGRING_RXPOST_SUBMIT];

	for (i = 0; i < (int)count; i++) {
		error = brcmf_alloc_ctrlbuf(sc, &sc->rxbuf[i],
		    BRCMF_MSGBUF_MAX_PKT_SIZE, 0x30000 + i);
		if (error != 0)
			return (error);

		error = brcmf_msgbuf_post_rxbuf(sc, &sc->rxbuf[i]);
		if (error != 0)
			return (error);
	}

	brcmf_msgbuf_ring_submit(sc, ring);

	sc->rxbufpost = count;
	device_printf(sc->dev, "posted %u RX data buffers\n", count);
	return (0);
}

/*
 * Repost RX data buffers. Called when firmware consumed all buffers
 * without returning completions (e.g., beacons during scan).
 */
void
brcmf_msgbuf_repost_rxbufs(struct brcmf_softc *sc)
{
	struct brcmf_pcie_ringbuf *ring;
	uint16_t fw_rptr;
	int i, count = 0;

	ring = sc->commonrings[BRCMF_H2D_MSGRING_RXPOST_SUBMIT];
	fw_rptr = brcmf_tcm_read16(sc, ring->r_idx_addr);

	if (fw_rptr != ring->w_ptr)
		return;

	for (i = 0; i < (int)sc->rxbufpost; i++) {
		if (brcmf_msgbuf_post_rxbuf(sc, &sc->rxbuf[i]) != 0)
			break;
		count++;
	}

	if (count > 0) {
		brcmf_msgbuf_ring_submit(sc, ring);
		printf("brcmfmac: reposted %d RX buffers\n", count);
	}
}

/*
 * Send IOCTL request to firmware.
 */
static int
brcmf_msgbuf_tx_ioctl(struct brcmf_softc *sc, uint32_t cmd,
    void *buf, uint32_t len)
{
	struct brcmf_pcie_ringbuf *ring;
	struct msgbuf_ioctl_req_hdr *req;
	uint32_t buflen;

	if (len > BRCMF_MSGBUF_MAX_CTL_PKT_SIZE)
		len = BRCMF_MSGBUF_MAX_CTL_PKT_SIZE;

	ring = sc->commonrings[BRCMF_H2D_MSGRING_CONTROL_SUBMIT];
	req = brcmf_msgbuf_ring_reserve(sc, ring);
	if (req == NULL)
		return (ENOBUFS);

	buflen = len;
	if (buf != NULL && len > 0)
		memcpy(sc->ioctlbuf, buf, len);
	else
		buflen = 0;

	memset(req, 0, sizeof(*req));
	req->msg.msgtype = MSGBUF_TYPE_IOCTLPTR_REQ;
	req->msg.ifidx = 0;
	req->msg.request_id = htole32(BRCMF_IOCTL_REQ_PKTID);
	req->cmd = htole32(cmd);
	req->trans_id = htole16(sc->ioctl_trans_id++);
	req->input_buf_len = htole16(buflen);
	req->output_buf_len = htole16(BRCMF_MSGBUF_MAX_CTL_PKT_SIZE);
	req->req_buf_addr.low_addr = htole32((uint32_t)sc->ioctlbuf_dma);
	req->req_buf_addr.high_addr = htole32((uint32_t)(sc->ioctlbuf_dma >> 32));

	sc->ioctl_completed = 0;
	brcmf_msgbuf_ring_submit(sc, ring);

	return (0);
}

/*
 * Execute IOCTL and wait for response.
 */
int
brcmf_msgbuf_ioctl(struct brcmf_softc *sc, uint32_t cmd,
    void *buf, uint32_t len, uint32_t *resp_len)
{
	int error, timeout;

	error = brcmf_msgbuf_tx_ioctl(sc, cmd, buf, len);
	if (error != 0)
		return (error);

	timeout = BRCMF_IOCTL_TIMEOUT_MS;
	while (!sc->ioctl_completed && timeout > 0) {
		/* Poll D2H rings while waiting */
		brcmf_msgbuf_process_d2h(sc);
		if (sc->ioctl_completed)
			break;
		error = tsleep(&sc->ioctl_completed, PCATCH, "brcmioctl",
		    hz / 10);
		if (error != 0 && error != EWOULDBLOCK)
			return (error);
		timeout -= 100;
	}

	if (!sc->ioctl_completed) {
		device_printf(sc->dev, "IOCTL timeout cmd=0x%x\n", cmd);
		return (ETIMEDOUT);
	}

	if (resp_len != NULL)
		*resp_len = sc->ioctl_resp_len;

	if (sc->ioctl_status != 0)
		return (EIO);

	if (buf != NULL && sc->ioctl_resp_len > 0) {
		if (sc->ioctl_resp_len > len)
			sc->ioctl_resp_len = len;
		memcpy(buf, sc->ioctlbuf, sc->ioctl_resp_len);
	}

	return (0);
}

/*
 * Free control buffers.
 */
static void
brcmf_msgbuf_free_ctrlbufs(struct brcmf_softc *sc)
{
	uint32_t i;

	if (sc->ioctlresp_buf != NULL) {
		for (i = 0; i < BRCMF_MSGBUF_MAX_IOCTLRESPBUF_POST; i++)
			brcmf_free_ctrlbuf(&sc->ioctlresp_buf[i]);
		free(sc->ioctlresp_buf, M_BRCMFMAC);
		sc->ioctlresp_buf = NULL;
	}

	if (sc->event_buf != NULL) {
		for (i = 0; i < BRCMF_MSGBUF_MAX_EVENTBUF_POST; i++)
			brcmf_free_ctrlbuf(&sc->event_buf[i]);
		free(sc->event_buf, M_BRCMFMAC);
		sc->event_buf = NULL;
	}

	if (sc->rxbuf != NULL) {
		for (i = 0; i < sc->rxbufpost; i++)
			brcmf_free_ctrlbuf(&sc->rxbuf[i]);
		free(sc->rxbuf, M_BRCMFMAC);
		sc->rxbuf = NULL;
	}
}

/*
 * Allocate IOCTL buffer.
 */
static int
brcmf_pcie_alloc_ioctlbuf(struct brcmf_softc *sc)
{
	return brcmf_alloc_dma_buf(sc->dev, BRCMF_MSGBUF_MAX_CTL_PKT_SIZE,
	    &sc->ioctlbuf_dma_tag, &sc->ioctlbuf_dma_map,
	    &sc->ioctlbuf, &sc->ioctlbuf_dma);
}

/*
 * Free IOCTL buffer.
 */
static void
brcmf_pcie_free_ioctlbuf(struct brcmf_softc *sc)
{
	brcmf_free_dma_buf(sc->ioctlbuf_dma_tag, sc->ioctlbuf_dma_map,
	    sc->ioctlbuf);
	sc->ioctlbuf_dma_tag = NULL;
	sc->ioctlbuf = NULL;
}

/* Ring descriptor offsets in TCM */
#define BRCMF_RING_MEM_BASE_ADDR_OFFSET	8
#define BRCMF_RING_MAX_ITEM_OFFSET	4
#define BRCMF_RING_LEN_ITEMS_OFFSET	6
#define BRCMF_RING_MEM_SZ		16

/*
 * Allocate and create a flow ring for TX.
 */
int
brcmf_msgbuf_init_flowring(struct brcmf_softc *sc, const uint8_t *da)
{
	struct brcmf_pcie_ringbuf *ring, *ctrl;
	struct msgbuf_flowring_create *create;
	uint16_t flowid;
	uint32_t desc_addr;
	int error, timeout;

	printf("brcmfmac: creating flowring for %02x:%02x:%02x:%02x:%02x:%02x\n",
	    da[0], da[1], da[2], da[3], da[4], da[5]);

	/* Allocate flow ring structure */
	ring = malloc(sizeof(*ring), M_BRCMFMAC, M_NOWAIT | M_ZERO);
	if (ring == NULL)
		return (ENOMEM);

	/* Allocate DMA buffer for the ring */
	error = brcmf_alloc_dma_buf(sc->dev,
	    BRCMF_FLOWRING_SIZE * BRCMF_FLOWRING_ITEM_SIZE,
	    &ring->dma_tag, &ring->dma_map, &ring->buf, &ring->dma_handle);
	if (error != 0) {
		free(ring, M_BRCMFMAC);
		return (error);
	}

	flowid = 0;  /* First flow ring (index into flowring array) */
	ring->id = flowid;
	ring->depth = BRCMF_FLOWRING_SIZE;
	ring->item_len = BRCMF_FLOWRING_ITEM_SIZE;
	ring->w_ptr = 0;
	ring->r_ptr = 0;

	/* Calculate index addresses in TCM (flowrings start after common H2D rings).
	 * TCM index slots are 4 bytes each, though only lower 16 bits used.
	 */
	ring->w_idx_addr = sc->h2d_w_idx_addr +
	    (BRCMF_NROF_H2D_COMMON_MSGRINGS + flowid) * sizeof(uint32_t);
	ring->r_idx_addr = sc->h2d_r_idx_addr +
	    (BRCMF_NROF_H2D_COMMON_MSGRINGS + flowid) * sizeof(uint32_t);

	/* Write ring descriptor to TCM (flowrings start after common rings) */
	desc_addr = sc->ringmem_addr +
	    (BRCMF_NROF_COMMON_MSGRINGS + flowid) * BRCMF_RING_MEM_SZ;
	brcmf_tcm_write16(sc, desc_addr + BRCMF_RING_MAX_ITEM_OFFSET, ring->depth);
	brcmf_tcm_write16(sc, desc_addr + BRCMF_RING_LEN_ITEMS_OFFSET, ring->item_len);
	brcmf_tcm_write32(sc, desc_addr + BRCMF_RING_MEM_BASE_ADDR_OFFSET,
	    (uint32_t)(ring->dma_handle & 0xffffffff));
	brcmf_tcm_write32(sc, desc_addr + BRCMF_RING_MEM_BASE_ADDR_OFFSET + 4,
	    (uint32_t)(ring->dma_handle >> 32));

	sc->flowring = ring;

	printf("brcmfmac: flowring w_idx_addr=0x%x r_idx_addr=0x%x desc_addr=0x%x\n",
	    ring->w_idx_addr, ring->r_idx_addr, desc_addr);
	printf("brcmfmac: flowring dma_handle=0x%llx\n", (unsigned long long)ring->dma_handle);

	/* Send flow ring create request */
	ctrl = sc->commonrings[BRCMF_H2D_MSGRING_CONTROL_SUBMIT];
	create = brcmf_msgbuf_ring_reserve(sc, ctrl);
	if (create == NULL) {
		device_printf(sc->dev, "no space for flowring create\n");
		return (ENOBUFS);
	}

	memset(create, 0, sizeof(*create));
	create->msg.msgtype = MSGBUF_TYPE_FLOW_RING_CREATE;
	create->msg.ifidx = 0;
	create->msg.request_id = htole32(flowid);
	memcpy(create->da, da, 6);
	memcpy(create->sa, sc->macaddr, 6);
	create->tid = 0;
	/* Flow ring ID is flowid + NROF_H2D_COMMON_MSGRINGS */
	create->flow_ring_id = htole16(BRCMF_NROF_H2D_COMMON_MSGRINGS + flowid);
	create->max_items = htole16(BRCMF_FLOWRING_SIZE);
	create->len_item = htole16(BRCMF_FLOWRING_ITEM_SIZE);
	create->flow_ring_addr.low_addr = htole32((uint32_t)ring->dma_handle);
	create->flow_ring_addr.high_addr = htole32((uint32_t)(ring->dma_handle >> 32));

	printf("brcmfmac: flowring create: flowid=%d ring_id=%d depth=%d item_len=%d\n",
	    flowid, BRCMF_NROF_H2D_COMMON_MSGRINGS + flowid, BRCMF_FLOWRING_SIZE,
	    (int)BRCMF_FLOWRING_ITEM_SIZE);

	sc->flowring_create_done = 0;
	brcmf_msgbuf_ring_submit(sc, ctrl);

	/* Wait for flow ring create completion */
	timeout = 1000;
	while (!sc->flowring_create_done && timeout > 0) {
		brcmf_msgbuf_process_d2h(sc);
		if (sc->flowring_create_done)
			break;
		DELAY(1000);
		timeout--;
	}

	if (!sc->flowring_create_done) {
		device_printf(sc->dev, "flowring create timeout\n");
		return (ETIMEDOUT);
	}

	if (sc->flowring_create_status != 0) {
		device_printf(sc->dev, "flowring create failed: %d\n",
		    sc->flowring_create_status);
		return (EIO);
	}

	device_printf(sc->dev, "flowring %d created\n", flowid);
	return (0);
}

/*
 * TX a packet via flow ring.
 */
int
brcmf_msgbuf_tx(struct brcmf_softc *sc, struct mbuf *m)
{
	struct brcmf_pcie_ringbuf *ring;
	struct msgbuf_tx_msghdr *tx;
	struct brcmf_txbuf *txb;
	bus_dma_segment_t seg;
	int error, nsegs;
	uint32_t pktid;
	static int tx_count = 0;

	if (sc->flowring == NULL) {
		if (tx_count++ < 5)
			printf("brcmfmac: TX called but no flowring\n");
		m_freem(m);
		return (ENXIO);
	}

	ring = sc->flowring;

	/* Find a free TX buffer slot */
	pktid = sc->tx_pktid_next;
	if (sc->txbuf[pktid % BRCMF_TX_RING_SIZE].m != NULL) {
		/* Ring full */
		m_freem(m);
		return (ENOBUFS);
	}

	txb = &sc->txbuf[pktid % BRCMF_TX_RING_SIZE];

	/* Create DMA tag/map if not yet done */
	if (txb->dma_tag == NULL) {
		error = bus_dma_tag_create(bus_get_dma_tag(sc->dev),
		    1, 0,
		    BUS_SPACE_MAXADDR,
		    BUS_SPACE_MAXADDR,
		    NULL, NULL,
		    BRCMF_MSGBUF_MAX_PKT_SIZE,
		    1,
		    BRCMF_MSGBUF_MAX_PKT_SIZE,
		    0, NULL, NULL,
		    &txb->dma_tag);
		if (error != 0) {
			m_freem(m);
			return (error);
		}
		error = bus_dmamap_create(txb->dma_tag, 0, &txb->dma_map);
		if (error != 0) {
			bus_dma_tag_destroy(txb->dma_tag);
			txb->dma_tag = NULL;
			m_freem(m);
			return (error);
		}
	}

	/* Make sure mbuf is contiguous */
	m = m_defrag(m, M_NOWAIT);
	if (m == NULL)
		return (ENOMEM);

	/* Map mbuf for DMA */
	error = bus_dmamap_load_mbuf_sg(txb->dma_tag, txb->dma_map, m,
	    &seg, &nsegs, BUS_DMA_NOWAIT);
	if (error != 0 || nsegs != 1) {
		m_freem(m);
		return (error != 0 ? error : EFBIG);
	}

	txb->m = m;
	txb->paddr = seg.ds_addr;

	bus_dmamap_sync(txb->dma_tag, txb->dma_map, BUS_DMASYNC_PREWRITE);

	/* Reserve space in flow ring */
	tx = brcmf_msgbuf_ring_reserve(sc, ring);
	if (tx == NULL) {
		bus_dmamap_unload(txb->dma_tag, txb->dma_map);
		txb->m = NULL;
		m_freem(m);
		return (ENOBUFS);
	}

	memset(tx, 0, sizeof(*tx));
	tx->msg.msgtype = MSGBUF_TYPE_TX_POST;
	tx->msg.ifidx = 0;
	tx->msg.request_id = htole32(0x40000 + (pktid % BRCMF_TX_RING_SIZE));

	/* Copy Ethernet header */
	if (m->m_len >= ETH_HLEN)
		memcpy(tx->txhdr, mtod(m, void *), ETH_HLEN);

	tx->flags = BRCMF_MSGBUF_PKT_FLAGS_FRAME_802_3;
	tx->flags |= (0 & 0x07) << BRCMF_MSGBUF_PKT_FLAGS_PRIO_SHIFT;
	tx->seg_cnt = 1;
	/* DMA address points to data after Ethernet header */
	tx->data_buf_addr.low_addr = htole32((uint32_t)(seg.ds_addr + ETH_HLEN));
	tx->data_buf_addr.high_addr = htole32((uint32_t)((seg.ds_addr + ETH_HLEN) >> 32));
	/* data_len is packet length minus Ethernet header */
	tx->data_len = htole16(m->m_pkthdr.len - ETH_HLEN);

	sc->tx_pktid_next++;

	{
		uint8_t *eh = tx->txhdr;
		static int tx_dbg = 0;
		if (tx_dbg < 5) {
			printf("brcmfmac: TX hdr dst=%02x:%02x:%02x:%02x:%02x:%02x "
			    "src=%02x:%02x:%02x:%02x:%02x:%02x type=%02x%02x len=%d\n",
			    eh[0],eh[1],eh[2],eh[3],eh[4],eh[5],
			    eh[6],eh[7],eh[8],eh[9],eh[10],eh[11],
			    eh[12],eh[13], m->m_pkthdr.len);
			tx_dbg++;
		}
	}
	printf("brcmfmac: TX submit pktid=0x%x len=%d data_len=%d dma=0x%llx w_ptr=%d\n",
	    0x40000 + (pktid % BRCMF_TX_RING_SIZE),
	    m->m_pkthdr.len, m->m_pkthdr.len - ETH_HLEN,
	    (unsigned long long)(seg.ds_addr + ETH_HLEN), ring->w_ptr);

	brcmf_msgbuf_ring_submit(sc, ring);

	/* Check if firmware read from flowring */
	{
		uint16_t r_ptr = brcmf_tcm_read16(sc, ring->r_idx_addr);
		printf("brcmfmac: flowring after submit: w=%d r=%d\n", ring->w_ptr, r_ptr);
	}

	return (0);
}

/*
 * Initialize msgbuf protocol.
 */
int
brcmf_msgbuf_init(struct brcmf_softc *sc)
{
	int error;

	error = brcmf_pcie_alloc_ioctlbuf(sc);
	if (error != 0) {
		device_printf(sc->dev, "failed to allocate IOCTL buffer\n");
		return (error);
	}



	error = brcmf_msgbuf_init_ioctlresp(sc);
	if (error != 0) {
		device_printf(sc->dev,
		    "failed to post IOCTL response buffers\n");
		return (error);
	}

	error = brcmf_msgbuf_init_event(sc);
	if (error != 0) {
		device_printf(sc->dev, "failed to post event buffers\n");
		return (error);
	}

	error = brcmf_msgbuf_init_rxbuf(sc);
	if (error != 0) {
		device_printf(sc->dev, "failed to post RX buffers\n");
		return (error);
	}

	return (0);
}

/*
 * Cleanup msgbuf protocol.
 */
void
brcmf_msgbuf_cleanup(struct brcmf_softc *sc)
{
	brcmf_msgbuf_free_ctrlbufs(sc);
	brcmf_pcie_free_ioctlbuf(sc);
}
