/* Message buffer protocol: ring operations, D2H processing, IOCTL handling */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bus.h>
#include <sys/kernel.h>
#include <sys/malloc.h>

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
#define MSGBUF_TYPE_RXBUF_POST		 0x11

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
	uint16_t avail;

	ring = sc->commonrings[BRCMF_D2H_MSGRING_TX_COMPLETE];

	brcmf_ring_read_wptr(sc, ring);

	if (ring->w_ptr >= ring->r_ptr)
		avail = ring->w_ptr - ring->r_ptr;
	else
		avail = ring->depth - ring->r_ptr;

	if (avail == 0)
		return;

	/* TODO: process TX completions, free TX buffers */
	ring->r_ptr = ring->w_ptr;
	brcmf_ring_write_rptr(sc, ring);
}

/*
 * Process RX complete ring.
 */
static void
brcmf_msgbuf_process_rx_complete(struct brcmf_softc *sc)
{
	struct brcmf_pcie_ringbuf *ring;
	uint16_t avail;

	ring = sc->commonrings[BRCMF_D2H_MSGRING_RX_COMPLETE];

	brcmf_ring_read_wptr(sc, ring);

	if (ring->w_ptr >= ring->r_ptr)
		avail = ring->w_ptr - ring->r_ptr;
	else
		avail = ring->depth - ring->r_ptr;

	if (avail == 0)
		return;

	/* TODO: process RX completions, deliver packets */
	ring->r_ptr = ring->w_ptr;
	brcmf_ring_write_rptr(sc, ring);
}

/*
 * Process D2H completion rings.
 */
void
brcmf_msgbuf_process_d2h(struct brcmf_softc *sc)
{
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
