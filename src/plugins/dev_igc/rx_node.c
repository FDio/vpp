/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <dev_igc/igc.h>
#include <vnet/ethernet/ethernet.h>

VNET_DEV_NODE_FN (igc_rx_node_fn)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  foreach_vnet_dev_rx_queue_runtime (rxq, node)
    {
      igc_rxq_t *iq = vnet_dev_get_rx_queue_data (rxq);
      igc_rx_desc_t *d = iq->descs + iq->head;

      if (d->hdr_addr)
	{
	  vlib_buffer_t *b =
	    vlib_get_buffer (vm, iq->buffer_indices[iq->head]);
	  fformat (
	    stderr,
	    "%s: queue_id %u head %u tail %u rss_type %u "
	    "packet_type %u pkt_len %u status %x err %x sph %u hdr_len %u\n",
	    __func__, rxq->queue_id, iq->head, iq->tail, d->rss_type,
	    d->packet_type, d->pkt_len, d->ext_status, d->ext_error, d->sph,
	    d->hdr_len_lo | d->hdr_len_hi << 10);
	  fformat (stderr, "%U\n", format_hexdump, b->data, d->pkt_len);
	  iq->head++;
	}
    }
  return 0;
}
