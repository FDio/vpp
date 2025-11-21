/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Damjan Marion
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <dev_atlantic/atlantic.h>

VNET_DEV_NODE_FN (atl_rx_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  vnet_dev_rx_node_runtime_t *rtd = vnet_dev_get_rx_node_runtime (node);
  vnet_dev_rx_queue_t *rxq = rtd->first_rx_queue;
  atl_rxq_t *aq = vnet_dev_get_rx_queue_data (rxq);
  atl_rx_desc_t *d = aq->descs + aq->next_index;
  u32 n_desc = 0;

  while ((d->status & 1) && n_desc < VLIB_FRAME_SIZE) /* DD bit set */
    {
      fformat (stderr, "RX desc: %U\n", format_atl_rx_desc, d, 0);
      d->status = 0; /* clear DD bit for next use (simulated) */

      /* Move to next descriptor */
      aq->next_index++;
      if (aq->next_index >= rxq->size)
	aq->next_index = 0;
      d = aq->descs + aq->next_index;
      n_desc++;
    }

  return n_desc;
}
