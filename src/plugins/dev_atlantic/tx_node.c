/* SPDX-License-Identifier: Apache-2.0 */
#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <dev_atlantic/atlantic.h>

VNET_DEV_NODE_FN (atl_tx_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  vnet_dev_tx_node_runtime_t *rt = vnet_dev_get_tx_node_runtime (node);
  vnet_dev_tx_queue_t *txq = rt->tx_queue;
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_pkts = frame->n_vectors;

  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
    {
      for (u32 i = 0; i < n_pkts; i++)
	{
	  vlib_buffer_t *b = vlib_get_buffer (vm, from[i]);
	  if (vlib_trace_buffer (vm, node, VNET_INTERFACE_OUTPUT_NEXT_DROP, b,
				 0))
	    {
	      atl_tx_trace_t *t = vlib_add_trace (vm, node, b, sizeof (*t));
	      t->buffer_index = from[i];
	      t->sw_if_index = vnet_buffer (b)->sw_if_index[VLIB_TX];
	      t->queue_id = txq ? txq->queue_id : 0;
	    }
	}
    }

  vlib_buffer_free (vm, from, n_pkts);
  return n_pkts;
}
