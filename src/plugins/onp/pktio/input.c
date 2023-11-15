/*
 * Copyright (c) 2021 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

/**
 * @file
 * @brief ONP pktio input node implementation.
 */

#include <onp/onp.h>
#include <onp/input.h>
#include <onp/drv/inc/pktio_fp_defs.h>
#include <onp/drv/inc/pool_fp.h>
#include <vnet/interface/rx_queue_funcs.h>

/* clang-format off */
static char *onp_pktio_input_error_strings[] = {
#define _(sym, str) str,
  foreach_onp_pktio_input_error
#undef _
};
/* clang-format on */

static_always_inline u32
onp_pktio_input_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
			cnxk_per_thread_data_t *ptd, onp_pktio_t *op, u16 qid,
			u8 is_trace_enable)
{
  u32 next_index = VNET_DEVICE_INPUT_NEXT_ETHERNET_INPUT;
  u32 *n_bytes = &ptd->out_user_nstats;
  u32 sw_if_index = op->sw_if_index;
  u32 n_rx_packets = 0, burst_size;
  vlib_buffer_t *bt;
  int n_trace;

  ptd->pktio_index = op->cnxk_pktio_index;

  bt = &ptd->buffer_template;
  vnet_buffer (bt)->sw_if_index[VLIB_RX] = op->sw_if_index;
  onp_update_bt_fields (node, bt, ONP_PKTIO_INPUT_ERROR_NONE);

  if (PREDICT_FALSE (vnet_device_input_have_features (op->sw_if_index)))
    vnet_feature_start_device_input (op->sw_if_index, &next_index,
				     &ptd->buffer_template);
  burst_size = op->onp_pktio_rxqs[qid].req_burst_size;

  if (PREDICT_TRUE (!is_trace_enable))
    n_rx_packets +=
      op->onp_pktio_rxqs[qid].pktio_recv_func (vm, node, qid, burst_size, ptd);
  else
    n_rx_packets += op->onp_pktio_rxqs[qid].pktio_recv_func_with_trace (
      vm, node, qid, burst_size, ptd);

  if (PREDICT_FALSE (!n_rx_packets))
    return 0;

  vlib_get_buffer_indices_with_offset (vm, (void **) ptd->buffers,
				       ptd->buffer_indices, n_rx_packets, 0);
  vlib_buffer_enqueue_to_single_next (vm, node, ptd->buffer_indices,
				      next_index, n_rx_packets);

  if (PREDICT_TRUE (next_index == VNET_DEVICE_INPUT_NEXT_ETHERNET_INPUT))
    onp_prepare_next_eth_input_frame (vm, node, op, ptd, next_index, 1);

  if (PREDICT_FALSE (is_trace_enable &&
		     (n_trace = vlib_get_trace_count (vm, node))))
    {
      i32 n_left = n_rx_packets;
      vlib_buffer_t **bufs;
      u32 count = 0;

      while (n_trace && (n_left > 0))
	{
	  bufs = ptd->buffers;
#if CLIB_DEBUG > 0
	  if (vlib_trace_buffer (vm, node, next_index, bufs[count], 1))
#else
	  if (vlib_trace_buffer (vm, node, next_index, bufs[count], 0))
#endif
	    {
	      onp_rx_trace_t *t0 =
		vlib_add_trace (vm, node, bufs[count], sizeof t0[0]);
	      t0->buffer_index = vlib_get_buffer_index (vm, bufs[count]);
	      t0->pktio_index = op->cnxk_pktio_index;
	      t0->next_node_index = next_index, t0->queue_index = qid;
	      clib_memcpy_fast (t0->driver_data, bufs[count]->pre_data, 64);
	      clib_memcpy_fast (&t0->buffer, bufs[count],
				sizeof (vlib_buffer_t));
	      clib_memcpy_fast (t0->data, bufs[count]->data, sizeof t0->data);
	      n_trace--;
	    }
	  count++;
	  n_left--;
	}
      vlib_set_trace_count (vm, node, n_trace);
    }

  vlib_increment_combined_counter (
    vnet_get_main ()->interface_main.combined_sw_if_counters +
      VNET_INTERFACE_COUNTER_RX,
    vm->thread_index, sw_if_index, n_rx_packets, *n_bytes);

  vnet_device_increment_rx_packets (vm->thread_index, n_rx_packets);

  return n_rx_packets;
}

/**
 * @brief ONP PKTIO input node.
 * @node onp-pktio-input
 *
 * This is the main onp input node.
 *
 * @param vm   vlib_main_t corresponding to the current thread.
 * @param node vlib_node_runtime_t.
 * @param f    vlib_frame_t input-node, not used.
 *
 * @em Sets:
 * - <code>b->error</code> if the packet is to be dropped immediately
 * - <code>b->current_data, b->current_length</code>
 * - <code>vnet_buffer(b)->sw_if_index[VLIB_RX]</code>
 *     - rx interface sw_if_index
 * - <code>vnet_buffer(b)->sw_if_index[VLIB_TX] = ~0</code>
 *     - required by ipX-lookup
 * - <code>b->flags</code>
 *
 * <em>Next Nodes:</em>
 * - Static arcs to: error-drop, ethernet-input, ip4-input,
 *   ip4-input-no-checksum, ip6-input,
 * - per-interface redirection, controlled by
 *   <code>od->per_interface_next_index</code>
 */
/* clang-format off */
VLIB_NODE_FN (onp_pktio_input_node) (vlib_main_t *vm,
				     vlib_node_runtime_t *node,
				     vlib_frame_t *f)
{
  vnet_hw_if_rxq_poll_vector_t *pv;
  cnxk_per_thread_data_t *ptd;
  onp_main_t *om = onp_get_main ();
  u32 n_rx_packets = 0, is_trace_enabled;
  onp_pktio_t *od;
  /* Single numa node */
  u32 numa_node = 0;
  u8 default_bp_index = vlib_buffer_pool_get_default_for_numa (vm, numa_node);

  is_trace_enabled = vlib_get_trace_count (vm, node);
  ptd = vec_elt_at_index (om->onp_per_thread_data, vm->thread_index);

  cnxk_pktpools_deplete_to_vlib (vm, node, ptd, 0, 0);

  /* Refill default buffer pool */
  cnxk_pktpool_refill_single_aura (vm, node, default_bp_index, ptd,
		  CNXK_POOL_MAX_REFILL_DEPLTE_COUNT);

  if (!(ptd->pktio_node_state))
    return 0;

  pv = vnet_hw_if_get_rxq_poll_vector (vm, node);

  if (PREDICT_TRUE (!(is_trace_enabled)))
    {

      for (int i = 0; i < vec_len (pv); i++)
	{
	  od = onp_get_pktio (pv[i].dev_instance);

	  if ((od->pktio_flags & ONP_DEVICE_F_ADMIN_UP) == 0)
	    continue;

	  n_rx_packets +=
	    onp_pktio_input_inline (vm, node, ptd, od, pv[i].queue_id, 0);
	}
    }
  else
    {
      for (int i = 0; i < vec_len (pv); i++)
	{
	  od = onp_get_pktio (pv[i].dev_instance);

	  if ((od->pktio_flags & ONP_DEVICE_F_ADMIN_UP) == 0)
	    continue;

	  n_rx_packets +=
	    onp_pktio_input_inline (vm, node, ptd, od, pv[i].queue_id, 1);
	}
    }

  return n_rx_packets;
}
/* clang-format on */

VLIB_REGISTER_NODE (onp_pktio_input_node) = {
  .type = VLIB_NODE_TYPE_INPUT,
  .name = "onp-pktio-input",
  .sibling_of = "device-input",
  .flags = VLIB_NODE_FLAG_TRACE_SUPPORTED,
  .state = VLIB_NODE_STATE_DISABLED,
  .format_buffer = format_ethernet_header_with_length,
  .format_trace = format_onp_pktio_rx_trace,
  .n_errors = ARRAY_LEN (onp_pktio_input_error_strings),
  .error_strings = onp_pktio_input_error_strings,
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
