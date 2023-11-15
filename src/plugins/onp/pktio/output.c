/*
 * Copyright (c) 2021 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

/**
 * @file
 * @brief ONP pktio/device output node implementation.
 */

#include <onp/onp.h>

#define foreach_onp_tx_func_error                                             \
  _ (BAD_PARAM, "Invalid parameters")                                         \
  _ (TX_BURST, "TX failed due to insufficient descriptors")

typedef enum
{
#define _(f, s) ONP_TX_FUNC_ERROR_##f,
  foreach_onp_tx_func_error
#undef _
    ONP_TX_FUNC_N_ERROR,
} onp_tx_func_error_t;

static char *onp_tx_func_error_strings[] = {
#define _(n, s) s,
  foreach_onp_tx_func_error
#undef _
};

static void
onp_pktio_intf_counters_clear (u32 instance)
{
  vlib_main_t *vm = vlib_get_main ();
  onp_main_t *om = onp_get_main ();
  onp_pktio_t *op;
  int i, rv;

  op = pool_elt_at_index (om->onp_pktios, instance);

  if (cnxk_drv_pktio_stats_clear (vm, op->cnxk_pktio_index) < 0)
    onp_pktio_warn ("Failed to clear pktio(%d) stats", op->cnxk_pktio_index);

  for (i = 0; i < op->n_rx_q; i++)
    {
      rv = cnxk_drv_pktio_queue_stats_clear (vm, op->cnxk_pktio_index, i, 1);
      if (rv < 0)
	onp_pktio_warn ("Failed to clear pktio(%d) RX queue(%d) stats",
			op->cnxk_pktio_index, i);
    }

  for (i = 0; i < op->n_tx_q; i++)
    {
      rv = cnxk_drv_pktio_queue_stats_clear (vm, op->cnxk_pktio_index, i, 0);
      if (rv < 0)
	onp_pktio_warn ("Failed to clear pktio(%d) TX queue(%d) stats",
			op->cnxk_pktio_index, i);
    }
}

static_always_inline void
onp_pktio_tx_pkts_trace (vlib_main_t *vm, vlib_node_runtime_t *node,
			 vlib_frame_t *frame, vlib_buffer_t **b, u32 n_left,
			 u8 qid)
{
  onp_tx_trace_t *trace0;

  while (n_left)
    {
      if (b[0]->flags & VLIB_BUFFER_IS_TRACED)
	{
	  trace0 = vlib_add_trace (vm, node, b[0], sizeof (*trace0));
	  trace0->buffer_index = vlib_get_buffer_index (vm, b[0]);
	  trace0->qid = qid;
	  clib_memcpy_fast (&trace0->buf, b[0],
			    sizeof b[0][0] - sizeof b[0]->pre_data);
	  clib_memcpy_fast (trace0->data, vlib_buffer_get_current (b[0]), 256);
	}
      n_left -= 1;
      b += 1;
    }
}

static clib_error_t *
onp_pktio_intf_admin_up_down (vnet_main_t *vnm, u32 hw_if_index, u32 flags)
{
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_index);
  onp_main_t *om = onp_get_main ();
  onp_pktio_t *od = vec_elt_at_index (om->onp_pktios, hi->dev_instance);
  uword is_up = (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) != 0;
  vlib_main_t *vm = vlib_get_main ();

  if (od->pktio_flags & ONP_DEVICE_F_ERROR)
    return clib_error_return (0, "Invalid (error) device state");

  if (is_up)
    {
      vnet_hw_interface_set_flags (vnm, od->hw_if_index,
				   VNET_HW_INTERFACE_FLAG_LINK_UP);
      od->pktio_flags |= ONP_DEVICE_F_ADMIN_UP;
      if (cnxk_drv_pktio_start (vm, od->cnxk_pktio_index) < 0)
	return clib_error_return (0, "device start failed");
    }
  else
    {
      if (cnxk_drv_pktio_stop (vm, od->cnxk_pktio_index) < 0)
	return clib_error_return (0, "device stop failed");
      vnet_hw_interface_set_flags (vnm, od->hw_if_index, 0);
      od->pktio_flags &= ~ONP_DEVICE_F_ADMIN_UP;
    }
  return 0;
}

static clib_error_t *
onp_pktio_subif_add_del (vnet_main_t *vnm, u32 hw_if_index,
			 struct vnet_sw_interface_t *st, int is_add)
{
  clib_error_t *error = NULL;
  ASSERT (0);

  return error;
}

static void
onp_pktio_intf_next_node_set (vnet_main_t *vnm, u32 hw_if_index,
			      u32 node_index)
{
  onp_main_t *om = onp_get_main ();
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
  onp_pktio_t *od = vec_elt_at_index (om->onp_pktios, hw->dev_instance);

  if (node_index == ~0)
    {
      od->per_interface_next_index = node_index;
      return;
    }
}

static clib_error_t *
onp_pktio_mac_addr_add_del (vnet_hw_interface_t *hi, const u8 *addr, u8 is_add)
{
  onp_main_t *om = onp_get_main ();
  onp_pktio_t *od = vec_elt_at_index (om->onp_pktios, hi->dev_instance);
  int rv;

  rv = cnxk_drv_pktio_mac_addr_add (vlib_get_main (), od->cnxk_pktio_index,
				    (char *) addr);
  if (rv < 0)
    onp_pktio_notice ("mac address add failed");

  return NULL;
}

static clib_error_t *
onp_pktio_mac_addr_set (vnet_hw_interface_t *hi, const u8 *old_addr,
			const u8 *addr)
{
  onp_main_t *om = onp_get_main ();
  onp_pktio_t *od = vec_elt_at_index (om->onp_pktios, hi->dev_instance);
  int rv;

  rv = cnxk_drv_pktio_mac_addr_set (vlib_get_main (), od->cnxk_pktio_index,
				    (char *) addr);
  if (rv < 0)
    onp_pktio_notice ("mac address set failed");

  return NULL;
}

/**
 * @brief ONP output node.
 * @node onp-output.
 *
 * ONP output node - Transmit packets using device tx queues.
 *
 * @param vm       vlib_main_t corresponding to the current thread.
 * @param node     vlib_node_runtime_t.
 * @param frame    vlib_frame_t.
 */
/* clang-format off */
VNET_DEVICE_CLASS_TX_FN (onp_pktio_device_class) (vlib_main_t *vm,
					   vlib_node_runtime_t *node,
					   vlib_frame_t *frame)
{
  vnet_interface_output_runtime_t *rd = (void *) node->runtime_data;
  onp_pktio_t *od = onp_get_pktio (rd->dev_instance);
  u32 n_left, n_sent, *from, queue;
  onp_main_t *om = onp_get_main ();
  cnxk_per_thread_data_t *ptd;

  ptd = vec_elt_at_index (om->onp_per_thread_data, vm->thread_index);

  from = vlib_frame_vector_args (frame);
  n_left = frame->n_vectors;

  vlib_get_buffers (vm, from, ptd->buffers, n_left);
  ptd->pktio_index = od->cnxk_pktio_index;
  queue = vm->thread_index % od->n_tx_q;

      if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
	  onp_pktio_tx_pkts_trace (vm, node, frame, ptd->buffers, n_left, queue);

      n_sent = od->onp_pktio_txqs[queue].pktio_send_func (vm, node, queue,
							  n_left, ptd);

  if (PREDICT_FALSE (n_sent != n_left))
    {
      u32 n_failed = n_left - n_sent;
      vlib_error_count (vm, node->node_index, ONP_TX_FUNC_ERROR_TX_BURST,
			n_failed);
      return 0;
    }

  return n_sent;
}
/* clang-format on */

VNET_DEVICE_CLASS (onp_pktio_device_class) = {
  .name = "onp",
  .tx_function_n_errors = ONP_TX_FUNC_N_ERROR,
  .tx_function_error_strings = onp_tx_func_error_strings,
  .format_device_name = format_onp_pktio_name,
  .format_device = format_onp_pktio,
  .format_tx_trace = format_onp_pktio_tx_trace,
  .clear_counters = onp_pktio_intf_counters_clear,
  .admin_up_down_function = onp_pktio_intf_admin_up_down,
  .subif_add_del_function = onp_pktio_subif_add_del,
  .rx_redirect_to_node = onp_pktio_intf_next_node_set,
  .mac_addr_change_function = onp_pktio_mac_addr_set,
  .mac_addr_add_del_function = onp_pktio_mac_addr_add_del,
  .format_flow = format_onp_pktio_flow,
  .flow_ops_function = onp_pktio_flow_ops,
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
