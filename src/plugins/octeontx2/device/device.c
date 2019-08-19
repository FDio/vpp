/*
 * Copyright (c) 2017-2019 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* Copyright (c) 2019 Marvell International Ltd. */

#include <vnet/vnet.h>
#include <vppinfra/vec.h>
#include <vppinfra/format.h>
#include <vlib/unix/cj.h>
#include <assert.h>

#include <vnet/ethernet/ethernet.h>
#include <vppinfra/error.h>

#include <octeontx2/buffer.h>
#include <octeontx2/device/octeontx2.h>
#include <octeontx2/device/otx2_priv.h>
#include <octeontx2/device/mempool.h>

#define foreach_otx2_tx_func_error			\
  _(BAD_RETVAL, "DPDK tx function returned an error")	\
  _(PKT_DROP, "Tx packet drops (octeontx2 tx failure)")

typedef enum
{
#define _(f,s) OTX2_TX_FUNC_ERROR_##f,
  foreach_otx2_tx_func_error
#undef _
    OTX2_TX_FUNC_N_ERROR,
} otx2_tx_func_error_t;

static char *otx2_tx_func_error_strings[] = {
#define _(n,s) s,
  foreach_otx2_tx_func_error
#undef _
};

static clib_error_t *
otx2_set_mac_address (vnet_hw_interface_t * hi,
		      const u8 * old_address, const u8 * address)
{
  int error;
  otx2_main_t *dm = &otx2_main;
  otx2_device_t *xd = vec_elt_at_index (dm->devices, hi->dev_instance);

  error = rte_eth_dev_default_mac_addr_set (xd->port_id,
					    (struct rte_ether_addr *)
					    address);

  if (error)
    {
      return clib_error_return (0, "mac address set failed: %d", error);
    }
  else
    {
      vec_reset_length (xd->default_mac_address);
      vec_add (xd->default_mac_address, address, sizeof (address));
      return NULL;
    }
}

static void
otx2_tx_trace_buffer (otx2_main_t * dm, vlib_node_runtime_t * node,
		      otx2_device_t * xd, u16 queue_id,
		      vlib_buffer_t * buffer)
{
  vlib_main_t *vm = vlib_get_main ();
  otx2_tx_trace_t *trace;

  trace = vlib_add_trace (vm, node, buffer, sizeof (trace[0]));
  trace->queue_index = queue_id;
  trace->device_index = xd->device_index;
  trace->buffer_index = vlib_get_buffer_index (vm, buffer);

  clib_memcpy_fast (&trace->buffer, buffer,
		    sizeof (buffer[0]) - sizeof (buffer->pre_data));
  clib_memcpy_fast (trace->buffer.pre_data,
		    buffer->data + buffer->current_data,
		    sizeof (trace->buffer.pre_data));
  clib_memcpy_fast (trace->data, buffer->data, sizeof (trace->data));
}

/*
 * This function calls the dpdk's tx_burst function to transmit the packets.
 */
static_always_inline u32
tx_burst_vector_internal (vlib_main_t * vm,
			  otx2_device_t * xd,
			  vlib_buffer_t ** ppb, u32 n_left)
{
  otx2_main_t *dm = &otx2_main;
  int n_sent = 0;
  int queue_id;

  queue_id = vm->thread_index;

  {
    if (PREDICT_TRUE (xd->flags & OTX2_DEVICE_FLAG_PMD))
      {
	/* no wrap, transmit in one burst */
	n_sent =
	  rte_eth_tx_burst (xd->port_id, queue_id, (struct rte_mbuf **) ppb,
			    n_left);
      }
    else
      {
	ASSERT (0);
	n_sent = 0;
      }

    if (PREDICT_FALSE (n_sent < 0))
      {
	// emit non-fatal message, bump counter
	vnet_main_t *vnm = dm->vnet_main;
	vnet_interface_main_t *im = &vnm->interface_main;
	u32 node_index;

	node_index = vec_elt_at_index (im->hw_interfaces,
				       xd->hw_if_index)->tx_node_index;

	vlib_error_count (vm, node_index, OTX2_TX_FUNC_ERROR_BAD_RETVAL, 1);
	clib_warning ("rte_eth_tx_burst[%d]: error %d", xd->port_id, n_sent);
	return n_left;		// untransmitted packets
      }
    n_left -= n_sent;
    ppb += n_sent;
  }

  return n_left;
}

/*
 * Transmits the packets on the frame to the interface associated with the
 * node. It first copies packets on the frame to a per-thread arrays
 */
VNET_DEVICE_CLASS_TX_FN (otx2_device_class) (vlib_main_t * vm,
					     vlib_node_runtime_t * node,
					     vlib_frame_t * f)
{
  otx2_main_t *dm = &otx2_main;
  vnet_interface_output_runtime_t *rd = (void *) node->runtime_data;
  otx2_device_t *xd = vec_elt_at_index (dm->devices, rd->dev_instance);
  u32 thread_index = vm->thread_index;
  u32 n_packets = f->n_vectors;
  int queue_id = thread_index;
  vlib_buffer_t **b;
  u32 tx_pkts;
  i32 n_left;

  otx2_per_thread_data_t *ptd = vec_elt_at_index (dm->per_thread_data,
						  thread_index);

  vlib_get_buffers_with_offset (vm, vlib_frame_vector_args (f),
				(void **) ptd->vbufs, n_packets, -(i32) (0));

  b = ptd->vbufs;

  /*Loop through packets only for trace enable */
  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
    {
      n_left = n_packets;
      while (n_left > 0)
	{
	  if (b[0]->flags & VLIB_BUFFER_IS_TRACED)
	    otx2_tx_trace_buffer (dm, node, xd, queue_id, b[0]);
	  b++;
	  n_left--;
	}
    }

  /* transmit as many packets as possible */
  tx_pkts = n_packets;

  ptd->tx_not_freed = 0;

  /*rte_eth_tx_burst does following
   * Sets ptd->tx_not_freed which indicates number of buffers not freed due to (b->refcnt>1)
   * Send all vlib buffers;
   */
  n_left = tx_burst_vector_internal (vm, xd, ptd->vbufs, n_packets);

  /*Freed packets = Tx total pkts - (not transferref) - (nbuffers having b->refcnt >1) */
  ptd->n_buffers_to_free -= (tx_pkts - n_left - ptd->tx_not_freed);

  {
    /* If n_left free buffers back to pool */
    if (PREDICT_FALSE (n_left > 0))
      {
	tx_pkts -= n_left;
	vlib_simple_counter_main_t *cm;
	vnet_main_t *vnm = vnet_get_main ();

	cm = vec_elt_at_index (vnm->interface_main.sw_if_counters,
			       VNET_INTERFACE_COUNTER_TX_ERROR);

	vlib_increment_simple_counter (cm, thread_index, xd->sw_if_index,
				       n_left);

	vlib_error_count (vm, node->node_index, OTX2_TX_FUNC_ERROR_PKT_DROP,
			  n_left);
	vec_reset_length (ptd->buffers);
	vlib_get_buffer_indices_with_offset (vm,
					     (void **)
					     &(ptd->vbufs
					       [n_packets - n_left]),
					     ptd->buffers, n_left, 0);
	vlib_buffer_free (vm, ptd->buffers, n_left);
      }
    vec_reset_length (ptd->buffers);
    /*take back buffers */
    if (ptd->n_buffers_to_free < -(OTX2_RX_BURST_SZ))
      {
	n_left = otx2_mempool_deplete (vm, ptd->buffer_pool_index,
				       OTX2_RX_BURST_SZ,
				       ptd->buffers, (void **) ptd->vbufs);
	ptd->n_buffers_to_free += n_left;
	vec_reset_length (ptd->buffers);
      }
  }

  return tx_pkts;

}

static void
otx2_clear_hw_interface_counters (u32 instance)
{
  otx2_main_t *dm = &otx2_main;
  otx2_device_t *xd = vec_elt_at_index (dm->devices, instance);

  rte_eth_stats_reset (xd->port_id);
  rte_eth_xstats_reset (xd->port_id);
}

static clib_error_t *
otx2_interface_admin_up_down (vnet_main_t * vnm, u32 hw_if_index, u32 flags)
{
  vnet_hw_interface_t *hif = vnet_get_hw_interface (vnm, hw_if_index);
  uword is_up = (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) != 0;
  otx2_main_t *dm = &otx2_main;
  otx2_device_t *xd = vec_elt_at_index (dm->devices, hif->dev_instance);

  if (xd->flags & OTX2_DEVICE_FLAG_PMD_INIT_FAIL)
    return clib_error_return (0, "Interface not initialized");

  if (is_up)
    {
      if ((xd->flags & OTX2_DEVICE_FLAG_ADMIN_UP) == 0)
	otx2_device_start (xd);
      xd->flags |= OTX2_DEVICE_FLAG_ADMIN_UP;
      f64 now = vlib_time_now (dm->vlib_main);
      otx2_update_counters (xd, now);
      otx2_update_link_state (xd, now);
    }
  else
    {
      vnet_hw_interface_set_flags (vnm, xd->hw_if_index, 0);
      if ((xd->flags & OTX2_DEVICE_FLAG_ADMIN_UP) != 0)
	otx2_device_stop (xd);
      xd->flags &= ~OTX2_DEVICE_FLAG_ADMIN_UP;
    }

  return /* no error */ 0;
}

/*
 * Dynamically redirect all pkts from a specific interface
 * to the specified node
 */
static void
otx2_set_interface_next_node (vnet_main_t * vnm, u32 hw_if_index,
			      u32 node_index)
{
  otx2_main_t *xm = &otx2_main;
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
  otx2_device_t *xd = vec_elt_at_index (xm->devices, hw->dev_instance);

  /* Shut off redirection */
  if (node_index == ~0)
    {
      xd->per_interface_next_index = node_index;
      return;
    }

  xd->per_interface_next_index =
    vlib_node_add_next (xm->vlib_main, otx2_input_node.index, node_index);
}


static clib_error_t *
otx2_subif_add_del_function (vnet_main_t * vnm,
			     u32 hw_if_index,
			     struct vnet_sw_interface_t *st, int is_add)
{
  otx2_main_t *xm = &otx2_main;
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
  otx2_device_t *xd = vec_elt_at_index (xm->devices, hw->dev_instance);
  vnet_sw_interface_t *t = (vnet_sw_interface_t *) st;
  int r, vlan_offload;
  u32 prev_subifs = xd->num_subifs;
  clib_error_t *err = 0;

  if (is_add)
    xd->num_subifs++;
  else if (xd->num_subifs)
    xd->num_subifs--;

  if ((xd->flags & OTX2_DEVICE_FLAG_PMD) == 0)
    goto done;

  if (t->sub.eth.flags.no_tags == 1)
    goto done;

  if ((t->sub.eth.flags.one_tag != 1) || (t->sub.eth.flags.exact_match != 1))
    {
      xd->num_subifs = prev_subifs;
      err = clib_error_return (0, "unsupported VLAN setup");
      goto done;
    }

  vlan_offload = rte_eth_dev_get_vlan_offload (xd->port_id);
  vlan_offload |= ETH_VLAN_FILTER_OFFLOAD;

  if ((r = rte_eth_dev_set_vlan_offload (xd->port_id, vlan_offload)))
    {
      xd->num_subifs = prev_subifs;
      err = clib_error_return (0, "rte_eth_dev_set_vlan_offload[%d]: err %d",
			       xd->port_id, r);
      goto done;
    }


  if ((r =
       rte_eth_dev_vlan_filter (xd->port_id,
				t->sub.eth.outer_vlan_id, is_add)))
    {
      xd->num_subifs = prev_subifs;
      err = clib_error_return (0, "rte_eth_dev_vlan_filter[%d]: err %d",
			       xd->port_id, r);
      goto done;
    }

done:
  if (xd->num_subifs)
    xd->flags |= OTX2_DEVICE_FLAG_HAVE_SUBIF;
  else
    xd->flags &= ~OTX2_DEVICE_FLAG_HAVE_SUBIF;

  return err;
}

/* *INDENT-OFF* */
VNET_DEVICE_CLASS (otx2_device_class) = {
  .name = "otx2",
  .tx_function_n_errors = OTX2_TX_FUNC_N_ERROR,
  .tx_function_error_strings = otx2_tx_func_error_strings,
  .format_device_name = format_otx2_device_name,
  .format_device = format_otx2_device,
  .format_tx_trace = format_otx2_tx_trace,
  .clear_counters = otx2_clear_hw_interface_counters,
  .admin_up_down_function = otx2_interface_admin_up_down,
  .subif_add_del_function = otx2_subif_add_del_function,
  .rx_redirect_to_node = otx2_set_interface_next_node,
  .mac_addr_change_function = otx2_set_mac_address,
};
/* *INDENT-ON* */

#define UP_DOWN_FLAG_EVENT 1

static uword
admin_up_down_process (vlib_main_t * vm,
		       vlib_node_runtime_t * rt, vlib_frame_t * f)
{
  clib_error_t *error = 0;
  uword event_type;
  uword *event_data = 0;
  u32 sw_if_index;
  u32 flags;

  while (1)
    {
      vlib_process_wait_for_event (vm);

      event_type = vlib_process_get_events (vm, &event_data);

      otx2_main.admin_up_down_in_progress = 1;

      switch (event_type)
	{
	case UP_DOWN_FLAG_EVENT:
	  {
	    if (vec_len (event_data) == 2)
	      {
		sw_if_index = event_data[0];
		flags = event_data[1];
		error =
		  vnet_sw_interface_set_flags (vnet_get_main (), sw_if_index,
					       flags);
		clib_error_report (error);
	      }
	  }
	  break;
	}

      vec_reset_length (event_data);

      otx2_main.admin_up_down_in_progress = 0;

    }
  return 0;			/* or not */
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (admin_up_down_process_node) = {
    .function = admin_up_down_process,
    .type = VLIB_NODE_TYPE_PROCESS,
    .name = "admin-up-down-process",
    .process_log2_n_stack_bytes = 17,  // 256KB
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
