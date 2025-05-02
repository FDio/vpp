/*
 *------------------------------------------------------------------
 * Copyright (c) 2017 Cisco and/or its affiliates.
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
 *------------------------------------------------------------------
 */

#define _GNU_SOURCE
#include <stdint.h>
#include <vnet/llc/llc.h>
#include <vnet/snap/snap.h>
#include <vnet/bonding/node.h>

#ifndef CLIB_MARCH_VARIANT
bond_main_t bond_main;
#endif /* CLIB_MARCH_VARIANT */

#define foreach_bond_input_error \
  _(NONE, "no error")            \
  _(IF_DOWN, "interface down")   \
  _(PASSIVE_IF, "traffic received on passive interface")   \
  _(PASS_THRU, "pass through (CDP, LLDP, slow protocols)")

typedef enum
{
#define _(f,s) BOND_INPUT_ERROR_##f,
  foreach_bond_input_error
#undef _
    BOND_INPUT_N_ERROR,
} bond_input_error_t;

static char *bond_input_error_strings[] = {
#define _(n,s) s,
  foreach_bond_input_error
#undef _
};

static u8 *
format_bond_input_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  bond_packet_trace_t *t = va_arg (*args, bond_packet_trace_t *);

  s = format (s, "src %U, dst %U, %U -> %U",
	      format_ethernet_address, t->ethernet.src_address,
	      format_ethernet_address, t->ethernet.dst_address,
	      format_vnet_sw_if_index_name, vnet_get_main (),
	      t->sw_if_index,
	      format_vnet_sw_if_index_name, vnet_get_main (),
	      t->bond_sw_if_index);

  return s;
}

typedef enum
{
  BOND_INPUT_NEXT_DROP,
  BOND_INPUT_N_NEXT,
} bond_output_next_t;

static_always_inline u8
packet_is_cdp (ethernet_header_t * eth)
{
  llc_header_t *llc;
  snap_header_t *snap;

  llc = (llc_header_t *) (eth + 1);
  snap = (snap_header_t *) (llc + 1);

  return ((eth->type == htons (ETHERNET_TYPE_CDP)) ||
	  ((llc->src_sap == 0xAA) && (llc->control == 0x03) &&
	   (snap->protocol == htons (0x2000)) &&
	   (snap->oui[0] == 0) && (snap->oui[1] == 0) &&
	   (snap->oui[2] == 0x0C)));
}

static inline void
bond_sw_if_idx_rewrite (vlib_main_t * vm, vlib_node_runtime_t * node,
			vlib_buffer_t * b, u32 bond_sw_if_index,
			u32 * n_rx_packets, u32 * n_rx_bytes)
{
  u16 *ethertype_p, ethertype;
  ethernet_vlan_header_t *vlan;
  ethernet_header_t *eth = (ethernet_header_t *) vlib_buffer_get_current (b);

  (*n_rx_packets)++;
  *n_rx_bytes += b->current_length;
  ethertype = clib_mem_unaligned (&eth->type, u16);
  if (!ethernet_frame_is_tagged (ntohs (ethertype)))
    {
      // Let some layer2 packets pass through.
      if (PREDICT_TRUE ((ethertype != htons (ETHERNET_TYPE_SLOW_PROTOCOLS))
			&& !packet_is_cdp (eth)
			&& (ethertype != htons (ETHERNET_TYPE_802_1_LLDP))))
	{
	  /* Change the physical interface to bond interface */
	  vnet_buffer (b)->sw_if_index[VLIB_RX] = bond_sw_if_index;
	  return;
	}
    }
  else
    {
      vlan = (void *) (eth + 1);
      ethertype_p = &vlan->type;
      ethertype = clib_mem_unaligned (ethertype_p, u16);
      if (ethertype == ntohs (ETHERNET_TYPE_VLAN))
	{
	  vlan++;
	  ethertype_p = &vlan->type;
	}
      ethertype = clib_mem_unaligned (ethertype_p, u16);
      if (PREDICT_TRUE ((ethertype != htons (ETHERNET_TYPE_SLOW_PROTOCOLS))
			&& (ethertype != htons (ETHERNET_TYPE_CDP))
			&& (ethertype != htons (ETHERNET_TYPE_802_1_LLDP))))
	{
	  /* Change the physical interface to bond interface */
	  vnet_buffer (b)->sw_if_index[VLIB_RX] = bond_sw_if_index;
	  return;
	}
    }

  vlib_error_count (vm, node->node_index, BOND_INPUT_ERROR_PASS_THRU, 1);
  return;
}

static inline void
bond_update_next (vlib_main_t * vm, vlib_node_runtime_t * node,
		  u32 * last_member_sw_if_index, u32 member_sw_if_index,
		  u32 * bond_sw_if_index, vlib_buffer_t * b,
		  u32 * next_index, vlib_error_t * error)
{
  member_if_t *mif;
  bond_if_t *bif;

  *next_index = BOND_INPUT_NEXT_DROP;
  *error = 0;

  if (PREDICT_TRUE (*last_member_sw_if_index == member_sw_if_index))
    goto next;

  *last_member_sw_if_index = member_sw_if_index;

  mif = bond_get_member_by_sw_if_index (member_sw_if_index);
  ALWAYS_ASSERT (mif);

  bif = bond_get_bond_if_by_dev_instance (mif->bif_dev_instance);

  ALWAYS_ASSERT (bif);
  ASSERT (vec_len (bif->members));

  if (PREDICT_FALSE (bif->admin_up == 0))
    {
      *bond_sw_if_index = member_sw_if_index;
      *error = node->errors[BOND_INPUT_ERROR_IF_DOWN];
    }

  if (PREDICT_FALSE ((bif->mode == BOND_MODE_ACTIVE_BACKUP) &&
		     vec_len (bif->active_members) &&
		     (member_sw_if_index != bif->active_members[0])))
    {
      *bond_sw_if_index = member_sw_if_index;
      *error = node->errors[BOND_INPUT_ERROR_PASSIVE_IF];
      return;
    }

  *bond_sw_if_index = bif->sw_if_index;

next:
  vnet_feature_next (next_index, b);
}

static_always_inline void
bond_update_next_x4 (vlib_buffer_t * b0, vlib_buffer_t * b1,
		     vlib_buffer_t * b2, vlib_buffer_t * b3)
{
  u32 tmp0, tmp1, tmp2, tmp3;

  tmp0 = tmp1 = tmp2 = tmp3 = BOND_INPUT_NEXT_DROP;
  vnet_feature_next (&tmp0, b0);
  vnet_feature_next (&tmp1, b1);
  vnet_feature_next (&tmp2, b2);
  vnet_feature_next (&tmp3, b3);
}

VLIB_NODE_FN (bond_input_node) (vlib_main_t * vm,
				vlib_node_runtime_t * node,
				vlib_frame_t * frame)
{
  clib_thread_index_t thread_index = vm->thread_index;
  u32 *from, n_left;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u32 sw_if_indices[VLIB_FRAME_SIZE], *sw_if_index;
  u16 nexts[VLIB_FRAME_SIZE], *next;
  u32 last_member_sw_if_index = ~0;
  u32 bond_sw_if_index = 0;
  vlib_error_t error = 0;
  u32 next_index = 0;
  u32 n_rx_bytes = 0, n_rx_packets = 0;

  /* Vector of buffer / pkt indices we're supposed to process */
  from = vlib_frame_vector_args (frame);

  /* Number of buffers / pkts */
  n_left = frame->n_vectors;

  vlib_get_buffers (vm, from, bufs, n_left);

  b = bufs;
  next = nexts;
  sw_if_index = sw_if_indices;

  while (n_left >= 4)
    {
      u32 x = 0;
      /* Prefetch next iteration */
      if (PREDICT_TRUE (n_left >= 16))
	{
	  vlib_prefetch_buffer_data (b[8], LOAD);
	  vlib_prefetch_buffer_data (b[9], LOAD);
	  vlib_prefetch_buffer_data (b[10], LOAD);
	  vlib_prefetch_buffer_data (b[11], LOAD);

	  vlib_prefetch_buffer_header (b[12], LOAD);
	  vlib_prefetch_buffer_header (b[13], LOAD);
	  vlib_prefetch_buffer_header (b[14], LOAD);
	  vlib_prefetch_buffer_header (b[15], LOAD);
	}

      sw_if_index[0] = vnet_buffer (b[0])->sw_if_index[VLIB_RX];
      sw_if_index[1] = vnet_buffer (b[1])->sw_if_index[VLIB_RX];
      sw_if_index[2] = vnet_buffer (b[2])->sw_if_index[VLIB_RX];
      sw_if_index[3] = vnet_buffer (b[3])->sw_if_index[VLIB_RX];

      x |= sw_if_index[0] ^ last_member_sw_if_index;
      x |= sw_if_index[1] ^ last_member_sw_if_index;
      x |= sw_if_index[2] ^ last_member_sw_if_index;
      x |= sw_if_index[3] ^ last_member_sw_if_index;

      if (PREDICT_TRUE (x == 0))
	{
	  /*
	   * Optimize to call update_next only if there is a feature arc
	   * after bond-input. Test feature count greater than 1 because
	   * bond-input itself is a feature arc for this member interface.
	   */
	  ASSERT ((vnet_buffer (b[0])->feature_arc_index ==
		   vnet_buffer (b[1])->feature_arc_index) &&
		  (vnet_buffer (b[0])->feature_arc_index ==
		   vnet_buffer (b[2])->feature_arc_index) &&
		  (vnet_buffer (b[0])->feature_arc_index ==
		   vnet_buffer (b[3])->feature_arc_index));
	  if (PREDICT_FALSE (vnet_get_feature_count
			     (vnet_buffer (b[0])->feature_arc_index,
			      last_member_sw_if_index) > 1))
	    bond_update_next_x4 (b[0], b[1], b[2], b[3]);

	  next[0] = next[1] = next[2] = next[3] = next_index;
	  if (next_index == BOND_INPUT_NEXT_DROP)
	    {
	      b[0]->error = error;
	      b[1]->error = error;
	      b[2]->error = error;
	      b[3]->error = error;
	    }
	  else
	    {
	      bond_sw_if_idx_rewrite (vm, node, b[0], bond_sw_if_index,
				      &n_rx_packets, &n_rx_bytes);
	      bond_sw_if_idx_rewrite (vm, node, b[1], bond_sw_if_index,
				      &n_rx_packets, &n_rx_bytes);
	      bond_sw_if_idx_rewrite (vm, node, b[2], bond_sw_if_index,
				      &n_rx_packets, &n_rx_bytes);
	      bond_sw_if_idx_rewrite (vm, node, b[3], bond_sw_if_index,
				      &n_rx_packets, &n_rx_bytes);
	    }
	}
      else
	{
	  bond_update_next (vm, node, &last_member_sw_if_index,
			    sw_if_index[0], &bond_sw_if_index, b[0],
			    &next_index, &error);
	  next[0] = next_index;
	  if (next_index == BOND_INPUT_NEXT_DROP)
	    b[0]->error = error;
	  else
	    bond_sw_if_idx_rewrite (vm, node, b[0], bond_sw_if_index,
				    &n_rx_packets, &n_rx_bytes);

	  bond_update_next (vm, node, &last_member_sw_if_index,
			    sw_if_index[1], &bond_sw_if_index, b[1],
			    &next_index, &error);
	  next[1] = next_index;
	  if (next_index == BOND_INPUT_NEXT_DROP)
	    b[1]->error = error;
	  else
	    bond_sw_if_idx_rewrite (vm, node, b[1], bond_sw_if_index,
				    &n_rx_packets, &n_rx_bytes);

	  bond_update_next (vm, node, &last_member_sw_if_index,
			    sw_if_index[2], &bond_sw_if_index, b[2],
			    &next_index, &error);
	  next[2] = next_index;
	  if (next_index == BOND_INPUT_NEXT_DROP)
	    b[2]->error = error;
	  else
	    bond_sw_if_idx_rewrite (vm, node, b[2], bond_sw_if_index,
				    &n_rx_packets, &n_rx_bytes);

	  bond_update_next (vm, node, &last_member_sw_if_index,
			    sw_if_index[3], &bond_sw_if_index, b[3],
			    &next_index, &error);
	  next[3] = next_index;
	  if (next_index == BOND_INPUT_NEXT_DROP)
	    b[3]->error = error;
	  else
	    bond_sw_if_idx_rewrite (vm, node, b[3], bond_sw_if_index,
				    &n_rx_packets, &n_rx_bytes);
	}

      /* next */
      n_left -= 4;
      b += 4;
      sw_if_index += 4;
      next += 4;
    }

  while (n_left)
    {
      sw_if_index[0] = vnet_buffer (b[0])->sw_if_index[VLIB_RX];
      bond_update_next (vm, node, &last_member_sw_if_index, sw_if_index[0],
			&bond_sw_if_index, b[0], &next_index, &error);
      next[0] = next_index;
      if (next_index == BOND_INPUT_NEXT_DROP)
	b[0]->error = error;
      else
	bond_sw_if_idx_rewrite (vm, node, b[0], bond_sw_if_index,
				&n_rx_packets, &n_rx_bytes);

      /* next */
      n_left -= 1;
      b += 1;
      sw_if_index += 1;
      next += 1;
    }

  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)))
    {
      n_left = frame->n_vectors;	/* number of packets to process */
      b = bufs;
      sw_if_index = sw_if_indices;
      bond_packet_trace_t *t0;

      while (n_left)
	{
	  if (PREDICT_FALSE (b[0]->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      t0 = vlib_add_trace (vm, node, b[0], sizeof (*t0));
	      t0->sw_if_index = sw_if_index[0];
	      clib_memcpy_fast (&t0->ethernet, vlib_buffer_get_current (b[0]),
				sizeof (ethernet_header_t));
	      t0->bond_sw_if_index = vnet_buffer (b[0])->sw_if_index[VLIB_RX];
	    }
	  /* next */
	  n_left--;
	  b++;
	  sw_if_index++;
	}
    }

  /* increase rx counters */
  vlib_increment_combined_counter
    (vnet_main.interface_main.combined_sw_if_counters +
     VNET_INTERFACE_COUNTER_RX, thread_index, bond_sw_if_index, n_rx_packets,
     n_rx_bytes);

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);
  vlib_node_increment_counter (vm, bond_input_node.index,
			       BOND_INPUT_ERROR_NONE, frame->n_vectors);

  return frame->n_vectors;
}

static clib_error_t *
bond_input_init (vlib_main_t * vm)
{
  return 0;
}

VLIB_REGISTER_NODE (bond_input_node) = {
  .name = "bond-input",
  .vector_size = sizeof (u32),
  .format_buffer = format_ethernet_header_with_length,
  .format_trace = format_bond_input_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = BOND_INPUT_N_ERROR,
  .error_strings = bond_input_error_strings,
  .n_next_nodes = BOND_INPUT_N_NEXT,
  .next_nodes =
  {
    [BOND_INPUT_NEXT_DROP] = "error-drop"
  }
};

VLIB_INIT_FUNCTION (bond_input_init);

VNET_FEATURE_INIT (bond_input_device, static) =
{
  .arc_name = "device-input",
  .node_name = "bond-input",
  .runs_before = VNET_FEATURES ("ethernet-input"),
};

VNET_FEATURE_INIT (bond_input_rx, static) =
{
  .arc_name = "port-rx-eth",
  .node_name = "bond-input",
  .runs_before = VNET_FEATURES ("ethernet-input"),
};

static clib_error_t *
bond_sw_interface_up_down (vnet_main_t * vnm, u32 sw_if_index, u32 flags)
{
  bond_main_t *bm = &bond_main;
  member_if_t *mif;
  vlib_main_t *vm = bm->vlib_main;

  mif = bond_get_member_by_sw_if_index (sw_if_index);
  if (mif)
    {
      if (mif->lacp_enabled)
	return 0;

      /* port_enabled is both admin up and hw link up */
      mif->port_enabled = ((flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) &&
			   vnet_sw_interface_is_link_up (vnm, sw_if_index));
      if (mif->port_enabled == 0)
	bond_disable_collecting_distributing (vm, mif);
      else
	bond_enable_collecting_distributing (vm, mif);
    }

  return 0;
}

VNET_SW_INTERFACE_ADMIN_UP_DOWN_FUNCTION (bond_sw_interface_up_down);

static clib_error_t *
bond_hw_interface_up_down (vnet_main_t * vnm, u32 hw_if_index, u32 flags)
{
  bond_main_t *bm = &bond_main;
  member_if_t *mif;
  vnet_sw_interface_t *sw;
  vlib_main_t *vm = bm->vlib_main;

  sw = vnet_get_hw_sw_interface (vnm, hw_if_index);
  mif = bond_get_member_by_sw_if_index (sw->sw_if_index);
  if (mif)
    {
      if (mif->lacp_enabled)
	return 0;

      /* port_enabled is both admin up and hw link up */
      mif->port_enabled = ((flags & VNET_HW_INTERFACE_FLAG_LINK_UP) &&
			   vnet_sw_interface_is_admin_up (vnm,
							  sw->sw_if_index));
      if (mif->port_enabled == 0)
	bond_disable_collecting_distributing (vm, mif);
      else
	bond_enable_collecting_distributing (vm, mif);
    }

  return 0;
}

VNET_HW_INTERFACE_LINK_UP_DOWN_FUNCTION (bond_hw_interface_up_down);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
