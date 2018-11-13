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

bond_main_t bond_main;

#define foreach_bond_input_error \
  _(NONE, "no error")            \
  _(IF_DOWN, "interface down")   \
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

static inline u32
bond_sw_if_idx_rewrite (vlib_main_t * vm, vlib_node_runtime_t * node,
			vlib_buffer_t * b, u32 bond_sw_if_index)
{
  u16 *ethertype_p, ethertype;
  ethernet_vlan_header_t *vlan;
  ethernet_header_t *eth = (ethernet_header_t *) vlib_buffer_get_current (b);

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
	  return 1;
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
	  return 1;
	}
    }

  vlib_error_count (vm, node->node_index, BOND_INPUT_ERROR_PASS_THRU, 1);
  return 0;
}

static inline void
bond_update_next (vlib_main_t * vm, vlib_node_runtime_t * node,
		  u32 * last_slave_sw_if_index, u32 slave_sw_if_index,
		  u32 packet_count,
		  u32 * bond_sw_if_index, vlib_buffer_t * b,
		  u32 * next_index, vlib_error_t * error)
{
  u16 thread_index = vm->thread_index;
  slave_if_t *sif;
  bond_if_t *bif;

  if (PREDICT_TRUE (*last_slave_sw_if_index == slave_sw_if_index))
    return;

  if (packet_count)
    vlib_increment_simple_counter (vnet_main.interface_main.sw_if_counters +
				   VNET_INTERFACE_COUNTER_RX, thread_index,
				   *last_slave_sw_if_index, packet_count);

  *last_slave_sw_if_index = slave_sw_if_index;
  *next_index = BOND_INPUT_NEXT_DROP;

  sif = bond_get_slave_by_sw_if_index (slave_sw_if_index);
  ASSERT (sif);

  bif = bond_get_master_by_dev_instance (sif->bif_dev_instance);

  ASSERT (bif);
  ASSERT (vec_len (bif->slaves));

  if (PREDICT_TRUE (bif->admin_up == 0))
    {
      *bond_sw_if_index = slave_sw_if_index;
      *error = node->errors[BOND_INPUT_ERROR_IF_DOWN];
    }

  *bond_sw_if_index = bif->sw_if_index;
  *error = 0;
  vnet_feature_next (next_index, b);
}

VLIB_NODE_FN (bond_input_node) (vlib_main_t * vm,
				vlib_node_runtime_t * node,
				vlib_frame_t * frame)
{
  u16 thread_index = vm->thread_index;
  u32 *from, n_left;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u32 sw_if_indices[VLIB_FRAME_SIZE], *sw_if_index;
  u16 nexts[VLIB_FRAME_SIZE], *next;
  u32 last_slave_sw_if_index = ~0;
  u32 bond_sw_if_index = 0;
  vlib_error_t error = 0;
  u32 next_index = 0;
  u32 cnt = 0;

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
	  CLIB_PREFETCH (vlib_buffer_get_current (b[8]),
			 CLIB_CACHE_LINE_BYTES, LOAD);
	  CLIB_PREFETCH (vlib_buffer_get_current (b[9]),
			 CLIB_CACHE_LINE_BYTES, LOAD);
	  CLIB_PREFETCH (vlib_buffer_get_current (b[10]),
			 CLIB_CACHE_LINE_BYTES, LOAD);
	  CLIB_PREFETCH (vlib_buffer_get_current (b[11]),
			 CLIB_CACHE_LINE_BYTES, LOAD);

	  vlib_prefetch_buffer_header (b[12], LOAD);
	  vlib_prefetch_buffer_header (b[13], LOAD);
	  vlib_prefetch_buffer_header (b[14], LOAD);
	  vlib_prefetch_buffer_header (b[15], LOAD);
	}

      sw_if_index[0] = vnet_buffer (b[0])->sw_if_index[VLIB_RX];
      sw_if_index[1] = vnet_buffer (b[1])->sw_if_index[VLIB_RX];
      sw_if_index[2] = vnet_buffer (b[2])->sw_if_index[VLIB_RX];
      sw_if_index[3] = vnet_buffer (b[3])->sw_if_index[VLIB_RX];

      x |= sw_if_index[0] ^ last_slave_sw_if_index;
      x |= sw_if_index[1] ^ last_slave_sw_if_index;
      x |= sw_if_index[2] ^ last_slave_sw_if_index;
      x |= sw_if_index[3] ^ last_slave_sw_if_index;

      if (PREDICT_TRUE (x == 0))
	{
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
	      cnt +=
		bond_sw_if_idx_rewrite (vm, node, b[0], bond_sw_if_index);
	      cnt +=
		bond_sw_if_idx_rewrite (vm, node, b[1], bond_sw_if_index);
	      cnt +=
		bond_sw_if_idx_rewrite (vm, node, b[2], bond_sw_if_index);
	      cnt +=
		bond_sw_if_idx_rewrite (vm, node, b[3], bond_sw_if_index);
	    }
	}
      else
	{

	  bond_update_next (vm, node, &last_slave_sw_if_index, sw_if_index[0],
			    cnt, &bond_sw_if_index, b[0], &next_index,
			    &error);
	  next[0] = next_index;
	  if (next_index == BOND_INPUT_NEXT_DROP)
	    b[0]->error = error;
	  else
	    cnt += bond_sw_if_idx_rewrite (vm, node, b[0], bond_sw_if_index);

	  bond_update_next (vm, node, &last_slave_sw_if_index, sw_if_index[1],
			    cnt, &bond_sw_if_index, b[1], &next_index,
			    &error);
	  next[1] = next_index;
	  if (next_index == BOND_INPUT_NEXT_DROP)
	    b[1]->error = error;
	  else
	    cnt += bond_sw_if_idx_rewrite (vm, node, b[1], bond_sw_if_index);

	  bond_update_next (vm, node, &last_slave_sw_if_index, sw_if_index[2],
			    cnt, &bond_sw_if_index, b[2], &next_index,
			    &error);
	  next[2] = next_index;
	  if (next_index == BOND_INPUT_NEXT_DROP)
	    b[2]->error = error;
	  else
	    cnt += bond_sw_if_idx_rewrite (vm, node, b[2], bond_sw_if_index);

	  bond_update_next (vm, node, &last_slave_sw_if_index, sw_if_index[3],
			    cnt, &bond_sw_if_index, b[3], &next_index,
			    &error);
	  next[3] = next_index;
	  if (next_index == BOND_INPUT_NEXT_DROP)
	    b[3]->error = error;
	  else
	    cnt += bond_sw_if_idx_rewrite (vm, node, b[3], bond_sw_if_index);
	}

      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b[0]);
      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b[1]);
      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b[2]);
      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b[3]);

      /* next */
      n_left -= 4;
      b += 4;
      sw_if_index += 4;
      next += 4;
    }

  while (n_left)
    {
      sw_if_index[0] = vnet_buffer (b[0])->sw_if_index[VLIB_RX];
      bond_update_next (vm, node, &last_slave_sw_if_index, sw_if_index[0],
			cnt, &bond_sw_if_index, b[0], &next_index, &error);
      next[0] = next_index;
      if (next_index == BOND_INPUT_NEXT_DROP)
	b[0]->error = error;
      else
	bond_sw_if_idx_rewrite (vm, node, b[0], bond_sw_if_index);

      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b[0]);

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
	      _clib_memcpy (&t0->ethernet, vlib_buffer_get_current (b[0]),
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
  vlib_increment_simple_counter
    (vnet_main.interface_main.sw_if_counters +
     VNET_INTERFACE_COUNTER_RX, thread_index, bond_sw_if_index, cnt);

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

/* *INDENT-OFF* */
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

VNET_FEATURE_INIT (bond_input, static) =
{
  .arc_name = "device-input",
  .node_name = "bond-input",
  .runs_before = VNET_FEATURES ("ethernet-input"),
};
/* *INDENT-ON* */

static clib_error_t *
bond_sw_interface_up_down (vnet_main_t * vnm, u32 sw_if_index, u32 flags)
{
  bond_main_t *bm = &bond_main;
  slave_if_t *sif;
  vlib_main_t *vm = bm->vlib_main;

  sif = bond_get_slave_by_sw_if_index (sw_if_index);
  if (sif)
    {
      sif->port_enabled = flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP;
      if (sif->port_enabled == 0)
	{
	  if (sif->lacp_enabled == 0)
	    {
	      bond_disable_collecting_distributing (vm, sif);
	    }
	}
      else
	{
	  if (sif->lacp_enabled == 0)
	    {
	      bond_enable_collecting_distributing (vm, sif);
	    }
	}
    }

  return 0;
}

VNET_SW_INTERFACE_ADMIN_UP_DOWN_FUNCTION (bond_sw_interface_up_down);

static clib_error_t *
bond_hw_interface_up_down (vnet_main_t * vnm, u32 hw_if_index, u32 flags)
{
  bond_main_t *bm = &bond_main;
  slave_if_t *sif;
  vnet_sw_interface_t *sw;
  vlib_main_t *vm = bm->vlib_main;

  sw = vnet_get_hw_sw_interface (vnm, hw_if_index);
  sif = bond_get_slave_by_sw_if_index (sw->sw_if_index);
  if (sif)
    {
      if (!(flags & VNET_HW_INTERFACE_FLAG_LINK_UP))
	{
	  if (sif->lacp_enabled == 0)
	    {
	      bond_disable_collecting_distributing (vm, sif);
	    }
	}
      else
	{
	  if (sif->lacp_enabled == 0)
	    {
	      bond_enable_collecting_distributing (vm, sif);
	    }
	}
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
