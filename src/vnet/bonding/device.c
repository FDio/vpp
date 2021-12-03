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
#include <vnet/ip-neighbor/ip4_neighbor.h>
#include <vnet/ip-neighbor/ip6_neighbor.h>
#include <vnet/bonding/node.h>

#define foreach_bond_tx_error                                                 \
  _ (NONE, "no error")                                                        \
  _ (IF_DOWN, "interface down")                                               \
  _ (BAD_LB_MODE, "bad load balance mode")                                    \
  _ (NO_MEMBER, "no member")

typedef enum
{
#define _(f,s) BOND_TX_ERROR_##f,
  foreach_bond_tx_error
#undef _
    BOND_TX_N_ERROR,
} bond_tx_error_t;

static char *bond_tx_error_strings[] = {
#define _(n,s) s,
  foreach_bond_tx_error
#undef _
};

static u8 *
format_bond_tx_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  bond_packet_trace_t *t = va_arg (*args, bond_packet_trace_t *);
  vnet_hw_interface_t *hw, *hw1;
  vnet_main_t *vnm = vnet_get_main ();

  hw = vnet_get_sup_hw_interface (vnm, t->sw_if_index);
  hw1 = vnet_get_sup_hw_interface (vnm, t->bond_sw_if_index);
  s = format (s, "src %U, dst %U, %s -> %s",
	      format_ethernet_address, t->ethernet.src_address,
	      format_ethernet_address, t->ethernet.dst_address,
	      hw->name, hw1->name);

  return s;
}

#ifndef CLIB_MARCH_VARIANT
u8 *
format_bond_interface_name (u8 * s, va_list * args)
{
  u32 dev_instance = va_arg (*args, u32);
  bond_main_t *bm = &bond_main;
  bond_if_t *bif = pool_elt_at_index (bm->interfaces, dev_instance);

  s = format (s, "BondEthernet%lu", bif->id);

  return s;
}
#endif

static __clib_unused clib_error_t *
bond_set_l2_mode_function (vnet_main_t * vnm,
			   struct vnet_hw_interface_t *bif_hw,
			   i32 l2_if_adjust)
{
  bond_if_t *bif;
  u32 *sw_if_index;
  struct vnet_hw_interface_t *mif_hw;

  bif = bond_get_bond_if_by_sw_if_index (bif_hw->sw_if_index);
  if (!bif)
    return 0;

  if ((bif_hw->l2_if_count == 1) && (l2_if_adjust == 1))
    {
      /* Just added first L2 interface on this port */
      vec_foreach (sw_if_index, bif->members)
      {
	mif_hw = vnet_get_sup_hw_interface (vnm, *sw_if_index);
	ethernet_set_flags (vnm, mif_hw->hw_if_index,
			    ETHERNET_INTERFACE_FLAG_ACCEPT_ALL);
      }
    }
  else if ((bif_hw->l2_if_count == 0) && (l2_if_adjust == -1))
    {
      /* Just removed last L2 subinterface on this port */
      vec_foreach (sw_if_index, bif->members)
      {
	mif_hw = vnet_get_sup_hw_interface (vnm, *sw_if_index);
	ethernet_set_flags (vnm, mif_hw->hw_if_index,
			    /*ETHERNET_INTERFACE_FLAG_DEFAULT_L3 */ 0);
      }
    }

  return 0;
}

static __clib_unused clib_error_t *
bond_subif_add_del_function (vnet_main_t * vnm, u32 hw_if_index,
			     struct vnet_sw_interface_t *st, int is_add)
{
  /* Nothing for now */
  return 0;
}

static clib_error_t *
bond_interface_admin_up_down (vnet_main_t * vnm, u32 hw_if_index, u32 flags)
{
  vnet_hw_interface_t *hif = vnet_get_hw_interface (vnm, hw_if_index);
  uword is_up = (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) != 0;
  bond_main_t *bm = &bond_main;
  bond_if_t *bif = pool_elt_at_index (bm->interfaces, hif->dev_instance);

  bif->admin_up = is_up;
  if (is_up)
    vnet_hw_interface_set_flags (vnm, bif->hw_if_index,
				 VNET_HW_INTERFACE_FLAG_LINK_UP);
  return 0;
}

static clib_error_t *
bond_add_del_mac_address (vnet_hw_interface_t * hi, const u8 * address,
			  u8 is_add)
{
  vnet_main_t *vnm = vnet_get_main ();
  bond_if_t *bif;
  clib_error_t *error = 0;
  vnet_hw_interface_t *s_hi;
  int i;


  bif = bond_get_bond_if_by_sw_if_index (hi->sw_if_index);
  if (!bif)
    {
      return clib_error_return (0,
				"No bond interface found for sw_if_index %u",
				hi->sw_if_index);
    }

  /* Add/del address on each member hw intf, they control the hardware */
  vec_foreach_index (i, bif->members)
  {
    s_hi = vnet_get_sup_hw_interface (vnm, vec_elt (bif->members, i));
    error = vnet_hw_interface_add_del_mac_address (vnm, s_hi->hw_if_index,
						   address, is_add);

    if (error)
      {
	int j;

	/* undo any that were completed before the failure */
	for (j = i - 1; j > -1; j--)
	  {
	    s_hi = vnet_get_sup_hw_interface (vnm, vec_elt (bif->members, j));
	    vnet_hw_interface_add_del_mac_address (vnm, s_hi->hw_if_index,
						   address, !(is_add));
	  }

	return error;
      }
  }

  return 0;
}

static_always_inline void
bond_tx_add_to_queue (bond_per_thread_data_t * ptd, u32 port, u32 bi)
{
  u32 idx = ptd->per_port_queue[port].n_buffers++;
  ptd->per_port_queue[port].buffers[idx] = bi;
}

static_always_inline u32
bond_lb_broadcast (vlib_main_t *vm, bond_if_t *bif, vlib_buffer_t *b0,
		   uword n_members)
{
  bond_main_t *bm = &bond_main;
  vlib_buffer_t *c0;
  int port;
  u32 sw_if_index;
  u16 thread_index = vm->thread_index;
  bond_per_thread_data_t *ptd = vec_elt_at_index (bm->per_thread_data,
						  thread_index);

  for (port = 1; port < n_members; port++)
    {
      sw_if_index = *vec_elt_at_index (bif->active_members, port);
      c0 = vlib_buffer_copy (vm, b0);
      if (PREDICT_TRUE (c0 != 0))
	{
	  vnet_buffer (c0)->sw_if_index[VLIB_TX] = sw_if_index;
	  bond_tx_add_to_queue (ptd, port, vlib_get_buffer_index (vm, c0));
	}
    }

  return 0;
}

static_always_inline u32
bond_lb_round_robin (bond_if_t *bif, vlib_buffer_t *b0, uword n_members)
{
  bif->lb_rr_last_index++;
  if (bif->lb_rr_last_index >= n_members)
    bif->lb_rr_last_index = 0;

  return bif->lb_rr_last_index;
}

static_always_inline void
bond_tx_hash (vlib_main_t *vm, bond_per_thread_data_t *ptd, bond_if_t *bif,
	      vlib_buffer_t **b, u32 *h, u32 n_left)
{
  u32 n_left_from = n_left;
  void **data;

  ASSERT (bif->hash_func != 0);

  vec_validate_aligned (ptd->data, n_left - 1, CLIB_CACHE_LINE_BYTES);
  data = ptd->data;
  while (n_left >= 8)
    {
      // Prefetch next iteration
      vlib_prefetch_buffer_header (b[4], LOAD);
      vlib_prefetch_buffer_header (b[5], LOAD);
      vlib_prefetch_buffer_header (b[6], LOAD);
      vlib_prefetch_buffer_header (b[7], LOAD);

      data[0] = vlib_buffer_get_current (b[0]);
      data[1] = vlib_buffer_get_current (b[1]);
      data[2] = vlib_buffer_get_current (b[2]);
      data[3] = vlib_buffer_get_current (b[3]);

      n_left -= 4;
      b += 4;
      data += 4;
    }

  while (n_left > 0)
    {
      data[0] = vlib_buffer_get_current (b[0]);

      n_left -= 1;
      b += 1;
      data += 1;
    }

  bif->hash_func (ptd->data, h, n_left_from);
  vec_reset_length (ptd->data);
}

static_always_inline void
bond_tx_no_hash (vlib_main_t *vm, bond_if_t *bif, vlib_buffer_t **b, u32 *h,
		 u32 n_left, uword n_members, u32 lb_alg)
{
  while (n_left >= 8)
    {
      // Prefetch next iteration
      vlib_prefetch_buffer_header (b[4], LOAD);
      vlib_prefetch_buffer_header (b[5], LOAD);
      vlib_prefetch_buffer_header (b[6], LOAD);
      vlib_prefetch_buffer_header (b[7], LOAD);

      clib_prefetch_load (b[4]->data);
      clib_prefetch_load (b[5]->data);
      clib_prefetch_load (b[6]->data);
      clib_prefetch_load (b[7]->data);

      if (lb_alg == BOND_LB_RR)
	{
	  h[0] = bond_lb_round_robin (bif, b[0], n_members);
	  h[1] = bond_lb_round_robin (bif, b[1], n_members);
	  h[2] = bond_lb_round_robin (bif, b[2], n_members);
	  h[3] = bond_lb_round_robin (bif, b[3], n_members);
	}
      else if (lb_alg == BOND_LB_BC)
	{
	  h[0] = bond_lb_broadcast (vm, bif, b[0], n_members);
	  h[1] = bond_lb_broadcast (vm, bif, b[1], n_members);
	  h[2] = bond_lb_broadcast (vm, bif, b[2], n_members);
	  h[3] = bond_lb_broadcast (vm, bif, b[3], n_members);
	}
      else
	{
	  ASSERT (0);
	}

      n_left -= 4;
      b += 4;
      h += 4;
    }

  while (n_left > 0)
    {
      if (bif->lb == BOND_LB_RR)
	h[0] = bond_lb_round_robin (bif, b[0], n_members);
      else if (bif->lb == BOND_LB_BC)
	h[0] = bond_lb_broadcast (vm, bif, b[0], n_members);
      else
	{
	  ASSERT (0);
	}

      n_left -= 1;
      b += 1;
      h += 1;
    }
}

static_always_inline void
bond_hash_to_port (u32 * h, u32 n_left, u32 n_members,
		   int use_modulo_shortcut)
{
  u32 mask = n_members - 1;

  while (n_left > 4)
    {
      if (use_modulo_shortcut)
	{
	  h[0] &= mask;
	  h[1] &= mask;
	  h[2] &= mask;
	  h[3] &= mask;
	}
      else
	{
	  h[0] %= n_members;
	  h[1] %= n_members;
	  h[2] %= n_members;
	  h[3] %= n_members;
	}
      n_left -= 4;
      h += 4;
    }
  while (n_left)
    {
      if (use_modulo_shortcut)
	h[0] &= mask;
      else
	h[0] %= n_members;
      n_left -= 1;
      h += 1;
    }
}

static_always_inline void
bond_update_sw_if_index (bond_per_thread_data_t * ptd, bond_if_t * bif,
			 u32 * bi, vlib_buffer_t ** b, u32 * data, u32 n_left,
			 int single_sw_if_index)
{
  u32 sw_if_index = data[0];
  u32 *h = data;

  while (n_left >= 8)
    {
      // Prefetch next iteration
      vlib_prefetch_buffer_header (b[4], LOAD);
      vlib_prefetch_buffer_header (b[5], LOAD);
      vlib_prefetch_buffer_header (b[6], LOAD);
      vlib_prefetch_buffer_header (b[7], LOAD);

      if (PREDICT_FALSE (single_sw_if_index))
	{
	  vnet_buffer (b[0])->sw_if_index[VLIB_TX] = sw_if_index;
	  vnet_buffer (b[1])->sw_if_index[VLIB_TX] = sw_if_index;
	  vnet_buffer (b[2])->sw_if_index[VLIB_TX] = sw_if_index;
	  vnet_buffer (b[3])->sw_if_index[VLIB_TX] = sw_if_index;

	  bond_tx_add_to_queue (ptd, 0, bi[0]);
	  bond_tx_add_to_queue (ptd, 0, bi[1]);
	  bond_tx_add_to_queue (ptd, 0, bi[2]);
	  bond_tx_add_to_queue (ptd, 0, bi[3]);
	}
      else
	{
	  vnet_buffer (b[0])->sw_if_index[VLIB_TX] =
	    *vec_elt_at_index (bif->active_members, h[0]);
	  vnet_buffer (b[1])->sw_if_index[VLIB_TX] =
	    *vec_elt_at_index (bif->active_members, h[1]);
	  vnet_buffer (b[2])->sw_if_index[VLIB_TX] =
	    *vec_elt_at_index (bif->active_members, h[2]);
	  vnet_buffer (b[3])->sw_if_index[VLIB_TX] =
	    *vec_elt_at_index (bif->active_members, h[3]);

	  bond_tx_add_to_queue (ptd, h[0], bi[0]);
	  bond_tx_add_to_queue (ptd, h[1], bi[1]);
	  bond_tx_add_to_queue (ptd, h[2], bi[2]);
	  bond_tx_add_to_queue (ptd, h[3], bi[3]);
	}

      bi += 4;
      h += 4;
      b += 4;
      n_left -= 4;
    }
  while (n_left)
    {
      if (PREDICT_FALSE (single_sw_if_index))
	{
	  vnet_buffer (b[0])->sw_if_index[VLIB_TX] = sw_if_index;
	  bond_tx_add_to_queue (ptd, 0, bi[0]);
	}
      else
	{
	  vnet_buffer (b[0])->sw_if_index[VLIB_TX] =
	    *vec_elt_at_index (bif->active_members, h[0]);
	  bond_tx_add_to_queue (ptd, h[0], bi[0]);
	}

      bi += 1;
      h += 1;
      b += 1;
      n_left -= 1;
    }
}

static_always_inline void
bond_tx_trace (vlib_main_t * vm, vlib_node_runtime_t * node, bond_if_t * bif,
	       vlib_buffer_t ** b, u32 n_left, u32 * h)
{
  uword n_trace = vlib_get_trace_count (vm, node);

  while (n_trace > 0 && n_left > 0)
    {
      if (PREDICT_TRUE
	  (vlib_trace_buffer (vm, node, 0, b[0], 0 /* follow_chain */ )))
	{
	  bond_packet_trace_t *t0;
	  ethernet_header_t *eth;

	  vlib_set_trace_count (vm, node, --n_trace);
	  t0 = vlib_add_trace (vm, node, b[0], sizeof (*t0));
	  eth = vlib_buffer_get_current (b[0]);
	  t0->ethernet = *eth;
	  t0->sw_if_index = vnet_buffer (b[0])->sw_if_index[VLIB_TX];
	  if (!h)
	    {
	      t0->bond_sw_if_index =
		*vec_elt_at_index (bif->active_members, 0);
	    }
	  else
	    {
	      t0->bond_sw_if_index =
		*vec_elt_at_index (bif->active_members, h[0]);
	      h++;
	    }
	}
      b++;
      n_left--;
    }
}

VNET_DEVICE_CLASS_TX_FN (bond_dev_class) (vlib_main_t * vm,
					  vlib_node_runtime_t * node,
					  vlib_frame_t * frame)
{
  vnet_interface_output_runtime_t *rund = (void *) node->runtime_data;
  bond_main_t *bm = &bond_main;
  u16 thread_index = vm->thread_index;
  bond_if_t *bif = pool_elt_at_index (bm->interfaces, rund->dev_instance);
  uword n_members;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE];
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left = frame->n_vectors;
  u32 hashes[VLIB_FRAME_SIZE], *h;
  vnet_main_t *vnm = vnet_get_main ();
  bond_per_thread_data_t *ptd = vec_elt_at_index (bm->per_thread_data,
						  thread_index);
  u32 p, sw_if_index;

  if (PREDICT_FALSE (bif->admin_up == 0))
    {
      vlib_buffer_free (vm, vlib_frame_vector_args (frame), frame->n_vectors);
      vlib_increment_simple_counter (vnet_main.interface_main.sw_if_counters +
				     VNET_INTERFACE_COUNTER_DROP,
				     thread_index, bif->sw_if_index,
				     frame->n_vectors);
      vlib_error_count (vm, node->node_index, BOND_TX_ERROR_IF_DOWN,
			frame->n_vectors);
      return frame->n_vectors;
    }

  n_members = vec_len (bif->active_members);
  if (PREDICT_FALSE (n_members == 0))
    {
      vlib_buffer_free (vm, vlib_frame_vector_args (frame), frame->n_vectors);
      vlib_increment_simple_counter (vnet_main.interface_main.sw_if_counters +
				     VNET_INTERFACE_COUNTER_DROP,
				     thread_index, bif->sw_if_index,
				     frame->n_vectors);
      vlib_error_count (vm, node->node_index, BOND_TX_ERROR_NO_MEMBER,
			frame->n_vectors);
      return frame->n_vectors;
    }

  vlib_get_buffers (vm, from, bufs, n_left);

  /* active-backup mode, ship everything to first sw if index */
  if ((bif->lb == BOND_LB_AB) || PREDICT_FALSE (n_members == 1))
    {
      sw_if_index = *vec_elt_at_index (bif->active_members, 0);

      bond_tx_trace (vm, node, bif, bufs, frame->n_vectors, 0);
      bond_update_sw_if_index (ptd, bif, from, bufs, &sw_if_index, n_left,
			       /* single_sw_if_index */ 1);
      goto done;
    }

  if (bif->lb == BOND_LB_BC)
    {
      sw_if_index = *vec_elt_at_index (bif->active_members, 0);

      bond_tx_no_hash (vm, bif, bufs, hashes, n_left, n_members, BOND_LB_BC);
      bond_tx_trace (vm, node, bif, bufs, frame->n_vectors, 0);
      bond_update_sw_if_index (ptd, bif, from, bufs, &sw_if_index, n_left,
			       /* single_sw_if_index */ 1);
      goto done;
    }

  /* if have at least one member on local numa node, only members on local numa
     node will transmit pkts when bif->local_numa_only is enabled */
  if (bif->n_numa_members >= 1)
    n_members = bif->n_numa_members;

  if (bif->lb == BOND_LB_RR)
    bond_tx_no_hash (vm, bif, bufs, hashes, n_left, n_members, BOND_LB_RR);
  else
    bond_tx_hash (vm, ptd, bif, bufs, hashes, n_left);

  /* calculate port out of hash */
  h = hashes;
  if (BOND_MODULO_SHORTCUT (n_members))
    bond_hash_to_port (h, frame->n_vectors, n_members, 1);
  else
    bond_hash_to_port (h, frame->n_vectors, n_members, 0);

  bond_tx_trace (vm, node, bif, bufs, frame->n_vectors, h);

  bond_update_sw_if_index (ptd, bif, from, bufs, hashes, frame->n_vectors,
			   /* single_sw_if_index */ 0);

done:
  for (p = 0; p < n_members; p++)
    {
      vlib_frame_t *f;
      u32 *to_next;

      sw_if_index = *vec_elt_at_index (bif->active_members, p);
      if (PREDICT_TRUE (ptd->per_port_queue[p].n_buffers))
	{
	  f = vnet_get_frame_to_sw_interface (vnm, sw_if_index);
	  f->n_vectors = ptd->per_port_queue[p].n_buffers;
	  to_next = vlib_frame_vector_args (f);
	  clib_memcpy_fast (to_next, ptd->per_port_queue[p].buffers,
			    f->n_vectors * sizeof (u32));
	  vnet_put_frame_to_sw_interface (vnm, sw_if_index, f);
	  ptd->per_port_queue[p].n_buffers = 0;
	}
    }
  return frame->n_vectors;
}

static walk_rc_t
bond_active_interface_switch_cb (vnet_main_t * vnm, u32 sw_if_index,
				 void *arg)
{
  bond_main_t *bm = &bond_main;

  ip4_neighbor_advertise (bm->vlib_main, bm->vnet_main, sw_if_index, NULL);
  ip6_neighbor_advertise (bm->vlib_main, bm->vnet_main, sw_if_index, NULL);

  return (WALK_CONTINUE);
}

static uword
bond_process (vlib_main_t * vm, vlib_node_runtime_t * rt, vlib_frame_t * f)
{
  vnet_main_t *vnm = vnet_get_main ();
  uword event_type, *event_data = 0;

  while (1)
    {
      u32 i;
      u32 hw_if_index;

      vlib_process_wait_for_event (vm);
      event_type = vlib_process_get_events (vm, &event_data);
      ASSERT (event_type == BOND_SEND_GARP_NA);
      for (i = 0; i < vec_len (event_data); i++)
	{
	  hw_if_index = event_data[i];
	  if (vnet_get_hw_interface_or_null (vnm, hw_if_index))
	    /* walk hw interface to process all subinterfaces */
	    vnet_hw_interface_walk_sw (vnm, hw_if_index,
				       bond_active_interface_switch_cb, 0);
	}
      vec_reset_length (event_data);
    }
  return 0;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (bond_process_node) = {
  .function = bond_process,
  .flags = VLIB_NODE_FLAG_TRACE_SUPPORTED,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "bond-process",
};
/* *INDENT-ON* */

/* *INDENT-OFF* */
VNET_DEVICE_CLASS (bond_dev_class) = {
  .name = "bond",
  .tx_function_n_errors = BOND_TX_N_ERROR,
  .tx_function_error_strings = bond_tx_error_strings,
  .format_device_name = format_bond_interface_name,
  .set_l2_mode_function = bond_set_l2_mode_function,
  .admin_up_down_function = bond_interface_admin_up_down,
  .subif_add_del_function = bond_subif_add_del_function,
  .format_tx_trace = format_bond_tx_trace,
  .mac_addr_add_del_function = bond_add_del_mac_address,
};

/* *INDENT-ON* */

static clib_error_t *
bond_member_interface_add_del (vnet_main_t * vnm, u32 sw_if_index, u32 is_add)
{
  bond_main_t *bm = &bond_main;
  member_if_t *mif;
  bond_detach_member_args_t args = { 0 };

  if (is_add)
    return 0;
  mif = bond_get_member_by_sw_if_index (sw_if_index);
  if (!mif)
    return 0;
  args.member = sw_if_index;
  bond_detach_member (bm->vlib_main, &args);
  return args.error;
}

VNET_SW_INTERFACE_ADD_DEL_FUNCTION (bond_member_interface_add_del);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
