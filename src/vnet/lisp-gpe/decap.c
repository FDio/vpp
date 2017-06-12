/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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
/**
 * @file
 * @brief L2 LISP-GPE decap code.
 *
 */
#include <vlib/vlib.h>
#include <vnet/pg/pg.h>
#include <vnet/lisp-gpe/lisp_gpe.h>

typedef struct
{
  u32 next_index;
  u32 tunnel_index;
  u32 error;
  lisp_gpe_header_t h;
} lisp_gpe_rx_trace_t;

static u8 *
format_lisp_gpe_rx_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  lisp_gpe_rx_trace_t *t = va_arg (*args, lisp_gpe_rx_trace_t *);

  if (t->tunnel_index != ~0)
    {
      s = format (s, "LISP-GPE: tunnel %d next %d error %d", t->tunnel_index,
		  t->next_index, t->error);
    }
  else
    {
      s = format (s, "LISP-GPE: no tunnel next %d error %d\n", t->next_index,
		  t->error);
    }
  s = format (s, "\n  %U", format_lisp_gpe_header_with_length, &t->h,
	      (u32) sizeof (t->h) /* max size */ );
  return s;
}

static u32 next_proto_to_next_index[LISP_GPE_NEXT_PROTOS] = {
  LISP_GPE_INPUT_NEXT_DROP,
  LISP_GPE_INPUT_NEXT_IP4_INPUT,
  LISP_GPE_INPUT_NEXT_IP6_INPUT,
  LISP_GPE_INPUT_NEXT_L2_INPUT,
  LISP_GPE_INPUT_NEXT_DROP
};

always_inline u32
next_protocol_to_next_index (lisp_gpe_header_t * lgh, u8 * next_header)
{
  lisp_gpe_main_t *lgm = vnet_lisp_gpe_get_main ();

  /* lisp-gpe router */
  if (PREDICT_TRUE ((lgh->flags & LISP_GPE_FLAGS_P)
		    || GPE_ENCAP_VXLAN == lgm->encap_mode))
    {
      if (PREDICT_FALSE (lgh->next_protocol >= LISP_GPE_NEXT_PROTOS))
	return LISP_GPE_INPUT_NEXT_DROP;

      return next_proto_to_next_index[lgh->next_protocol];
    }
  /* legacy lisp router */
  else if ((lgh->flags & LISP_GPE_FLAGS_P) == 0)
    {
      ip4_header_t *iph = (ip4_header_t *) next_header;
      if ((iph->ip_version_and_header_length & 0xF0) == 0x40)
	return LISP_GPE_INPUT_NEXT_IP4_INPUT;
      else if ((iph->ip_version_and_header_length & 0xF0) == 0x60)
	return LISP_GPE_INPUT_NEXT_IP6_INPUT;
      else
	return LISP_GPE_INPUT_NEXT_DROP;
    }
  else
    return LISP_GPE_INPUT_NEXT_DROP;
}

always_inline tunnel_lookup_t *
next_index_to_iface (lisp_gpe_main_t * lgm, u32 next_index)
{
  if (LISP_GPE_INPUT_NEXT_IP4_INPUT == next_index
      || LISP_GPE_INPUT_NEXT_IP6_INPUT == next_index)
    return &lgm->l3_ifaces;
  else if (LISP_GPE_INPUT_NEXT_L2_INPUT == next_index)
    return &lgm->l2_ifaces;
  else if (LISP_GPE_INPUT_NEXT_NSH_INPUT == next_index)
    return &lgm->nsh_ifaces;
  clib_warning ("next_index not associated to an interface!");
  return 0;
}

static_always_inline void
incr_decap_stats (vnet_main_t * vnm, u32 thread_index, u32 length,
		  u32 sw_if_index, u32 * last_sw_if_index, u32 * n_packets,
		  u32 * n_bytes)
{
  vnet_interface_main_t *im;

  if (PREDICT_TRUE (sw_if_index == *last_sw_if_index))
    {
      *n_packets += 1;
      *n_bytes += length;
    }
  else
    {
      if (PREDICT_TRUE (*last_sw_if_index != ~0))
	{
	  im = &vnm->interface_main;

	  vlib_increment_combined_counter (im->combined_sw_if_counters +
					   VNET_INTERFACE_COUNTER_RX,
					   thread_index, *last_sw_if_index,
					   *n_packets, *n_bytes);
	}
      *last_sw_if_index = sw_if_index;
      *n_packets = 1;
      *n_bytes = length;
    }
}

/**
 * @brief LISP-GPE decap dispatcher.
 * @node lisp_gpe_input_inline
 *
 * LISP-GPE decap dispatcher.
 *
 * Decaps IP-UDP-LISP-GPE header and based on the next protocol and in the
 * GPE header and the vni decides the next node to forward the packet to.
 *
 * @param[in]   vm      vlib_main_t corresponding to current thread.
 * @param[in]   node    vlib_node_runtime_t data for this node.
 * @param[in]   frame   vlib_frame_t whose contents should be dispatched.
 *
 * @return number of vectors in frame.
 */
static uword
lisp_gpe_input_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
		       vlib_frame_t * from_frame, u8 is_v4)
{
  u32 n_left_from, next_index, *from, *to_next, thread_index;
  u32 n_bytes = 0, n_packets = 0, last_sw_if_index = ~0, drops = 0;
  lisp_gpe_main_t *lgm = vnet_lisp_gpe_get_main ();

  thread_index = vlib_get_thread_index ();
  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
	  u32 bi0, bi1;
	  vlib_buffer_t *b0, *b1;
	  ip4_udp_lisp_gpe_header_t *iul4_0, *iul4_1;
	  ip6_udp_lisp_gpe_header_t *iul6_0, *iul6_1;
	  lisp_gpe_header_t *lh0, *lh1;
	  u32 next0, next1, error0, error1;
	  uword *si0, *si1;
	  tunnel_lookup_t *tl0, *tl1;

	  /* Prefetch next iteration. */
	  {
	    vlib_buffer_t *p2, *p3;

	    p2 = vlib_get_buffer (vm, from[2]);
	    p3 = vlib_get_buffer (vm, from[3]);

	    vlib_prefetch_buffer_header (p2, LOAD);
	    vlib_prefetch_buffer_header (p3, LOAD);

	    CLIB_PREFETCH (p2->data, 2 * CLIB_CACHE_LINE_BYTES, LOAD);
	    CLIB_PREFETCH (p3->data, 2 * CLIB_CACHE_LINE_BYTES, LOAD);
	  }

	  bi0 = from[0];
	  bi1 = from[1];
	  to_next[0] = bi0;
	  to_next[1] = bi1;
	  from += 2;
	  to_next += 2;
	  n_left_to_next -= 2;
	  n_left_from -= 2;

	  b0 = vlib_get_buffer (vm, bi0);
	  b1 = vlib_get_buffer (vm, bi1);

	  /* udp leaves current_data pointing at the lisp header */
	  if (is_v4)
	    {
	      vlib_buffer_advance (b0,
				   -(word) (sizeof (udp_header_t) +
					    sizeof (ip4_header_t)));
	      vlib_buffer_advance (b1,
				   -(word) (sizeof (udp_header_t) +
					    sizeof (ip4_header_t)));

	      iul4_0 = vlib_buffer_get_current (b0);
	      iul4_1 = vlib_buffer_get_current (b1);

	      /* pop (ip, udp, lisp-gpe) */
	      vlib_buffer_advance (b0, sizeof (*iul4_0));
	      vlib_buffer_advance (b1, sizeof (*iul4_1));

	      lh0 = &iul4_0->lisp;
	      lh1 = &iul4_1->lisp;
	    }
	  else
	    {
	      vlib_buffer_advance (b0,
				   -(word) (sizeof (udp_header_t) +
					    sizeof (ip6_header_t)));
	      vlib_buffer_advance (b1,
				   -(word) (sizeof (udp_header_t) +
					    sizeof (ip6_header_t)));

	      iul6_0 = vlib_buffer_get_current (b0);
	      iul6_1 = vlib_buffer_get_current (b1);

	      /* pop (ip, udp, lisp-gpe) */
	      vlib_buffer_advance (b0, sizeof (*iul6_0));
	      vlib_buffer_advance (b1, sizeof (*iul6_1));

	      lh0 = &iul6_0->lisp;
	      lh1 = &iul6_1->lisp;
	    }

	  /* determine next_index from lisp-gpe header */
	  next0 = next_protocol_to_next_index (lh0,
					       vlib_buffer_get_current (b0));
	  next1 = next_protocol_to_next_index (lh1,
					       vlib_buffer_get_current (b1));

	  /* determine if tunnel is l2 or l3 */
	  tl0 = next_index_to_iface (lgm, next0);
	  tl1 = next_index_to_iface (lgm, next1);

	  /* map iid/vni to lisp-gpe sw_if_index which is used by ipx_input to
	   * decide the rx vrf and the input features to be applied */
	  si0 = hash_get (tl0->sw_if_index_by_vni,
			  clib_net_to_host_u32 (lh0->iid << 8));
	  si1 = hash_get (tl1->sw_if_index_by_vni,
			  clib_net_to_host_u32 (lh1->iid << 8));


	  /* Required to make the l2 tag push / pop code work on l2 subifs */
	  vnet_update_l2_len (b0);
	  vnet_update_l2_len (b1);

	  if (si0)
	    {
	      incr_decap_stats (lgm->vnet_main, thread_index,
				vlib_buffer_length_in_chain (vm, b0), si0[0],
				&last_sw_if_index, &n_packets, &n_bytes);
	      vnet_buffer (b0)->sw_if_index[VLIB_RX] = si0[0];
	      error0 = 0;
	    }
	  else
	    {
	      next0 = LISP_GPE_INPUT_NEXT_DROP;
	      error0 = LISP_GPE_ERROR_NO_TUNNEL;
	      drops++;
	    }

	  if (si1)
	    {
	      incr_decap_stats (lgm->vnet_main, thread_index,
				vlib_buffer_length_in_chain (vm, b1), si1[0],
				&last_sw_if_index, &n_packets, &n_bytes);
	      vnet_buffer (b1)->sw_if_index[VLIB_RX] = si1[0];
	      error1 = 0;
	    }
	  else
	    {
	      next1 = LISP_GPE_INPUT_NEXT_DROP;
	      error1 = LISP_GPE_ERROR_NO_TUNNEL;
	      drops++;
	    }

	  b0->error = error0 ? node->errors[error0] : 0;
	  b1->error = error1 ? node->errors[error1] : 0;

	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      lisp_gpe_rx_trace_t *tr = vlib_add_trace (vm, node, b0,
							sizeof (*tr));
	      tr->next_index = next0;
	      tr->error = error0;
	      tr->h = lh0[0];
	    }

	  if (PREDICT_FALSE (b1->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      lisp_gpe_rx_trace_t *tr = vlib_add_trace (vm, node, b1,
							sizeof (*tr));
	      tr->next_index = next1;
	      tr->error = error1;
	      tr->h = lh1[0];
	    }

	  vlib_validate_buffer_enqueue_x2 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, bi1, next0,
					   next1);
	}

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  u32 next0;
	  ip4_udp_lisp_gpe_header_t *iul4_0;
	  ip6_udp_lisp_gpe_header_t *iul6_0;
	  lisp_gpe_header_t *lh0;
	  u32 error0;
	  uword *si0;
	  tunnel_lookup_t *tl0;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

	  /* udp leaves current_data pointing at the lisp header
	   * TODO: there's no difference in processing between v4 and v6
	   * encapsulated packets so the code should be simplified if ip header
	   * info is not going to be used for dp smrs/dpsec */
	  if (is_v4)
	    {
	      vlib_buffer_advance (b0,
				   -(word) (sizeof (udp_header_t) +
					    sizeof (ip4_header_t)));

	      iul4_0 = vlib_buffer_get_current (b0);

	      /* pop (ip, udp, lisp-gpe) */
	      vlib_buffer_advance (b0, sizeof (*iul4_0));

	      lh0 = &iul4_0->lisp;
	    }
	  else
	    {
	      vlib_buffer_advance (b0,
				   -(word) (sizeof (udp_header_t) +
					    sizeof (ip6_header_t)));

	      iul6_0 = vlib_buffer_get_current (b0);

	      /* pop (ip, udp, lisp-gpe) */
	      vlib_buffer_advance (b0, sizeof (*iul6_0));

	      lh0 = &iul6_0->lisp;
	    }

	  /* TODO if security is to be implemented, something similar to RPF,
	   * probably we'd like to check that the peer is allowed to send us
	   * packets. For this, we should use the tunnel table OR check that
	   * we have a mapping for the source eid and that the outer source of
	   * the packet is one of its locators */

	  /* determine next_index from lisp-gpe header */
	  next0 = next_protocol_to_next_index (lh0,
					       vlib_buffer_get_current (b0));

	  /* determine if tunnel is l2 or l3 */
	  tl0 = next_index_to_iface (lgm, next0);

	  /* map iid/vni to lisp-gpe sw_if_index which is used by ipx_input to
	   * decide the rx vrf and the input features to be applied.
	   * NOTE: vni uses only the first 24 bits */
	  si0 = hash_get (tl0->sw_if_index_by_vni,
			  clib_net_to_host_u32 (lh0->iid << 8));

	  /* Required to make the l2 tag push / pop code work on l2 subifs */
	  vnet_update_l2_len (b0);

	  if (si0)
	    {
	      incr_decap_stats (lgm->vnet_main, thread_index,
				vlib_buffer_length_in_chain (vm, b0), si0[0],
				&last_sw_if_index, &n_packets, &n_bytes);
	      vnet_buffer (b0)->sw_if_index[VLIB_RX] = si0[0];
	      error0 = 0;
	    }
	  else
	    {
	      next0 = LISP_GPE_INPUT_NEXT_DROP;
	      error0 = LISP_GPE_ERROR_NO_TUNNEL;
	      drops++;
	    }

	  /* TODO error handling if security is implemented */
	  b0->error = error0 ? node->errors[error0] : 0;

	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      lisp_gpe_rx_trace_t *tr = vlib_add_trace (vm, node, b0,
							sizeof (*tr));
	      tr->next_index = next0;
	      tr->error = error0;
	      tr->h = lh0[0];
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  /* flush iface stats */
  incr_decap_stats (lgm->vnet_main, thread_index, 0, ~0, &last_sw_if_index,
		    &n_packets, &n_bytes);
  vlib_node_increment_counter (vm, lisp_gpe_ip4_input_node.index,
			       LISP_GPE_ERROR_NO_TUNNEL, drops);
  return from_frame->n_vectors;
}

static uword
lisp_gpe_ip4_input (vlib_main_t * vm, vlib_node_runtime_t * node,
		    vlib_frame_t * from_frame)
{
  return lisp_gpe_input_inline (vm, node, from_frame, 1);
}

static uword
lisp_gpe_ip6_input (vlib_main_t * vm, vlib_node_runtime_t * node,
		    vlib_frame_t * from_frame)
{
  return lisp_gpe_input_inline (vm, node, from_frame, 0);
}

static char *lisp_gpe_ip4_input_error_strings[] = {
#define lisp_gpe_error(n,s) s,
#include <vnet/lisp-gpe/lisp_gpe_error.def>
#undef lisp_gpe_error
};

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (lisp_gpe_ip4_input_node) = {
  .function = lisp_gpe_ip4_input,
  .name = "lisp-gpe-ip4-input",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),
  .n_next_nodes = LISP_GPE_INPUT_N_NEXT,
  .next_nodes = {
#define _(s,n) [LISP_GPE_INPUT_NEXT_##s] = n,
    foreach_lisp_gpe_ip_input_next
#undef _
  },

  .n_errors = ARRAY_LEN (lisp_gpe_ip4_input_error_strings),
  .error_strings = lisp_gpe_ip4_input_error_strings,

  .format_buffer = format_lisp_gpe_header_with_length,
  .format_trace = format_lisp_gpe_rx_trace,
  // $$$$ .unformat_buffer = unformat_lisp_gpe_header,
};
/* *INDENT-ON* */

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (lisp_gpe_ip6_input_node) = {
  .function = lisp_gpe_ip6_input,
  .name = "lisp-gpe-ip6-input",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),
  .n_next_nodes = LISP_GPE_INPUT_N_NEXT,
  .next_nodes = {
#define _(s,n) [LISP_GPE_INPUT_NEXT_##s] = n,
    foreach_lisp_gpe_ip_input_next
#undef _
  },

  .n_errors = ARRAY_LEN (lisp_gpe_ip4_input_error_strings),
  .error_strings = lisp_gpe_ip4_input_error_strings,

  .format_buffer = format_lisp_gpe_header_with_length,
  .format_trace = format_lisp_gpe_rx_trace,
  // $$$$ .unformat_buffer = unformat_lisp_gpe_header,
};
/* *INDENT-ON* */

/**
 * Adds arc from lisp-gpe-input to nsh-input if nsh-input is available
 */
static void
gpe_add_arc_from_input_to_nsh ()
{
  lisp_gpe_main_t *lgm = vnet_lisp_gpe_get_main ();
  vlib_main_t *vm = lgm->vlib_main;
  vlib_node_t *nsh_input;

  /* Arc already exists */
  if (next_proto_to_next_index[LISP_GPE_NEXT_PROTO_NSH]
      != LISP_GPE_INPUT_NEXT_DROP)
    return;

  /* Check if nsh-input is available */
  if ((nsh_input = vlib_get_node_by_name (vm, (u8 *) "nsh-input")))
    {
      u32 slot4, slot6;
      slot4 = vlib_node_add_next_with_slot (vm, lisp_gpe_ip4_input_node.index,
					    nsh_input->index,
					    LISP_GPE_NEXT_PROTO_NSH);
      slot6 = vlib_node_add_next_with_slot (vm, lisp_gpe_ip6_input_node.index,
					    nsh_input->index,
					    LISP_GPE_NEXT_PROTO_NSH);
      ASSERT (slot4 == slot6 && slot4 == LISP_GPE_INPUT_NEXT_NSH_INPUT);

      next_proto_to_next_index[LISP_GPE_NEXT_PROTO_NSH] = slot4;
    }
}

/** GPE decap init function. */
clib_error_t *
gpe_decap_init (vlib_main_t * vm)
{
  clib_error_t *error = 0;

  if ((error = vlib_call_init_function (vm, lisp_gpe_init)))
    return error;

  gpe_add_arc_from_input_to_nsh ();
  return 0;
}

static uword
lisp_gpe_nsh_dummy_input (vlib_main_t * vm, vlib_node_runtime_t * node,
			  vlib_frame_t * from_frame)
{
  vlib_node_increment_counter (vm, node->node_index, 0, 1);
  return from_frame->n_vectors;
}

static char *lisp_gpe_nsh_dummy_error_strings[] = {
  "lisp gpe dummy nsh decap",
};

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (lisp_gpe_nsh_dummy_input_node) = {
  .function = lisp_gpe_nsh_dummy_input,
  .name = "lisp-gpe-nsh-dummy-input",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_next_nodes = 1,

  .n_errors = 1,
  .error_strings = lisp_gpe_nsh_dummy_error_strings,

  .next_nodes = {
      [0] = "error-drop",
  },
};
/* *INDENT-ON* */

static clib_error_t *
lisp_add_dummy_nsh_node_command_fn (vlib_main_t * vm,
				    unformat_input_t * input,
				    vlib_cli_command_t * cmd)
{
  lisp_gpe_main_t *lgm = vnet_lisp_gpe_get_main ();
  vlib_node_add_next (lgm->vlib_main, lisp_gpe_ip4_input_node.index,
		      lisp_gpe_nsh_dummy_input_node.index);
  next_proto_to_next_index[LISP_GPE_NEXT_PROTO_NSH] =
    LISP_GPE_INPUT_NEXT_NSH_INPUT;
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (lisp_add_dummy_nsh_node_command, static) = {
  .path = "test one nsh add-dummy-decap-node",
  .function = lisp_add_dummy_nsh_node_command_fn,
};
/* *INDENT-ON* */

VLIB_INIT_FUNCTION (gpe_decap_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
