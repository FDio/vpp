/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
/*
 * ip/ip4_input.c: IP v4 input node
 *
 * Copyright (c) 2008 Eliot Dresselhaus
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 *  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 *  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 *  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 *  LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 *  OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 *  WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include <vnet/ip/ip4_input.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/pg/pg.h>
#include <vnet/ppp/ppp.h>
#include <vnet/hdlc/hdlc.h>
#include <vnet/util/throttle.h>

typedef struct
{
  u8 packet_data[64];
} ip4_input_trace_t;

static u8 *
format_ip4_input_trace (u8 * s, va_list * va)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*va, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*va, vlib_node_t *);
  ip4_input_trace_t *t = va_arg (*va, ip4_input_trace_t *);

  s = format (s, "%U",
	      format_ip4_header, t->packet_data, sizeof (t->packet_data));

  return s;
}

static_always_inline u32
ip4_input_set_next (u32 sw_if_index, vlib_buffer_t * b, int arc_enabled)
{
  ip4_main_t *im = &ip4_main;
  ip_lookup_main_t *lm = &im->lookup_main;
  u32 next;
  u8 arc;

  ip4_header_t *ip = vlib_buffer_get_current (b);

  if (PREDICT_FALSE (ip4_address_is_multicast (&ip->dst_address)))
    {
      next = IP4_INPUT_NEXT_LOOKUP_MULTICAST;
      arc = lm->mcast_feature_arc_index;
    }
  else
    {
      next = IP4_INPUT_NEXT_LOOKUP;
      arc = lm->ucast_feature_arc_index;
    }

  if (arc_enabled)
    vnet_feature_arc_start (arc, sw_if_index, &next, b);

  return next;
}

static_always_inline void
ip4_input_check_sw_if_index (vlib_main_t * vm,
			     vlib_simple_counter_main_t * cm, u32 sw_if_index,
			     u32 * last_sw_if_index, u32 * cnt,
			     int *arc_enabled)
{
  ip4_main_t *im = &ip4_main;
  ip_lookup_main_t *lm = &im->lookup_main;
  u32 thread_index;
  if (*last_sw_if_index == sw_if_index)
    {
      (*cnt)++;
      return;
    }

  thread_index = vm->thread_index;
  if (*cnt)
    vlib_increment_simple_counter (cm, thread_index, *last_sw_if_index, *cnt);
  *cnt = 1;
  *last_sw_if_index = sw_if_index;

  if (vnet_have_features (lm->ucast_feature_arc_index, sw_if_index) ||
      vnet_have_features (lm->mcast_feature_arc_index, sw_if_index))
    *arc_enabled = 1;
  else
    *arc_enabled = 0;
}

/* Validate IP v4 packets and pass them either to forwarding code
   or drop/punt exception packets. */
always_inline uword
ip4_input_inline (vlib_main_t * vm,
		  vlib_node_runtime_t * node,
		  vlib_frame_t * frame, int verify_checksum)
{
  vnet_main_t *vnm = vnet_get_main ();
  u32 n_left_from, *from;
  u32 thread_index = vm->thread_index;
  vlib_node_runtime_t *error_node =
    vlib_node_get_runtime (vm, ip4_input_node.index);
  vlib_simple_counter_main_t *cm;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  ip4_header_t *ip[4];
  u16 nexts[VLIB_FRAME_SIZE], *next;
  u32 sw_if_index[4];
  u32 last_sw_if_index = ~0;
  u32 cnt = 0;
  int arc_enabled = 0;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;

  if (node->flags & VLIB_NODE_FLAG_TRACE)
    vlib_trace_frame_buffers_only (vm, node, from, frame->n_vectors,
				   /* stride */ 1,
				   sizeof (ip4_input_trace_t));

  cm = vec_elt_at_index (vnm->interface_main.sw_if_counters,
			 VNET_INTERFACE_COUNTER_IP4);

  vlib_get_buffers (vm, from, bufs, n_left_from);
  b = bufs;
  next = nexts;
#if (CLIB_N_PREFETCHES >= 8)
  while (n_left_from >= 4)
    {
      u32 x = 0;

      /* Prefetch next iteration. */
      if (n_left_from >= 12)
	{
	  vlib_prefetch_buffer_header (b[8], LOAD);
	  vlib_prefetch_buffer_header (b[9], LOAD);
	  vlib_prefetch_buffer_header (b[10], LOAD);
	  vlib_prefetch_buffer_header (b[11], LOAD);

	  vlib_prefetch_buffer_data (b[4], LOAD);
	  vlib_prefetch_buffer_data (b[5], LOAD);
	  vlib_prefetch_buffer_data (b[6], LOAD);
	  vlib_prefetch_buffer_data (b[7], LOAD);
	}

      vnet_buffer (b[0])->ip.adj_index[VLIB_RX] = ~0;
      vnet_buffer (b[1])->ip.adj_index[VLIB_RX] = ~0;
      vnet_buffer (b[2])->ip.adj_index[VLIB_RX] = ~0;
      vnet_buffer (b[3])->ip.adj_index[VLIB_RX] = ~0;

      sw_if_index[0] = vnet_buffer (b[0])->sw_if_index[VLIB_RX];
      sw_if_index[1] = vnet_buffer (b[1])->sw_if_index[VLIB_RX];
      sw_if_index[2] = vnet_buffer (b[2])->sw_if_index[VLIB_RX];
      sw_if_index[3] = vnet_buffer (b[3])->sw_if_index[VLIB_RX];

      x |= sw_if_index[0] ^ last_sw_if_index;
      x |= sw_if_index[1] ^ last_sw_if_index;
      x |= sw_if_index[2] ^ last_sw_if_index;
      x |= sw_if_index[3] ^ last_sw_if_index;

      if (PREDICT_TRUE (x == 0))
	{
	  /* we deal with 4 more packets sharing the same sw_if_index
	     with the previous one, so we can optimize */
	  cnt += 4;
	  if (arc_enabled)
	    {
	      next[0] = ip4_input_set_next (sw_if_index[0], b[0], 1);
	      next[1] = ip4_input_set_next (sw_if_index[1], b[1], 1);
	      next[2] = ip4_input_set_next (sw_if_index[2], b[2], 1);
	      next[3] = ip4_input_set_next (sw_if_index[3], b[3], 1);
	    }
	  else
	    {
	      next[0] = ip4_input_set_next (sw_if_index[0], b[0], 0);
	      next[1] = ip4_input_set_next (sw_if_index[1], b[1], 0);
	      next[2] = ip4_input_set_next (sw_if_index[2], b[2], 0);
	      next[3] = ip4_input_set_next (sw_if_index[3], b[3], 0);
	    }
	}
      else
	{
	  ip4_input_check_sw_if_index (vm, cm, sw_if_index[0],
				       &last_sw_if_index, &cnt, &arc_enabled);
	  ip4_input_check_sw_if_index (vm, cm, sw_if_index[1],
				       &last_sw_if_index, &cnt, &arc_enabled);
	  ip4_input_check_sw_if_index (vm, cm, sw_if_index[2],
				       &last_sw_if_index, &cnt, &arc_enabled);
	  ip4_input_check_sw_if_index (vm, cm, sw_if_index[3],
				       &last_sw_if_index, &cnt, &arc_enabled);

	  next[0] = ip4_input_set_next (sw_if_index[0], b[0], 1);
	  next[1] = ip4_input_set_next (sw_if_index[1], b[1], 1);
	  next[2] = ip4_input_set_next (sw_if_index[2], b[2], 1);
	  next[3] = ip4_input_set_next (sw_if_index[3], b[3], 1);
	}

      ip[0] = vlib_buffer_get_current (b[0]);
      ip[1] = vlib_buffer_get_current (b[1]);
      ip[2] = vlib_buffer_get_current (b[2]);
      ip[3] = vlib_buffer_get_current (b[3]);

      ip4_input_check_x4 (vm, error_node, b, ip, next, verify_checksum);

      /* next */
      b += 4;
      next += 4;
      n_left_from -= 4;
    }
#elif (CLIB_N_PREFETCHES >= 4)
  while (n_left_from >= 2)
    {
      u32 x = 0;
      u32 next0, next1;

      /* Prefetch next iteration. */
      if (n_left_from >= 6)
	{
	  vlib_prefetch_buffer_header (b[4], LOAD);
	  vlib_prefetch_buffer_header (b[5], LOAD);

	  vlib_prefetch_buffer_data (b[2], LOAD);
	  vlib_prefetch_buffer_data (b[3], LOAD);
	}

      vnet_buffer (b[0])->ip.adj_index[VLIB_RX] = ~0;
      vnet_buffer (b[1])->ip.adj_index[VLIB_RX] = ~0;

      sw_if_index[0] = vnet_buffer (b[0])->sw_if_index[VLIB_RX];
      sw_if_index[1] = vnet_buffer (b[1])->sw_if_index[VLIB_RX];

      x |= sw_if_index[0] ^ last_sw_if_index;
      x |= sw_if_index[1] ^ last_sw_if_index;

      if (PREDICT_TRUE (x == 0))
	{
	  /* we deal with 2 more packets sharing the same sw_if_index
	     with the previous one, so we can optimize */
	  cnt += 2;
	  if (arc_enabled)
	    {
	      next0 = ip4_input_set_next (sw_if_index[0], b[0], 1);
	      next1 = ip4_input_set_next (sw_if_index[1], b[1], 1);
	    }
	  else
	    {
	      next0 = ip4_input_set_next (sw_if_index[0], b[0], 0);
	      next1 = ip4_input_set_next (sw_if_index[1], b[1], 0);
	    }
	}
      else
	{
	  ip4_input_check_sw_if_index (vm, cm, sw_if_index[0],
				       &last_sw_if_index, &cnt, &arc_enabled);
	  ip4_input_check_sw_if_index (vm, cm, sw_if_index[1],
				       &last_sw_if_index, &cnt, &arc_enabled);

	  next0 = ip4_input_set_next (sw_if_index[0], b[0], 1);
	  next1 = ip4_input_set_next (sw_if_index[1], b[1], 1);
	}

      ip[0] = vlib_buffer_get_current (b[0]);
      ip[1] = vlib_buffer_get_current (b[1]);

      ip4_input_check_x2 (vm, error_node, b[0], b[1], ip[0], ip[1],
			  &next0, &next1, verify_checksum);
      next[0] = (u16) next0;
      next[1] = (u16) next1;

      /* next */
      b += 2;
      next += 2;
      n_left_from -= 2;
    }
#endif

  while (n_left_from)
    {
      u32 next0;
      vnet_buffer (b[0])->ip.adj_index[VLIB_RX] = ~0;
      sw_if_index[0] = vnet_buffer (b[0])->sw_if_index[VLIB_RX];
      ip4_input_check_sw_if_index (vm, cm, sw_if_index[0], &last_sw_if_index,
				   &cnt, &arc_enabled);
      next0 = ip4_input_set_next (sw_if_index[0], b[0], arc_enabled);
      ip[0] = vlib_buffer_get_current (b[0]);
      ip4_input_check_x1 (vm, error_node, b[0], ip[0], &next0,
			  verify_checksum);
      next[0] = next0;

      /* next */
      b += 1;
      next += 1;
      n_left_from -= 1;
    }

  vlib_increment_simple_counter (cm, thread_index, last_sw_if_index, cnt);
  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);
  return frame->n_vectors;
}

/** \brief IPv4 input node.
    @node ip4-input

    This is the IPv4 input node: validates ip4 header checksums,
    verifies ip header lengths, discards pkts with expired TTLs,
    and sends pkts to the set of ip feature nodes configured on
    the rx interface.

    @param vm vlib_main_t corresponding to the current thread
    @param node vlib_node_runtime_t
    @param frame vlib_frame_t whose contents should be dispatched

    @par Graph mechanics: buffer metadata, next index usage

    @em Uses:
    - vnet_feature_config_main_t cm corresponding to each pkt's dst address unicast /
      multicast status.
    - <code>b->current_config_index</code> corresponding to each pkt's
      rx sw_if_index.
         - This sets the per-packet graph trajectory, ensuring that
           each packet visits the per-interface features in order.

    - <code>vnet_buffer(b)->sw_if_index[VLIB_RX]</code>
        - Indicates the @c sw_if_index value of the interface that the
	  packet was received on.

    @em Sets:
    - <code>vnet_buffer(b)->ip.adj_index[VLIB_TX]</code>
        - The lookup result adjacency index.

    <em>Next Indices:</em>
    - Dispatches pkts to the (first) feature node:
      <code> vnet_get_config_data (... &next0 ...); </code>
      or @c error-drop
*/
VLIB_NODE_FN (ip4_input_node) (vlib_main_t * vm, vlib_node_runtime_t * node,
			       vlib_frame_t * frame)
{
  return ip4_input_inline (vm, node, frame, /* verify_checksum */ 1);
}

VLIB_NODE_FN (ip4_input_no_checksum_node) (vlib_main_t * vm,
					   vlib_node_runtime_t * node,
					   vlib_frame_t * frame)
{
  return ip4_input_inline (vm, node, frame, /* verify_checksum */ 0);
}

#ifndef CLIB_MARCH_VARIANT
char *ip4_error_strings[] = {
#define _(sym,string) string,
  foreach_ip4_error
#undef _
};
#endif

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ip4_input_node) = {
  .name = "ip4-input",
  .vector_size = sizeof (u32),
  .protocol_hint = VLIB_NODE_PROTO_HINT_IP4,

  .n_errors = IP4_N_ERROR,
  .error_strings = ip4_error_strings,

  .n_next_nodes = IP4_INPUT_N_NEXT,
  .next_nodes = {
    [IP4_INPUT_NEXT_DROP] = "error-drop",
    [IP4_INPUT_NEXT_PUNT] = "error-punt",
    [IP4_INPUT_NEXT_OPTIONS] = "ip4-options",
    [IP4_INPUT_NEXT_LOOKUP] = "ip4-lookup",
    [IP4_INPUT_NEXT_LOOKUP_MULTICAST] = "ip4-mfib-forward-lookup",
    [IP4_INPUT_NEXT_ICMP_ERROR] = "ip4-icmp-error",
  },

  .format_buffer = format_ip4_header,
  .format_trace = format_ip4_input_trace,
};

VLIB_REGISTER_NODE (ip4_input_no_checksum_node) = {
  .name = "ip4-input-no-checksum",
  .vector_size = sizeof (u32),

  .sibling_of = "ip4-input",
  .format_buffer = format_ip4_header,
  .format_trace = format_ip4_input_trace,
};
/* *INDENT-ON* */

static clib_error_t *
ip4_init (vlib_main_t * vm)
{
  clib_error_t *error;

  ethernet_register_input_type (vm, ETHERNET_TYPE_IP4, ip4_input_node.index);
  ppp_register_input_protocol (vm, PPP_PROTOCOL_ip4, ip4_input_node.index);
  hdlc_register_input_protocol (vm, HDLC_PROTOCOL_ip4, ip4_input_node.index);

  {
    extern vlib_node_registration_t ip4_input_no_checksum_node;
    pg_node_t *pn;
    pn = pg_get_node (ip4_input_node.index);
    pn->unformat_edit = unformat_pg_ip4_header;
    pn = pg_get_node (ip4_input_no_checksum_node.index);
    pn->unformat_edit = unformat_pg_ip4_header;
  }

  if ((error = vlib_call_init_function (vm, ip4_cli_init)))
    return error;

  if ((error = vlib_call_init_function
       (vm, ip4_source_and_port_range_check_init)))
    return error;

  /* Set flow hash to something non-zero. */
  ip4_main.flow_hash_seed = 0xdeadbeef;

  /* Default TTL for packets we generate. */
  ip4_main.host_config.ttl = 64;

  return error;
}

VLIB_INIT_FUNCTION (ip4_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
