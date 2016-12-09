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
 * ip/ip6_input.c: IP v6 input node
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

#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ppp/ppp.h>
#include <vnet/hdlc/hdlc.h>

typedef struct
{
  u8 packet_data[64];
} ip6_input_trace_t;

static u8 *
format_ip6_input_trace (u8 * s, va_list * va)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*va, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*va, vlib_node_t *);
  ip6_input_trace_t *t = va_arg (*va, ip6_input_trace_t *);

  s = format (s, "%U",
	      format_ip6_header, t->packet_data, sizeof (t->packet_data));

  return s;
}

typedef enum
{
  IP6_INPUT_NEXT_DROP,
  IP6_INPUT_NEXT_LOOKUP,
  IP6_INPUT_NEXT_ICMP_ERROR,
  IP6_INPUT_N_NEXT,
} ip6_input_next_t;

/* Validate IP v6 packets and pass them either to forwarding code
   or drop exception packets. */
static uword
ip6_input (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  vnet_main_t *vnm = vnet_get_main ();
  ip6_main_t *im = &ip6_main;
  ip_lookup_main_t *lm = &im->lookup_main;
  u32 n_left_from, *from, *to_next;
  ip6_input_next_t next_index;
  vlib_node_runtime_t *error_node =
    vlib_node_get_runtime (vm, ip6_input_node.index);
  vlib_simple_counter_main_t *cm;
  u32 cpu_index = os_get_cpu_number ();

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  if (node->flags & VLIB_NODE_FLAG_TRACE)
    vlib_trace_frame_buffers_only (vm, node, from, frame->n_vectors,
				   /* stride */ 1,
				   sizeof (ip6_input_trace_t));

  cm = vec_elt_at_index (vnm->interface_main.sw_if_counters,
			 VNET_INTERFACE_COUNTER_IP6);

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
	  vlib_buffer_t *p0, *p1;
	  ip6_header_t *ip0, *ip1;
	  u32 pi0, sw_if_index0, next0 = 0;
	  u32 pi1, sw_if_index1, next1 = 0;
	  u8 error0, error1, arc0, arc1;

	  /* Prefetch next iteration. */
	  {
	    vlib_buffer_t *p2, *p3;

	    p2 = vlib_get_buffer (vm, from[2]);
	    p3 = vlib_get_buffer (vm, from[3]);

	    vlib_prefetch_buffer_header (p2, LOAD);
	    vlib_prefetch_buffer_header (p3, LOAD);

	    CLIB_PREFETCH (p2->data, sizeof (ip0[0]), LOAD);
	    CLIB_PREFETCH (p3->data, sizeof (ip1[0]), LOAD);
	  }

	  pi0 = from[0];
	  pi1 = from[1];

	  to_next[0] = pi0;
	  to_next[1] = pi1;
	  from += 2;
	  to_next += 2;
	  n_left_from -= 2;
	  n_left_to_next -= 2;

	  p0 = vlib_get_buffer (vm, pi0);
	  p1 = vlib_get_buffer (vm, pi1);

	  ip0 = vlib_buffer_get_current (p0);
	  ip1 = vlib_buffer_get_current (p1);

	  sw_if_index0 = vnet_buffer (p0)->sw_if_index[VLIB_RX];
	  sw_if_index1 = vnet_buffer (p1)->sw_if_index[VLIB_RX];

	  arc0 =
	    ip6_address_is_multicast (&ip0->dst_address) ?
	    lm->mcast_feature_arc_index : lm->ucast_feature_arc_index;
	  arc1 =
	    ip6_address_is_multicast (&ip1->dst_address) ?
	    lm->mcast_feature_arc_index : lm->ucast_feature_arc_index;

	  vnet_buffer (p0)->ip.adj_index[VLIB_RX] = ~0;
	  vnet_buffer (p1)->ip.adj_index[VLIB_RX] = ~0;

	  vnet_feature_arc_start (arc0, sw_if_index0, &next0, p0);
	  vnet_feature_arc_start (arc1, sw_if_index1, &next1, p1);

	  vlib_increment_simple_counter (cm, cpu_index, sw_if_index0, 1);
	  vlib_increment_simple_counter (cm, cpu_index, sw_if_index1, 1);

	  error0 = error1 = IP6_ERROR_NONE;

	  /* Version != 6?  Drop it. */
	  error0 =
	    (clib_net_to_host_u32
	     (ip0->ip_version_traffic_class_and_flow_label) >> 28) !=
	    6 ? IP6_ERROR_VERSION : error0;
	  error1 =
	    (clib_net_to_host_u32
	     (ip1->ip_version_traffic_class_and_flow_label) >> 28) !=
	    6 ? IP6_ERROR_VERSION : error1;

	  /* hop limit < 1? Drop it.  for link-local broadcast packets,
	   * like dhcpv6 packets from client has hop-limit 1, which should not
	   * be dropped.
	   */
	  error0 = ip0->hop_limit < 1 ? IP6_ERROR_TIME_EXPIRED : error0;
	  error1 = ip1->hop_limit < 1 ? IP6_ERROR_TIME_EXPIRED : error1;

	  /* L2 length must be at least minimal IP header. */
	  error0 =
	    p0->current_length <
	    sizeof (ip0[0]) ? IP6_ERROR_TOO_SHORT : error0;
	  error1 =
	    p1->current_length <
	    sizeof (ip1[0]) ? IP6_ERROR_TOO_SHORT : error1;

	  if (PREDICT_FALSE (error0 != IP6_ERROR_NONE))
	    {
	      if (error0 == IP6_ERROR_TIME_EXPIRED)
		{
		  icmp6_error_set_vnet_buffer (p0, ICMP6_time_exceeded,
					       ICMP6_time_exceeded_ttl_exceeded_in_transit,
					       0);
		  next0 = IP6_INPUT_NEXT_ICMP_ERROR;
		}
	      else
		{
		  next0 = IP6_INPUT_NEXT_DROP;
		}
	    }
	  if (PREDICT_FALSE (error1 != IP6_ERROR_NONE))
	    {
	      if (error1 == IP6_ERROR_TIME_EXPIRED)
		{
		  icmp6_error_set_vnet_buffer (p1, ICMP6_time_exceeded,
					       ICMP6_time_exceeded_ttl_exceeded_in_transit,
					       0);
		  next1 = IP6_INPUT_NEXT_ICMP_ERROR;
		}
	      else
		{
		  next1 = IP6_INPUT_NEXT_DROP;
		}
	    }

	  p0->error = error_node->errors[error0];
	  p1->error = error_node->errors[error1];

	  vlib_validate_buffer_enqueue_x2 (vm, node, next_index,
					   to_next, n_left_to_next,
					   pi0, pi1, next0, next1);
	}

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  vlib_buffer_t *p0;
	  ip6_header_t *ip0;
	  u32 pi0, sw_if_index0, next0 = 0;
	  u8 error0, arc0;

	  pi0 = from[0];
	  to_next[0] = pi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  p0 = vlib_get_buffer (vm, pi0);
	  ip0 = vlib_buffer_get_current (p0);

	  sw_if_index0 = vnet_buffer (p0)->sw_if_index[VLIB_RX];
	  arc0 =
	    ip6_address_is_multicast (&ip0->dst_address) ?
	    lm->mcast_feature_arc_index : lm->ucast_feature_arc_index;
	  vnet_buffer (p0)->ip.adj_index[VLIB_RX] = ~0;
	  vnet_feature_arc_start (arc0, sw_if_index0, &next0, p0);

	  vlib_increment_simple_counter (cm, cpu_index, sw_if_index0, 1);
	  error0 = IP6_ERROR_NONE;

	  /* Version != 6?  Drop it. */
	  error0 =
	    (clib_net_to_host_u32
	     (ip0->ip_version_traffic_class_and_flow_label) >> 28) !=
	    6 ? IP6_ERROR_VERSION : error0;

	  /* hop limit < 1? Drop it. for link-local broadcast packets,
	   * like dhcpv6 packets from client has hop-limit 1, which should not
	   * be dropped.
	   */
	  error0 = ip0->hop_limit < 1 ? IP6_ERROR_TIME_EXPIRED : error0;

	  /* L2 length must be at least minimal IP header. */
	  error0 =
	    p0->current_length <
	    sizeof (ip0[0]) ? IP6_ERROR_TOO_SHORT : error0;

	  if (PREDICT_FALSE (error0 != IP6_ERROR_NONE))
	    {
	      if (error0 == IP6_ERROR_TIME_EXPIRED)
		{
		  icmp6_error_set_vnet_buffer (p0, ICMP6_time_exceeded,
					       ICMP6_time_exceeded_ttl_exceeded_in_transit,
					       0);
		  next0 = IP6_INPUT_NEXT_ICMP_ERROR;
		}
	      else
		{
		  next0 = IP6_INPUT_NEXT_DROP;
		}
	    }
	  p0->error = error_node->errors[error0];

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   pi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

static char *ip6_error_strings[] = {
#define _(sym,string) string,
  foreach_ip6_error
#undef _
};

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ip6_input_node) = {
  .function = ip6_input,
  .name = "ip6-input",
  .vector_size = sizeof (u32),

  .n_errors = IP6_N_ERROR,
  .error_strings = ip6_error_strings,

  .n_next_nodes = IP6_INPUT_N_NEXT,
  .next_nodes = {
    [IP6_INPUT_NEXT_DROP] = "error-drop",
    [IP6_INPUT_NEXT_LOOKUP] = "ip6-lookup",
    [IP6_INPUT_NEXT_ICMP_ERROR] = "ip6-icmp-error",
  },

  .format_buffer = format_ip6_header,
  .format_trace = format_ip6_input_trace,
};
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (ip6_input_node, ip6_input)
     static clib_error_t *ip6_init (vlib_main_t * vm)
{
  ethernet_register_input_type (vm, ETHERNET_TYPE_IP6, ip6_input_node.index);
  ppp_register_input_protocol (vm, PPP_PROTOCOL_ip6, ip6_input_node.index);
  hdlc_register_input_protocol (vm, HDLC_PROTOCOL_ip6, ip6_input_node.index);

  {
    pg_node_t *pn;
    pn = pg_get_node (ip6_input_node.index);
    pn->unformat_edit = unformat_pg_ip6_header;
  }

  /* Set flow hash to something non-zero. */
  ip6_main.flow_hash_seed = 0xdeadbeef;

  /* Default hop limit for packets we generate. */
  ip6_main.host_config.ttl = 64;

  return /* no error */ 0;
}

VLIB_INIT_FUNCTION (ip6_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
