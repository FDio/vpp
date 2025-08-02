/*
 * Copyright (c) 2025 Cisco and/or its affiliates.
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

#include <vlib/vlib.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>

#include <ping/common.h>

ping_traceroute_main_t ping_traceroute_main;

typedef struct
{
  uword cli_process_node;
  u16 hash;
} reply_trace_t;

u8 *
format_reply_trace (u8 *s, va_list *va)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*va, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*va, vlib_node_t *);
  reply_trace_t *t = va_arg (*va, reply_trace_t *);

  s = format (s, "Reply received and");
  if (t->cli_process_node == CLI_UNKNOWN_NODE)
    s = format (s, " punted");
  else
    s = format (s, " sent to cli node %d", t->cli_process_node);
  s = format (s, " (hash %d)", t->hash);
  return s;
}

static u8 *
format_icmp_input_trace (u8 *s, va_list *va)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*va, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*va, vlib_node_t *);
  icmp_input_trace_t *t = va_arg (*va, icmp_input_trace_t *);

  s = format (s, "%U", format_ip4_header, t->packet_data,
	      sizeof (t->packet_data));

  return s;
}

static uword
ip4_icmp_echo_request (vlib_main_t *vm, vlib_node_runtime_t *node,
		       vlib_frame_t *frame)
{
  uword n_packets = frame->n_vectors;
  u32 *from, *to_next;
  u32 n_left_from, n_left_to_next, next;
  ip4_main_t *i4m = &ip4_main;
  u16 *fragment_ids, *fid;
  u8 host_config_ttl = i4m->host_config.ttl;

  from = vlib_frame_vector_args (frame);
  n_left_from = n_packets;
  next = node->cached_next_index;

  if (node->flags & VLIB_NODE_FLAG_TRACE)
    vlib_trace_frame_buffers_only (vm, node, from, frame->n_vectors,
				   /* stride */ 1,
				   sizeof (icmp_input_trace_t));

  /* Get random fragment IDs for replies. */
  fid = fragment_ids = clib_random_buffer_get_data (
    &vm->random_buffer, n_packets * sizeof (fragment_ids[0]));

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next, to_next, n_left_to_next);

      while (n_left_from > 2 && n_left_to_next > 2)
	{
	  vlib_buffer_t *p0, *p1;
	  ip4_header_t *ip0, *ip1;
	  icmp46_header_t *icmp0, *icmp1;
	  u32 bi0, src0, dst0;
	  u32 bi1, src1, dst1;
	  ip_csum_t sum0, sum1;

	  bi0 = to_next[0] = from[0];
	  bi1 = to_next[1] = from[1];

	  from += 2;
	  n_left_from -= 2;
	  to_next += 2;
	  n_left_to_next -= 2;

	  p0 = vlib_get_buffer (vm, bi0);
	  p1 = vlib_get_buffer (vm, bi1);
	  ip0 = vlib_buffer_get_current (p0);
	  ip1 = vlib_buffer_get_current (p1);
	  icmp0 = ip4_next_header (ip0);
	  icmp1 = ip4_next_header (ip1);

	  vnet_buffer (p0)->sw_if_index[VLIB_RX] =
	    vnet_main.local_interface_sw_if_index;
	  vnet_buffer (p1)->sw_if_index[VLIB_RX] =
	    vnet_main.local_interface_sw_if_index;

	  /* Update ICMP checksum. */
	  sum0 = icmp0->checksum;
	  sum1 = icmp1->checksum;

	  ASSERT (icmp0->type == ICMP4_echo_request);
	  ASSERT (icmp1->type == ICMP4_echo_request);
	  sum0 = ip_csum_update (sum0, ICMP4_echo_request, ICMP4_echo_reply,
				 icmp46_header_t, type);
	  sum1 = ip_csum_update (sum1, ICMP4_echo_request, ICMP4_echo_reply,
				 icmp46_header_t, type);
	  icmp0->type = ICMP4_echo_reply;
	  icmp1->type = ICMP4_echo_reply;

	  icmp0->checksum = ip_csum_fold (sum0);
	  icmp1->checksum = ip_csum_fold (sum1);

	  src0 = ip0->src_address.data_u32;
	  src1 = ip1->src_address.data_u32;
	  dst0 = ip0->dst_address.data_u32;
	  dst1 = ip1->dst_address.data_u32;

	  /* Swap source and destination address.
	     Does not change checksum. */
	  ip0->src_address.data_u32 = dst0;
	  ip1->src_address.data_u32 = dst1;
	  ip0->dst_address.data_u32 = src0;
	  ip1->dst_address.data_u32 = src1;

	  /* Update IP checksum. */
	  sum0 = ip0->checksum;
	  sum1 = ip1->checksum;

	  sum0 = ip_csum_update (sum0, ip0->ttl, host_config_ttl, ip4_header_t,
				 ttl);
	  sum1 = ip_csum_update (sum1, ip1->ttl, host_config_ttl, ip4_header_t,
				 ttl);
	  ip0->ttl = host_config_ttl;
	  ip1->ttl = host_config_ttl;

	  /* New fragment id. */
	  sum0 = ip_csum_update (sum0, ip0->fragment_id, fid[0], ip4_header_t,
				 fragment_id);
	  sum1 = ip_csum_update (sum1, ip1->fragment_id, fid[1], ip4_header_t,
				 fragment_id);
	  ip0->fragment_id = fid[0];
	  ip1->fragment_id = fid[1];
	  fid += 2;

	  ip0->checksum = ip_csum_fold (sum0);
	  ip1->checksum = ip_csum_fold (sum1);

	  ASSERT (ip4_header_checksum_is_valid (ip0));
	  ASSERT (ip4_header_checksum_is_valid (ip1));

	  p0->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;
	  p1->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;
	}

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  vlib_buffer_t *p0;
	  ip4_header_t *ip0;
	  icmp46_header_t *icmp0;
	  u32 bi0, src0, dst0;
	  ip_csum_t sum0;

	  bi0 = to_next[0] = from[0];

	  from += 1;
	  n_left_from -= 1;
	  to_next += 1;
	  n_left_to_next -= 1;

	  p0 = vlib_get_buffer (vm, bi0);
	  ip0 = vlib_buffer_get_current (p0);
	  icmp0 = ip4_next_header (ip0);

	  vnet_buffer (p0)->sw_if_index[VLIB_RX] =
	    vnet_main.local_interface_sw_if_index;

	  /* Update ICMP checksum. */
	  sum0 = icmp0->checksum;

	  ASSERT (icmp0->type == ICMP4_echo_request);
	  sum0 = ip_csum_update (sum0, ICMP4_echo_request, ICMP4_echo_reply,
				 icmp46_header_t, type);
	  icmp0->type = ICMP4_echo_reply;
	  icmp0->checksum = ip_csum_fold (sum0);

	  src0 = ip0->src_address.data_u32;
	  dst0 = ip0->dst_address.data_u32;
	  ip0->src_address.data_u32 = dst0;
	  ip0->dst_address.data_u32 = src0;

	  /* Update IP checksum. */
	  sum0 = ip0->checksum;

	  sum0 = ip_csum_update (sum0, ip0->ttl, host_config_ttl, ip4_header_t,
				 ttl);
	  ip0->ttl = host_config_ttl;

	  sum0 = ip_csum_update (sum0, ip0->fragment_id, fid[0], ip4_header_t,
				 fragment_id);
	  ip0->fragment_id = fid[0];
	  fid += 1;

	  ip0->checksum = ip_csum_fold (sum0);

	  ASSERT (ip4_header_checksum_is_valid (ip0));

	  p0->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;
	}

      vlib_put_next_frame (vm, node, next, n_left_to_next);
    }

  vlib_error_count (vm, ip4_icmp_input_node.index,
		    ICMP4_ERROR_ECHO_REPLIES_SENT, frame->n_vectors);

  return frame->n_vectors;
}

VLIB_REGISTER_NODE (ip4_icmp_echo_request_node,static) = {
  .function = ip4_icmp_echo_request,
  .name = "ip4-icmp-echo-request",
  .vector_size = sizeof (u32),
  .format_trace = format_icmp_input_trace,
  .n_next_nodes = 1,
  .next_nodes = {
    [0] = "ip4-load-balance",
  },
};

typedef enum
{
  ICMP6_ECHO_REQUEST_NEXT_LOOKUP,
  ICMP6_ECHO_REQUEST_NEXT_OUTPUT,
  ICMP6_ECHO_REQUEST_N_NEXT,
} icmp6_echo_request_next_t;

static uword
ip6_icmp_echo_request (vlib_main_t *vm, vlib_node_runtime_t *node,
		       vlib_frame_t *frame)
{
  u32 *from, *to_next;
  u32 n_left_from, n_left_to_next, next_index;
  ip6_main_t *im = &ip6_main;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  if (node->flags & VLIB_NODE_FLAG_TRACE)
    vlib_trace_frame_buffers_only (vm, node, from, frame->n_vectors,
				   /* stride */ 1,
				   sizeof (icmp6_input_trace_t));

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 2 && n_left_to_next > 2)
	{
	  vlib_buffer_t *p0, *p1;
	  ip6_header_t *ip0, *ip1;
	  icmp46_header_t *icmp0, *icmp1;
	  ip6_address_t tmp0, tmp1;
	  ip_csum_t sum0, sum1;
	  u32 bi0, bi1;
	  u32 fib_index0, fib_index1;
	  u32 next0 = ICMP6_ECHO_REQUEST_NEXT_LOOKUP;
	  u32 next1 = ICMP6_ECHO_REQUEST_NEXT_LOOKUP;

	  bi0 = to_next[0] = from[0];
	  bi1 = to_next[1] = from[1];

	  from += 2;
	  n_left_from -= 2;
	  to_next += 2;
	  n_left_to_next -= 2;

	  p0 = vlib_get_buffer (vm, bi0);
	  p1 = vlib_get_buffer (vm, bi1);
	  ip0 = vlib_buffer_get_current (p0);
	  ip1 = vlib_buffer_get_current (p1);
	  icmp0 = ip6_next_header (ip0);
	  icmp1 = ip6_next_header (ip1);

	  /* Check icmp type to echo reply and update icmp checksum. */
	  sum0 = icmp0->checksum;
	  sum1 = icmp1->checksum;

	  ASSERT (icmp0->type == ICMP6_echo_request);
	  ASSERT (icmp1->type == ICMP6_echo_request);
	  sum0 = ip_csum_update (sum0, ICMP6_echo_request, ICMP6_echo_reply,
				 icmp46_header_t, type);
	  sum1 = ip_csum_update (sum1, ICMP6_echo_request, ICMP6_echo_reply,
				 icmp46_header_t, type);

	  icmp0->checksum = ip_csum_fold (sum0);
	  icmp1->checksum = ip_csum_fold (sum1);

	  icmp0->type = ICMP6_echo_reply;
	  icmp1->type = ICMP6_echo_reply;

	  /* Swap source and destination address. */
	  tmp0 = ip0->src_address;
	  tmp1 = ip1->src_address;

	  ip0->src_address = ip0->dst_address;
	  ip1->src_address = ip1->dst_address;

	  ip0->dst_address = tmp0;
	  ip1->dst_address = tmp1;

	  /* New hop count. */
	  ip0->hop_limit = im->host_config.ttl;
	  ip1->hop_limit = im->host_config.ttl;

	  if (ip6_address_is_link_local_unicast (&ip0->src_address) &&
	      !ip6_address_is_link_local_unicast (&ip0->dst_address))
	    {
	      fib_index0 = vec_elt (im->fib_index_by_sw_if_index,
				    vnet_buffer (p0)->sw_if_index[VLIB_RX]);
	      vnet_buffer (p0)->sw_if_index[VLIB_TX] = fib_index0;
	    }
	  if (ip6_address_is_link_local_unicast (&ip1->src_address) &&
	      !ip6_address_is_link_local_unicast (&ip1->dst_address))
	    {
	      fib_index1 = vec_elt (im->fib_index_by_sw_if_index,
				    vnet_buffer (p1)->sw_if_index[VLIB_RX]);
	      vnet_buffer (p1)->sw_if_index[VLIB_TX] = fib_index1;
	    }
	  p0->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;
	  p1->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;

	  /* verify speculative enqueues, maybe switch current next frame */
	  /* if next0==next1==next_index then nothing special needs to be done
	   */
	  vlib_validate_buffer_enqueue_x2 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, bi1, next0,
					   next1);
	}

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  vlib_buffer_t *p0;
	  ip6_header_t *ip0;
	  icmp46_header_t *icmp0;
	  u32 bi0;
	  ip6_address_t tmp0;
	  ip_csum_t sum0;
	  u32 fib_index0;
	  u32 next0 = ICMP6_ECHO_REQUEST_NEXT_LOOKUP;

	  bi0 = to_next[0] = from[0];

	  from += 1;
	  n_left_from -= 1;
	  to_next += 1;
	  n_left_to_next -= 1;

	  p0 = vlib_get_buffer (vm, bi0);
	  ip0 = vlib_buffer_get_current (p0);
	  icmp0 = ip6_next_header (ip0);

	  /* Check icmp type to echo reply and update icmp checksum. */
	  sum0 = icmp0->checksum;

	  ASSERT (icmp0->type == ICMP6_echo_request);
	  sum0 = ip_csum_update (sum0, ICMP6_echo_request, ICMP6_echo_reply,
				 icmp46_header_t, type);

	  icmp0->checksum = ip_csum_fold (sum0);

	  icmp0->type = ICMP6_echo_reply;

	  /* Swap source and destination address. */
	  tmp0 = ip0->src_address;
	  ip0->src_address = ip0->dst_address;
	  ip0->dst_address = tmp0;

	  ip0->hop_limit = im->host_config.ttl;

	  if (ip6_address_is_link_local_unicast (&ip0->src_address) &&
	      !ip6_address_is_link_local_unicast (&ip0->dst_address))
	    {
	      /* if original packet was to the link local, then the
	       * fib index is that of the LL table, we can't use that
	       * to foward the response if the new destination
	       * is global, so reset to the fib index of the link.
	       * In other case, the fib index we need has been written
	       * to the buffer already. */
	      fib_index0 = vec_elt (im->fib_index_by_sw_if_index,
				    vnet_buffer (p0)->sw_if_index[VLIB_RX]);
	      vnet_buffer (p0)->sw_if_index[VLIB_TX] = fib_index0;
	    }
	  p0->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;
	  /* Verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_error_count (vm, ip6_icmp_input_node.index,
		    ICMP6_ERROR_ECHO_REPLIES_SENT, frame->n_vectors);

  return frame->n_vectors;
}

VLIB_REGISTER_NODE (ip6_icmp_echo_request_node,static) = {
  .function = ip6_icmp_echo_request,
  .name = "ip6-icmp-echo-request",
  .vector_size = sizeof (u32),
  .format_trace = format_icmp6_input_trace,
  .n_next_nodes = ICMP6_ECHO_REQUEST_N_NEXT,
  .next_nodes = {
    [ICMP6_ECHO_REQUEST_NEXT_LOOKUP] = "ip6-lookup",
    [ICMP6_ECHO_REQUEST_NEXT_OUTPUT] = "interface-output",
  },
};

static_always_inline uword
ip46_icmp_reply_node_fn (vlib_main_t *vm, vlib_node_runtime_t *node,
			 vlib_frame_t *frame, u8 icmp_type, int do_trace,
			 int is_ip6)
{
  u32 n_left_from, *from, *to_next;
  icmp46_reply_next_t next_index;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;

  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  /*
	   * The buffers (replies) are either posted to the CLI thread
	   * awaiting for them for subsequent analysis and disposal,
	   * or are sent to the punt node.
	   *
	   * So the only "next" node is a punt, normally.
	   */
	  u32 next0 = ICMP46_REPLY_NEXT_PUNT;

	  bi0 = from[0];
	  b0 = vlib_get_buffer (vm, bi0);
	  from += 1;
	  n_left_from -= 1;

	  uword cli_process_id = CLI_UNKNOWN_NODE;
	  u16 hash = ~0;

	  if (ip46_icmp_populate_vnet_cli_msg (vm, b0, icmp_type, is_ip6))
	    {
	      hash = vnet_buffer_cli_msg (b0)->hash;
	      cli_process_id = get_cli_process_id_by_hash (vm, hash);
	    }

	  if (cli_process_id != CLI_UNKNOWN_NODE)
	    {
	      /* Post the buffer to CLI thread. It will take care of freeing
	       * it. */
	      ip46_post_reply_event (vm, cli_process_id, bi0, is_ip6);
	    }
	  else
	    {
	      /* no outstanding requests for this reply, punt */
	      /* speculatively enqueue b0 to the current next frame */
	      to_next[0] = bi0;
	      to_next += 1;
	      n_left_to_next -= 1;
	      /* verify speculative enqueue, maybe switch current next frame
	       */
	      vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					       n_left_to_next, bi0, next0);
	    }

	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED) && do_trace)
	    {
	      reply_trace_t *tr = vlib_add_trace (vm, node, b0, sizeof (*tr));
	      tr->cli_process_node = cli_process_id;
	      tr->hash = hash;
	    }
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  return frame->n_vectors;
}

/*
 * select "with-trace" or "without-trace" codepaths upfront.
 */
static_always_inline uword
ip46_icmp_node_fn (vlib_main_t *vm, vlib_node_runtime_t *node,
		   vlib_frame_t *frame, u8 icmp_type, int is_ip6)
{
  if (node->flags & VLIB_NODE_FLAG_TRACE)
    return ip46_icmp_reply_node_fn (vm, node, frame, icmp_type,
				    1 /* do_trace */, is_ip6);
  else
    return ip46_icmp_reply_node_fn (vm, node, frame, icmp_type,
				    0 /* do_trace */, is_ip6);
}

#define ip_icmp_nodes_fn(_type, _v6)                                          \
  static uword ip##_v6##_icmp_##_type##_node_fn (                             \
    vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)          \
  {                                                                           \
    return ip46_icmp_node_fn (vm, node, frame, ICMP##_v6##_##_type,           \
			      (_v6) == 6 /* is_ip6 */);                       \
  }

#define ip46_icmp_nodes_fn(_type)                                             \
  ip_icmp_nodes_fn (_type, 4);                                                \
  ip_icmp_nodes_fn (_type, 6);

#define ip_icmp_node_registration(_type, _v6)                                 \
  VLIB_REGISTER_NODE (ip##_v6##_icmp_##_type##_node) = {             \
    .function = ip##_v6##_icmp_##_type##_node_fn,                                 \
    .name = "ip" #_v6 "-icmp-" #_type "-reply",                                    \
    .vector_size = sizeof (u32),                                              \
    .format_trace = format_reply_trace,                                   \
    .n_next_nodes = ICMP46_REPLY_N_NEXT,                                 \
    .next_nodes = {                                                           \
      [ICMP46_REPLY_NEXT_DROP] = "ip" #_v6 "-drop",                          \
      [ICMP46_REPLY_NEXT_PUNT] = "ip" #_v6 "-punt",                          \
    }, \
};

#define ip46_icmp_node_registration(_type)                                    \
  ip_icmp_node_registration (_type, 4);                                       \
  ip_icmp_node_registration (_type, 6);

#define __(_type)                                                             \
  ip46_icmp_nodes_fn (_type);                                                 \
  ip46_icmp_node_registration (_type)
foreach_icmp_type_reply
#undef __

  typedef enum {
    TCP_PUNTED_NEXT_DROP,
    TCP_PUNTED_N_NEXT,
  } tcp_punted_next_t;

static_always_inline uword
ip46_tcp_punted_node_fn (vlib_main_t *vm, vlib_node_runtime_t *node,
			 vlib_frame_t *frame, int do_trace, int is_ip6)
{
  u32 n_left_from, *from, *to_next;
  icmp46_reply_next_t next_index;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;

  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  u32 next0;
	  vlib_buffer_t *b0;
	  tcp_header_t *tcp0;
	  uword cli_process_id = CLI_UNKNOWN_NODE;
	  u16 hash = ~0;
	  u8 l4_proto;

	  bi0 = from[0];
	  b0 = vlib_get_buffer (vm, bi0);
	  from += 1;
	  n_left_from -= 1;
	  vnet_feature_next (&next0, b0);

	  if (is_ip6)
	    {
	      ip6_header_t *ip0 = vlib_buffer_get_current (b0);
	      l4_proto = ip0->protocol;
	      tcp0 = ip6_next_header (ip0);
	    }
	  else
	    {
	      ip4_header_t *ip0 = vlib_buffer_get_current (b0);
	      l4_proto = ip0->protocol;
	      tcp0 = ip4_next_header (ip0);
	    }

	  /* don't trace non-TCP packets */
	  if (PREDICT_FALSE (l4_proto != IP_PROTOCOL_TCP))
	    goto enqueue;

	  if (PREDICT_FALSE (!tcp_ack (tcp0) ||
			     !(tcp_syn (tcp0) || tcp_rst (tcp0))))

	    {
	      next0 = TCP_PUNTED_NEXT_DROP;
	      goto enqueue;
	    }

	  if (ip46_tcp_populate_vnet_cli_msg (vm, b0, tcp0))
	    {
	      hash = vnet_buffer_cli_msg (b0)->hash;
	      cli_process_id = get_cli_process_id_by_hash (vm, hash);
	    }

	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED) && do_trace)
	    {
	      reply_trace_t *tr = vlib_add_trace (vm, node, b0, sizeof (*tr));
	      tr->cli_process_node = cli_process_id;
	      tr->hash = hash;
	    }

	  if (cli_process_id == CLI_UNKNOWN_NODE)
	    goto enqueue;

	  /* Post the buffer to CLI thread. It will take care of freeing
	   * it. */
	  ip46_post_reply_event (vm, cli_process_id, bi0, is_ip6);
	  continue;

	enqueue:
	  /* no outstanding requests for this reply, punt */
	  /* speculatively enqueue b0 to the current next frame */
	  to_next[0] = bi0;
	  to_next += 1;
	  n_left_to_next -= 1;
	  /* verify speculative enqueue, maybe switch current next frame
	   */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  return frame->n_vectors;
}

/*
 * select "with-trace" or "without-trace" codepaths upfront.
 */
static_always_inline uword
ip46_tcp_punted_node_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
			     vlib_frame_t *frame, int is_ip6)
{
  if (node->flags & VLIB_NODE_FLAG_TRACE)
    return ip46_tcp_punted_node_fn (vm, node, frame, 1 /* do_trace */, is_ip6);
  else
    return ip46_tcp_punted_node_fn (vm, node, frame, 0 /* do_trace */, is_ip6);
}

static uword
ip4_tcp_punted_node_fn (vlib_main_t *vm, vlib_node_runtime_t *node,
			vlib_frame_t *frame)
{
  return ip46_tcp_punted_node_inline (vm, node, frame, 0 /* is_ip6 */);
}

static uword
ip6_tcp_punted_node_fn (vlib_main_t *vm, vlib_node_runtime_t *node,
			vlib_frame_t *frame)
{
  return ip46_tcp_punted_node_inline (vm, node, frame, 1 /* is_ip6 */);
}

VLIB_REGISTER_NODE (ip4_tcp_punted_node) = {
    .function = ip4_tcp_punted_node_fn,
    .name = "ip4-tcp-punted",
    .vector_size = sizeof (u32),
    .format_trace = format_reply_trace,
    .n_next_nodes = 1,
    .next_nodes = {
      [0] = "ip4-drop",
    },
};

VNET_FEATURE_INIT (ip4_tcp_punted, static) = {
  .arc_name = "ip4-punt",
  .node_name = "ip4-tcp-punted",
  .runs_before = VNET_FEATURES ("ip4-drop"),
};

VLIB_REGISTER_NODE (ip6_tcp_punted_node) = {
    .function = ip6_tcp_punted_node_fn,
    .name = "ip6-tcp-punted",
    .vector_size = sizeof (u32),
    .format_trace = format_reply_trace,
    .n_next_nodes = 1,
    .next_nodes = {
      [0] = "ip6-drop",
    },
};

VNET_FEATURE_INIT (ip6_tcp_punted, static) = {
  .arc_name = "ip6-punt",
  .node_name = "ip6-tcp-punted",
  .runs_before = VNET_FEATURES ("ip6-drop"),
};

static clib_error_t *
ping_traceroute_common_init (vlib_main_t *vm)
{
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  ping_traceroute_main_t *ptm = &ping_traceroute_main;

  if (tm->n_vlib_mains > 1)
    clib_spinlock_init (&ptm->run_check_lock);

#define __(_type)                                                             \
  ip4_icmp_register_type (vm, ICMP4_##_type, ip4_icmp_##_type##_node.index);  \
  icmp6_register_type (vm, ICMP6_##_type, ip6_icmp_##_type##_node.index);
  foreach_icmp_type_reply
#undef __

    ip4_icmp_register_type (vm, ICMP4_echo_request,
			    ip4_icmp_echo_request_node.index);
  icmp6_register_type (vm, ICMP6_echo_request,
		       ip6_icmp_echo_request_node.index);

  return 0;
}

VLIB_INIT_FUNCTION (ping_traceroute_common_init);

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "Ping & Traceroute (ping)",
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
