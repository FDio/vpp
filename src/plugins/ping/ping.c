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

#include <stddef.h>

#include <vlib/vlib.h>
#include <vnet/fib/ip6_fib.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/fib/fib_entry.h>
#include <vnet/ip/ip6_link.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>

#include <vnet/ip/icmp4.h>
#include <ping/ping.h>

ping_main_t ping_main;

/**
 * @file
 * @brief IPv4 and IPv6 ICMP Ping.
 *
 * This file contains code to support IPv4 or IPv6 ICMP ECHO_REQUEST to
 * network hosts.
 *
 */

typedef struct
{
  u16 id;
  u16 seq;
  u32 cli_process_node;
  u8 is_ip6;
} icmp_echo_trace_t;


u8 *
format_icmp_echo_trace (u8 * s, va_list * va)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*va, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*va, vlib_node_t *);
  icmp_echo_trace_t *t = va_arg (*va, icmp_echo_trace_t *);

  s =
    format (s, "ICMP%s echo id %d seq %d", t->is_ip6 ? "6" : "4", t->id,
	    t->seq);
  if (t->cli_process_node == PING_CLI_UNKNOWN_NODE)
    {
      s = format (s, " (unknown)");
    }
  else
    {
      s = format (s, " send to cli node %d", t->cli_process_node);
    }

  return s;
}


static u8 *
format_ip46_ping_result (u8 * s, va_list * args)
{
  send_ip46_ping_result_t res = va_arg (*args, send_ip46_ping_result_t);

  switch (res)
    {
#define _(v, n) case SEND_PING_##v: s = format(s, "%s", n);break;
      foreach_ip46_ping_result
#undef _
    }

  return (s);
}


/*
 * Poor man's get-set-clear functions
 * for manipulation of icmp_id -> cli_process_id
 * mappings.
 *
 * There should normally be very few (0..1..2) of these
 * mappings, so the linear search is a good strategy.
 *
 * Make them thread-safe via a simple spinlock.
 *
 */


static_always_inline uword
get_cli_process_id_by_icmp_id_mt (vlib_main_t * vm, u16 icmp_id)
{
  ping_main_t *pm = &ping_main;
  uword cli_process_id = PING_CLI_UNKNOWN_NODE;
  ping_run_t *pr;

  clib_spinlock_lock_if_init (&pm->ping_run_check_lock);
  vec_foreach (pr, pm->active_ping_runs)
  {
    if (pr->icmp_id == icmp_id)
      {
	cli_process_id = pr->cli_process_id;
	break;
      }
  }
  clib_spinlock_unlock_if_init (&pm->ping_run_check_lock);
  return cli_process_id;
}


static_always_inline void
set_cli_process_id_by_icmp_id_mt (vlib_main_t * vm, u16 icmp_id,
				  uword cli_process_id)
{
  ping_main_t *pm = &ping_main;
  ping_run_t *pr;

  clib_spinlock_lock_if_init (&pm->ping_run_check_lock);
  vec_foreach (pr, pm->active_ping_runs)
  {
    if (pr->icmp_id == icmp_id)
      {
	pr->cli_process_id = cli_process_id;
	goto have_found_and_set;
      }
  }
  /* no such key yet - add a new one */
  ping_run_t new_pr = {.icmp_id = icmp_id,.cli_process_id = cli_process_id };
  vec_add1 (pm->active_ping_runs, new_pr);
have_found_and_set:
  clib_spinlock_unlock_if_init (&pm->ping_run_check_lock);
}


static_always_inline void
clear_cli_process_id_by_icmp_id_mt (vlib_main_t * vm, u16 icmp_id)
{
  ping_main_t *pm = &ping_main;
  ping_run_t *pr;

  clib_spinlock_lock_if_init (&pm->ping_run_check_lock);
  vec_foreach (pr, pm->active_ping_runs)
  {
    if (pr->icmp_id == icmp_id)
      {
	vec_del1 (pm->active_ping_runs, pm->active_ping_runs - pr);
	break;
      }
  }
  clib_spinlock_unlock_if_init (&pm->ping_run_check_lock);
}

static_always_inline int
ip46_get_icmp_id_and_seq (vlib_main_t * vm, vlib_buffer_t * b0,
			  u16 * out_icmp_id, u16 * out_icmp_seq, int is_ip6)
{
  int l4_offset;
  if (is_ip6)
    {
      ip6_header_t *ip6 = vlib_buffer_get_current (b0);
      if (ip6->protocol != IP_PROTOCOL_ICMP6)
	{
	  return 0;
	}
      l4_offset = sizeof (*ip6);	// IPv6 EH
    }
  else
    {
      ip4_header_t *ip4 = vlib_buffer_get_current (b0);
      l4_offset = ip4_header_bytes (ip4);

    }
  icmp46_header_t *icmp46 = vlib_buffer_get_current (b0) + l4_offset;
  icmp46_echo_request_t *icmp46_echo = (icmp46_echo_request_t *) (icmp46 + 1);

  *out_icmp_id = clib_net_to_host_u16 (icmp46_echo->id);
  *out_icmp_seq = clib_net_to_host_u16 (icmp46_echo->seq);
  return 1;
}

/*
 * post the buffer to a given cli process node - the caller should forget bi0 after return.
 */

static_always_inline void
ip46_post_icmp_reply_event (vlib_main_t * vm, uword cli_process_id, u32 bi0,
			    int is_ip6)
{
  vlib_buffer_t *b0 = vlib_get_buffer (vm, bi0);
  u64 nowts = clib_cpu_time_now ();

  /* Pass the timestamp to the cli_process thanks to the vnet_buffer unused metadata field */

  /* Camping on unused data... just ensure statically that there is enough space */
  STATIC_ASSERT (ARRAY_LEN (vnet_buffer (b0)->unused) *
		 sizeof (vnet_buffer (b0)->unused[0]) > sizeof (nowts),
		 "ping reply timestamp fits within remaining space of vnet_buffer unused data");
  u64 *pnowts = (void *) &vnet_buffer (b0)->unused[0];
  *pnowts = nowts;

  u32 event_id = is_ip6 ? PING_RESPONSE_IP6 : PING_RESPONSE_IP4;
  vlib_process_signal_event_mt (vm, cli_process_id, event_id, bi0);
}


static_always_inline void
ip46_echo_reply_maybe_trace_buffer (vlib_main_t * vm,
				    vlib_node_runtime_t * node,
				    uword cli_process_id, u16 id, u16 seq,
				    vlib_buffer_t * b0, int is_ip6)
{
  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
    {
      icmp_echo_trace_t *tr = vlib_add_trace (vm, node, b0, sizeof (*tr));
      tr->id = id;
      tr->seq = seq;
      tr->cli_process_node = cli_process_id;
      tr->is_ip6 = is_ip6;
    }
}


static_always_inline uword
ip46_icmp_echo_reply_inner_node_fn (vlib_main_t * vm,
				    vlib_node_runtime_t * node,
				    vlib_frame_t * frame, int do_trace,
				    int is_ip6)
{
  u32 n_left_from, *from, *to_next;
  icmp46_echo_reply_next_t next_index;

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
	  u32 next0 = ICMP46_ECHO_REPLY_NEXT_PUNT;

	  bi0 = from[0];
	  b0 = vlib_get_buffer (vm, bi0);
	  from += 1;
	  n_left_from -= 1;

	  u16 icmp_id = ~0;
	  u16 icmp_seq = ~0;
	  uword cli_process_id = PING_CLI_UNKNOWN_NODE;

	  if (ip46_get_icmp_id_and_seq (vm, b0, &icmp_id, &icmp_seq, is_ip6))
	    {
	      cli_process_id = get_cli_process_id_by_icmp_id_mt (vm, icmp_id);
	    }

	  if (do_trace)
	    ip46_echo_reply_maybe_trace_buffer (vm, node, cli_process_id,
						icmp_id, icmp_seq, b0,
						is_ip6);

	  if (~0 == cli_process_id)
	    {
	      /* no outstanding requests for this reply, punt */
	      /* speculatively enqueue b0 to the current next frame */
	      to_next[0] = bi0;
	      to_next += 1;
	      n_left_to_next -= 1;
	      /* verify speculative enqueue, maybe switch current next frame */
	      vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					       to_next, n_left_to_next,
					       bi0, next0);
	    }
	  else
	    {
	      /* Post the buffer to CLI thread. It will take care of freeing it. */
	      ip46_post_icmp_reply_event (vm, cli_process_id, bi0, is_ip6);
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
ip46_icmp_echo_reply_outer_node_fn (vlib_main_t * vm,
				    vlib_node_runtime_t * node,
				    vlib_frame_t * frame, int is_ip6)
{
  if (node->flags & VLIB_NODE_FLAG_TRACE)
    return ip46_icmp_echo_reply_inner_node_fn (vm, node, frame,
					       1 /* do_trace */ , is_ip6);
  else
    return ip46_icmp_echo_reply_inner_node_fn (vm, node, frame,
					       0 /* do_trace */ , is_ip6);
}

static uword
ip4_icmp_echo_reply_node_fn (vlib_main_t * vm,
			     vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return ip46_icmp_echo_reply_outer_node_fn (vm, node, frame,
					     0 /* is_ip6 */ );
}

static uword
ip6_icmp_echo_reply_node_fn (vlib_main_t * vm,
			     vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return ip46_icmp_echo_reply_outer_node_fn (vm, node, frame,
					     1 /* is_ip6 */ );
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ip6_icmp_echo_reply_node, static) =
{
  .function = ip6_icmp_echo_reply_node_fn,
  .name = "ip6-icmp-echo-reply",
  .vector_size = sizeof (u32),
  .format_trace = format_icmp_echo_trace,
  .n_next_nodes = ICMP46_ECHO_REPLY_N_NEXT,
  .next_nodes = {
    [ICMP46_ECHO_REPLY_NEXT_DROP] = "ip6-drop",
    [ICMP46_ECHO_REPLY_NEXT_PUNT] = "ip6-punt",
  },
};

VLIB_REGISTER_NODE (ip4_icmp_echo_reply_node, static) =
{
  .function = ip4_icmp_echo_reply_node_fn,
  .name = "ip4-icmp-echo-reply",
  .vector_size = sizeof (u32),
  .format_trace = format_icmp_echo_trace,
  .n_next_nodes = ICMP46_ECHO_REPLY_N_NEXT,
  .next_nodes = {
    [ICMP46_ECHO_REPLY_NEXT_DROP] = "ip4-drop",
    [ICMP46_ECHO_REPLY_NEXT_PUNT] = "ip4-punt",
  },
};
/* *INDENT-ON* */

static uword
ip4_icmp_echo_request (vlib_main_t * vm,
		       vlib_node_runtime_t * node, vlib_frame_t * frame)
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
  fid = fragment_ids = clib_random_buffer_get_data (&vm->random_buffer,
						    n_packets *
						    sizeof (fragment_ids[0]));

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

	  if (~0 == vnet_buffer (p0)->sw_if_index[VLIB_TX])
	    vnet_buffer (p0)->sw_if_index[VLIB_TX] =
	      ip4_fib_table_get_index_for_sw_if_index (vnet_buffer
						       (p0)->sw_if_index
						       [VLIB_RX]);
	  if (~0 == vnet_buffer (p1)->sw_if_index[VLIB_TX])
	    vnet_buffer (p1)->sw_if_index[VLIB_TX] =
	      ip4_fib_table_get_index_for_sw_if_index (vnet_buffer
						       (p1)->sw_if_index
						       [VLIB_RX]);
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

	  sum0 = ip_csum_update (sum0, ip0->ttl, host_config_ttl,
				 ip4_header_t, ttl);
	  sum1 = ip_csum_update (sum1, ip1->ttl, host_config_ttl,
				 ip4_header_t, ttl);
	  ip0->ttl = host_config_ttl;
	  ip1->ttl = host_config_ttl;

	  /* New fragment id. */
	  sum0 = ip_csum_update (sum0, ip0->fragment_id, fid[0],
				 ip4_header_t, fragment_id);
	  sum1 = ip_csum_update (sum1, ip1->fragment_id, fid[1],
				 ip4_header_t, fragment_id);
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

	  if (~0 == vnet_buffer (p0)->sw_if_index[VLIB_TX])
	    vnet_buffer (p0)->sw_if_index[VLIB_TX] =
	      ip4_fib_table_get_index_for_sw_if_index (vnet_buffer
						       (p0)->sw_if_index
						       [VLIB_RX]);
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

	  sum0 = ip_csum_update (sum0, ip0->ttl, host_config_ttl,
				 ip4_header_t, ttl);
	  ip0->ttl = host_config_ttl;

	  sum0 = ip_csum_update (sum0, ip0->fragment_id, fid[0],
				 ip4_header_t, fragment_id);
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

static u8 *
format_icmp_input_trace (u8 * s, va_list * va)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*va, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*va, vlib_node_t *);
  icmp_input_trace_t *t = va_arg (*va, icmp_input_trace_t *);

  s = format (s, "%U",
	      format_ip4_header, t->packet_data, sizeof (t->packet_data));

  return s;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ip4_icmp_echo_request_node,static) = {
  .function = ip4_icmp_echo_request,
  .name = "ip4-icmp-echo-request",

  .vector_size = sizeof (u32),

  .format_trace = format_icmp_input_trace,

  .n_next_nodes = 1,
  .next_nodes = {
    [0] = "ip4-lookup",
  },
};
/* *INDENT-ON* */

/*
 * A swarm of address-family agnostic helper functions
 * for building and sending the ICMP echo request.
 *
 * Deliberately mostly "static" rather than "static inline"
 * so one can trace them sanely if needed in debugger, if needed.
 *
 */

static_always_inline u8
get_icmp_echo_payload_byte (int offset)
{
  return (offset % 256);
}

/* Fill in the ICMP ECHO structure, return the safety-checked and possibly shrunk data_len */
static u16
init_icmp46_echo_request (vlib_main_t * vm, vlib_buffer_t * b0,
			  int l4_header_offset,
			  icmp46_echo_request_t * icmp46_echo, u16 seq_host,
			  u16 id_host, u64 now, u16 data_len)
{
  int i;


  int l34_len =
    l4_header_offset + sizeof (icmp46_header_t) +
    offsetof (icmp46_echo_request_t, data);
  int max_data_len = vlib_buffer_get_default_data_size (vm) - l34_len;

  int first_buf_data_len = data_len < max_data_len ? data_len : max_data_len;

  int payload_offset = 0;
  for (i = 0; i < first_buf_data_len; i++)
    icmp46_echo->data[i] = get_icmp_echo_payload_byte (payload_offset++);

  /* inspired by vlib_buffer_add_data */
  vlib_buffer_t *hb = b0;
  int remaining_data_len = data_len - first_buf_data_len;
  while (remaining_data_len)
    {
      int this_buf_data_len =
	remaining_data_len <
	vlib_buffer_get_default_data_size (vm) ? remaining_data_len :
	vlib_buffer_get_default_data_size (vm);
      int n_alloc = vlib_buffer_alloc (vm, &b0->next_buffer, 1);
      if (n_alloc < 1)
	{
	  /* That is how much we have so far - return it... */
	  return (data_len - remaining_data_len);
	}
      b0->flags |= VLIB_BUFFER_NEXT_PRESENT;
      /* move on to the newly acquired buffer */
      b0 = vlib_get_buffer (vm, b0->next_buffer);
      /* initialize the data */
      for (i = 0; i < this_buf_data_len; i++)
	{
	  b0->data[i] = get_icmp_echo_payload_byte (payload_offset++);
	}
      b0->current_length = this_buf_data_len;
      b0->current_data = 0;
      remaining_data_len -= this_buf_data_len;
    }
  hb->flags |= VLIB_BUFFER_TOTAL_LENGTH_VALID;
  hb->current_length = l34_len + first_buf_data_len;
  hb->total_length_not_including_first_buffer = data_len - first_buf_data_len;

  icmp46_echo->time_sent = now;
  icmp46_echo->seq = clib_host_to_net_u16 (seq_host);
  icmp46_echo->id = clib_host_to_net_u16 (id_host);
  return data_len;
}


static u32
ip46_fib_index_from_table_id (u32 table_id, int is_ip6)
{
  u32 fib_index = is_ip6 ?
    ip6_fib_index_from_table_id (table_id) :
    ip4_fib_index_from_table_id (table_id);
  return fib_index;
}

static fib_node_index_t
ip46_fib_table_lookup_host (u32 fib_index, ip46_address_t * pa46, int is_ip6)
{
  fib_node_index_t fib_entry_index = is_ip6 ?
    ip6_fib_table_lookup (fib_index, &pa46->ip6, 128) :
    ip4_fib_table_lookup (ip4_fib_get (fib_index), &pa46->ip4, 32);
  return fib_entry_index;
}

static u32
ip46_get_resolving_interface (u32 fib_index, ip46_address_t * pa46,
			      int is_ip6)
{
  u32 sw_if_index = ~0;
  if (~0 != fib_index)
    {
      fib_node_index_t fib_entry_index;
      fib_entry_index = ip46_fib_table_lookup_host (fib_index, pa46, is_ip6);
      sw_if_index = fib_entry_get_resolving_interface (fib_entry_index);
    }
  return sw_if_index;
}

static u32
ip46_fib_table_get_index_for_sw_if_index (u32 sw_if_index, int is_ip6)
{
  u32 fib_table_index = is_ip6 ?
    ip6_fib_table_get_index_for_sw_if_index (sw_if_index) :
    ip4_fib_table_get_index_for_sw_if_index (sw_if_index);
  return fib_table_index;

}


static int
ip46_fill_l3_header (ip46_address_t * pa46, vlib_buffer_t * b0, int is_ip6)
{
  if (is_ip6)
    {
      ip6_header_t *ip6 = vlib_buffer_get_current (b0);
      /* Fill in ip6 header fields */
      ip6->ip_version_traffic_class_and_flow_label =
	clib_host_to_net_u32 (0x6 << 28);
      ip6->payload_length = 0;	/* will be set later */
      ip6->protocol = IP_PROTOCOL_ICMP6;
      ip6->hop_limit = 255;
      ip6->dst_address = pa46->ip6;
      ip6->src_address = pa46->ip6;
      return (sizeof (ip6_header_t));
    }
  else
    {
      ip4_header_t *ip4 = vlib_buffer_get_current (b0);
      /* Fill in ip4 header fields */
      ip4->checksum = 0;
      ip4->ip_version_and_header_length = 0x45;
      ip4->tos = 0;
      ip4->length = 0;		/* will be set later */
      ip4->fragment_id = 0;
      ip4->flags_and_fragment_offset = 0;
      ip4->ttl = 0xff;
      ip4->protocol = IP_PROTOCOL_ICMP;
      ip4->src_address = pa46->ip4;
      ip4->dst_address = pa46->ip4;
      return (sizeof (ip4_header_t));
    }
}

static int
ip46_set_src_address (u32 sw_if_index, vlib_buffer_t * b0, int is_ip6)
{
  int res;
  if (is_ip6)
    {
      ip6_header_t *ip6 = vlib_buffer_get_current (b0);
      res = ip6_src_address_for_packet (sw_if_index,
					&ip6->dst_address, &ip6->src_address);
    }
  else
    {
      ip4_main_t *im = &ip4_main;
      ip4_header_t *ip4 = vlib_buffer_get_current (b0);
      res = ip4_src_address_for_packet (&im->lookup_main,
					sw_if_index, &ip4->src_address);
      /* IP4 and IP6 paths have the inverse logic. Harmonize. */
      res = !res;
    }
  return res;
}

static void
ip46_print_buffer_src_address (vlib_main_t * vm, vlib_buffer_t * b0,
			       int is_ip6)
{
  void *format_addr_func;
  void *paddr;
  if (is_ip6)
    {
      ip6_header_t *ip6 = vlib_buffer_get_current (b0);
      format_addr_func = format_ip6_address;
      paddr = &ip6->src_address;
    }
  else
    {
      ip4_header_t *ip4 = vlib_buffer_get_current (b0);
      format_addr_func = format_ip4_address;
      paddr = &ip4->src_address;
    }
  vlib_cli_output (vm, "Source address: %U ", format_addr_func, paddr);
}

static u16
ip46_fill_icmp_request_at (vlib_main_t * vm, int l4_offset, u16 seq_host,
			   u16 id_host, u16 data_len, vlib_buffer_t * b0,
			   int is_ip6)
{
  icmp46_header_t *icmp46 = vlib_buffer_get_current (b0) + l4_offset;

  icmp46->type = is_ip6 ? ICMP6_echo_request : ICMP4_echo_request;
  icmp46->code = 0;
  icmp46->checksum = 0;

  icmp46_echo_request_t *icmp46_echo = (icmp46_echo_request_t *) (icmp46 + 1);

  data_len =
    init_icmp46_echo_request (vm, b0, l4_offset, icmp46_echo, seq_host,
			      id_host, clib_cpu_time_now (), data_len);
  return data_len;
}


/* Compute ICMP4 checksum with multibuffer support. */
u16
ip4_icmp_compute_checksum (vlib_main_t * vm, vlib_buffer_t * p0,
			   ip4_header_t * ip0)
{
  ip_csum_t sum0;
  u32 ip_header_length, payload_length_host_byte_order;
  u32 n_this_buffer, n_bytes_left, n_ip_bytes_this_buffer;
  u16 sum16;
  void *data_this_buffer;

  ip_header_length = ip4_header_bytes (ip0);
  payload_length_host_byte_order =
    clib_net_to_host_u16 (ip0->length) - ip_header_length;

  /* ICMP4 checksum does not include the IP header */
  sum0 = 0;

  n_bytes_left = n_this_buffer = payload_length_host_byte_order;
  data_this_buffer = (void *) ip0 + ip_header_length;
  n_ip_bytes_this_buffer =
    p0->current_length - (((u8 *) ip0 - p0->data) - p0->current_data);
  if (n_this_buffer + ip_header_length > n_ip_bytes_this_buffer)
    {
      n_this_buffer = n_ip_bytes_this_buffer > ip_header_length ?
	n_ip_bytes_this_buffer - ip_header_length : 0;
    }
  while (1)
    {
      sum0 = ip_incremental_checksum (sum0, data_this_buffer, n_this_buffer);
      n_bytes_left -= n_this_buffer;
      if (n_bytes_left == 0)
	break;

      ASSERT (p0->flags & VLIB_BUFFER_NEXT_PRESENT);
      p0 = vlib_get_buffer (vm, p0->next_buffer);
      data_this_buffer = vlib_buffer_get_current (p0);
      n_this_buffer = p0->current_length;
    }

  sum16 = ~ip_csum_fold (sum0);

  return sum16;
}


static void
ip46_fix_len_and_csum (vlib_main_t * vm, int l4_offset, u16 data_len,
		       vlib_buffer_t * b0, int is_ip6)
{
  u16 payload_length =
    data_len + sizeof (icmp46_header_t) + offsetof (icmp46_echo_request_t,
						    data);
  u16 total_length = payload_length + l4_offset;
  icmp46_header_t *icmp46 = vlib_buffer_get_current (b0) + l4_offset;
  icmp46->checksum = 0;

  if (is_ip6)
    {
      ip6_header_t *ip6 = vlib_buffer_get_current (b0);
      ip6->payload_length = clib_host_to_net_u16 (payload_length);

      int bogus_length = 0;
      icmp46->checksum =
	ip6_tcp_udp_icmp_compute_checksum (vm, b0, ip6, &bogus_length);
    }
  else
    {
      ip4_header_t *ip4 = vlib_buffer_get_current (b0);
      ip4->length = clib_host_to_net_u16 (total_length);

      ip4->checksum = ip4_header_checksum (ip4);
      icmp46->checksum = ip4_icmp_compute_checksum (vm, b0, ip4);
    }
}

static u16
at_most_a_frame (u32 count)
{
  return count > VLIB_FRAME_SIZE ? VLIB_FRAME_SIZE : count;
}

static int
ip46_enqueue_packet (vlib_main_t * vm, vlib_buffer_t * b0, u32 burst,
		     int is_ip6)
{
  vlib_frame_t *f = 0;
  u32 lookup_node_index =
    is_ip6 ? ip6_lookup_node.index : ip4_lookup_node.index;
  int n_sent = 0;

  u16 n_to_send;

  /*
   * Enqueue the packet, possibly as one or more frames of copies to make
   * bursts. We enqueue b0 as the very last buffer, when there is no possibility
   * for error in vlib_buffer_copy, so as to allow the caller to free it
   * in case we encounter the error in the middle of the loop.
   */
  for (n_to_send = at_most_a_frame (burst), burst -= n_to_send; n_to_send > 0;
       n_to_send = at_most_a_frame (burst), burst -= n_to_send)
    {
      f = vlib_get_frame_to_node (vm, lookup_node_index);
      /* f can not be NULL here - frame allocation failure causes panic */

      u32 *to_next = vlib_frame_vector_args (f);
      f->n_vectors = n_to_send;

      while (n_to_send > 1)
	{
	  vlib_buffer_t *b0copy = vlib_buffer_copy (vm, b0);
	  if (PREDICT_FALSE (b0copy == NULL))
	    goto ship_and_ret;
	  *to_next++ = vlib_get_buffer_index (vm, b0copy);
	  n_to_send--;
	  n_sent++;
	}

      /* n_to_send is guaranteed to equal 1 here */
      if (burst > 0)
	{
	  /* not the last burst, so still make a copy for the last buffer */
	  vlib_buffer_t *b0copy = vlib_buffer_copy (vm, b0);
	  if (PREDICT_FALSE (b0copy == NULL))
	    goto ship_and_ret;
	  n_to_send--;
	  *to_next++ = vlib_get_buffer_index (vm, b0copy);
	}
      else
	{
	  /* put the original buffer as the last one of an error-free run */
	  *to_next++ = vlib_get_buffer_index (vm, b0);
	}
      vlib_put_frame_to_node (vm, lookup_node_index, f);
      n_sent += f->n_vectors;
    }
  return n_sent;
  /*
   * We reach here in case we already enqueued one or more buffers
   * and maybe one or more frames but could not make more copies.
   * There is an outstanding frame - so ship it and return.
   * Caller will have to free the b0 in this case, since
   * we did not enqueue it here yet.
   */
ship_and_ret:
  ASSERT (n_to_send <= f->n_vectors);
  f->n_vectors -= n_to_send;
  n_sent += f->n_vectors;
  vlib_put_frame_to_node (vm, lookup_node_index, f);
  return n_sent;
}


/*
 * An address-family agnostic ping send function.
 */

#define ERROR_OUT(e) do { err = e; goto done; } while (0)

static send_ip46_ping_result_t
send_ip46_ping (vlib_main_t * vm,
		u32 table_id,
		ip46_address_t * pa46,
		u32 sw_if_index,
		u16 seq_host, u16 id_host, u16 data_len, u32 burst,
		u8 verbose, int is_ip6)
{
  int err = SEND_PING_OK;
  u32 bi0 = 0;
  int n_buf0 = 0;
  vlib_buffer_t *b0;

  n_buf0 = vlib_buffer_alloc (vm, &bi0, 1);
  if (n_buf0 < 1)
    ERROR_OUT (SEND_PING_ALLOC_FAIL);

  b0 = vlib_get_buffer (vm, bi0);
  VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b0);

  /*
   * if the user did not provide a source interface,
   * perform a resolution and use an interface
   * via which it succeeds.
   */
  u32 fib_index;
  if (~0 == sw_if_index)
    {
      fib_index = ip46_fib_index_from_table_id (table_id, is_ip6);
      sw_if_index = ip46_get_resolving_interface (fib_index, pa46, is_ip6);
    }
  else
    fib_index =
      ip46_fib_table_get_index_for_sw_if_index (sw_if_index, is_ip6);

  if (~0 == fib_index)
    ERROR_OUT (SEND_PING_NO_TABLE);
  if (~0 == sw_if_index)
    ERROR_OUT (SEND_PING_NO_INTERFACE);

  vnet_buffer (b0)->sw_if_index[VLIB_RX] = sw_if_index;
  vnet_buffer (b0)->sw_if_index[VLIB_TX] = fib_index;

  int l4_header_offset = ip46_fill_l3_header (pa46, b0, is_ip6);

  /* set the src address in the buffer */
  if (!ip46_set_src_address (sw_if_index, b0, is_ip6))
    ERROR_OUT (SEND_PING_NO_SRC_ADDRESS);
  if (verbose)
    ip46_print_buffer_src_address (vm, b0, is_ip6);

  data_len =
    ip46_fill_icmp_request_at (vm, l4_header_offset, seq_host, id_host,
			       data_len, b0, is_ip6);

  ip46_fix_len_and_csum (vm, l4_header_offset, data_len, b0, is_ip6);

  int n_sent = ip46_enqueue_packet (vm, b0, burst, is_ip6);
  if (n_sent < burst)
    err = SEND_PING_NO_BUFFERS;

done:
  if (err != SEND_PING_OK)
    {
      if (n_buf0 > 0)
	vlib_buffer_free (vm, &bi0, 1);
    }
  return err;
}

static send_ip46_ping_result_t
send_ip6_ping (vlib_main_t * vm,
	       u32 table_id, ip6_address_t * pa6,
	       u32 sw_if_index, u16 seq_host, u16 id_host, u16 data_len,
	       u32 burst, u8 verbose)
{
  ip46_address_t target;
  target.ip6 = *pa6;
  return send_ip46_ping (vm, table_id, &target, sw_if_index, seq_host,
			 id_host, data_len, burst, verbose, 1 /* is_ip6 */ );
}

static send_ip46_ping_result_t
send_ip4_ping (vlib_main_t * vm,
	       u32 table_id, ip4_address_t * pa4,
	       u32 sw_if_index, u16 seq_host, u16 id_host, u16 data_len,
	       u32 burst, u8 verbose)
{
  ip46_address_t target;
  ip46_address_set_ip4 (&target, pa4);
  return send_ip46_ping (vm, table_id, &target, sw_if_index, seq_host,
			 id_host, data_len, burst, verbose, 0 /* is_ip6 */ );
}

static void
print_ip46_icmp_reply (vlib_main_t * vm, u32 bi0, int is_ip6)
{
  vlib_buffer_t *b0 = vlib_get_buffer (vm, bi0);
  int l4_offset;
  void *paddr;
  void *format_addr_func;
  u16 payload_length;
  u8 ttl;
  if (is_ip6)
    {
      ip6_header_t *ip6 = vlib_buffer_get_current (b0);
      paddr = (void *) &ip6->src_address;
      format_addr_func = (void *) format_ip6_address;
      ttl = ip6->hop_limit;
      l4_offset = sizeof (ip6_header_t);	// FIXME - EH processing ?
      payload_length = clib_net_to_host_u16 (ip6->payload_length);
    }
  else
    {
      ip4_header_t *ip4 = vlib_buffer_get_current (b0);
      paddr = (void *) &ip4->src_address;
      format_addr_func = (void *) format_ip4_address;
      ttl = ip4->ttl;
      l4_offset = ip4_header_bytes (ip4);
      payload_length =
	clib_net_to_host_u16 (ip4->length) + ip4_header_bytes (ip4);
    }
  icmp46_header_t *icmp = vlib_buffer_get_current (b0) + l4_offset;
  icmp46_echo_request_t *icmp_echo = (icmp46_echo_request_t *) (icmp + 1);
  u64 *dataplane_ts = (u64 *) & vnet_buffer (b0)->unused[0];

  f64 clocks_per_second = ((f64) vm->clib_time.clocks_per_second);
  f64 rtt =
    ((f64) (*dataplane_ts - icmp_echo->time_sent)) / clocks_per_second;

  vlib_cli_output (vm,
		   "%d bytes from %U: icmp_seq=%d ttl=%d time=%.4f ms",
		   payload_length,
		   format_addr_func,
		   paddr,
		   clib_host_to_net_u16 (icmp_echo->seq), ttl, rtt * 1000.0);
}

/*
 * Perform the ping run with the given parameters in the current CLI process.
 * Depending on whether pa4 or pa6 is set, runs IPv4 or IPv6 ping.
 * The amusing side effect is of course if both are set, then both pings are sent.
 * This behavior can be used to ping a dualstack host over IPv4 and IPv6 at once.
 */

static void
run_ping_ip46_address (vlib_main_t * vm, u32 table_id, ip4_address_t * pa4,
		       ip6_address_t * pa6, u32 sw_if_index,
		       f64 ping_interval, u32 ping_repeat, u32 data_len,
		       u32 ping_burst, u32 verbose)
{
  int i;
  uword curr_proc = vlib_current_process (vm);
  u32 n_replies = 0;
  u32 n_requests = 0;
  u16 icmp_id;

  static u32 rand_seed = 0;

  if (PREDICT_FALSE (!rand_seed))
    rand_seed = random_default_seed ();

  icmp_id = random_u32 (&rand_seed) & 0xffff;

  while (~0 != get_cli_process_id_by_icmp_id_mt (vm, icmp_id))
    {
      vlib_cli_output (vm, "ICMP ID collision at %d, incrementing", icmp_id);
      icmp_id++;
    }

  set_cli_process_id_by_icmp_id_mt (vm, icmp_id, curr_proc);

  for (i = 1; i <= ping_repeat; i++)
    {
      send_ip46_ping_result_t res = SEND_PING_OK;
      f64 sleep_interval;
      f64 time_ping_sent = vlib_time_now (vm);
      if (pa6)
	{
	  res = send_ip6_ping (vm, table_id,
			       pa6, sw_if_index, i, icmp_id,
			       data_len, ping_burst, verbose);
	  if (SEND_PING_OK == res)
	    n_requests += ping_burst;
	  else
	    vlib_cli_output (vm, "Failed: %U", format_ip46_ping_result, res);
	}
      if (pa4)
	{
	  res = send_ip4_ping (vm, table_id, pa4,
			       sw_if_index, i, icmp_id, data_len,
			       ping_burst, verbose);
	  if (SEND_PING_OK == res)
	    n_requests += ping_burst;
	  else
	    vlib_cli_output (vm, "Failed: %U", format_ip46_ping_result, res);
	}

      /* Collect and print the responses until it is time to send a next ping */

      while ((i <= ping_repeat)
	     &&
	     ((sleep_interval =
	       time_ping_sent + ping_interval - vlib_time_now (vm)) > 0.0))
	{
	  uword event_type, *event_data = 0;
	  vlib_process_wait_for_event_or_clock (vm, sleep_interval);
	  event_type = vlib_process_get_events (vm, &event_data);
	  switch (event_type)
	    {
	    case ~0:		/* no events => timeout */
	      break;
	    case PING_RESPONSE_IP6:
	      /* fall-through */
	    case PING_RESPONSE_IP4:
	      {
		int ii;
		int is_ip6 = (event_type == PING_RESPONSE_IP6);
		for (ii = 0; ii < vec_len (event_data); ii++)
		  {
		    u32 bi0 = event_data[ii];
		    print_ip46_icmp_reply (vm, bi0, is_ip6);
		    n_replies++;
		    if (0 != bi0)
		      vlib_buffer_free (vm, &bi0, 1);
		  }
	      }
	      break;
	    default:
	      /* someone pressed a key, abort */
	      vlib_cli_output (vm, "Aborted due to a keypress.");
	      goto double_break;
	      break;
	    }
	  vec_free (event_data);
	}
    }
double_break:
  vlib_cli_output (vm, "\n");
  {
    float loss =
      (0 ==
       n_requests) ? 0 : 100.0 * ((float) n_requests -
				  (float) n_replies) / (float) n_requests;
    vlib_cli_output (vm,
		     "Statistics: %u sent, %u received, %f%% packet loss\n",
		     n_requests, n_replies, loss);
    clear_cli_process_id_by_icmp_id_mt (vm, icmp_id);
  }
}



static clib_error_t *
ping_ip_address (vlib_main_t * vm,
		 unformat_input_t * input, vlib_cli_command_t * cmd)
{
  ip4_address_t a4;
  ip6_address_t a6;
  clib_error_t *error = 0;
  u32 ping_repeat = 5;
  u32 ping_burst = 1;
  u8 ping_ip4, ping_ip6;
  vnet_main_t *vnm = vnet_get_main ();
  u32 data_len = PING_DEFAULT_DATA_LEN;
  u32 verbose = 0;
  f64 ping_interval = PING_DEFAULT_INTERVAL;
  u32 sw_if_index, table_id;

  table_id = 0;
  ping_ip4 = ping_ip6 = 0;
  sw_if_index = ~0;

  if (unformat (input, "%U", unformat_ip4_address, &a4))
    {
      ping_ip4 = 1;
    }
  else if (unformat (input, "%U", unformat_ip6_address, &a6))
    {
      ping_ip6 = 1;
    }
  else if (unformat (input, "ipv4"))
    {
      if (unformat (input, "%U", unformat_ip4_address, &a4))
	{
	  ping_ip4 = 1;
	}
      else
	{
	  error =
	    clib_error_return (0,
			       "expecting IPv4 address but got `%U'",
			       format_unformat_error, input);
	}
    }
  else if (unformat (input, "ipv6"))
    {
      if (unformat (input, "%U", unformat_ip6_address, &a6))
	{
	  ping_ip6 = 1;
	}
      else
	{
	  error =
	    clib_error_return (0,
			       "expecting IPv6 address but got `%U'",
			       format_unformat_error, input);
	}
    }
  else
    {
      error =
	clib_error_return (0,
			   "expecting IP4/IP6 address `%U'. Usage: ping <addr> [source <intf>] [size <datasz>] [repeat <count>] [verbose]",
			   format_unformat_error, input);
      goto done;
    }

  /* allow for the second AF in the same ping */
  if (!ping_ip4 && (unformat (input, "ipv4")))
    {
      if (unformat (input, "%U", unformat_ip4_address, &a4))
	{
	  ping_ip4 = 1;
	}
    }
  else if (!ping_ip6 && (unformat (input, "ipv6")))
    {
      if (unformat (input, "%U", unformat_ip6_address, &a6))
	{
	  ping_ip6 = 1;
	}
    }

  /* parse the rest of the parameters  in a cycle */
  while (!unformat_eof (input, NULL))
    {
      if (unformat (input, "source"))
	{
	  if (!unformat_user
	      (input, unformat_vnet_sw_interface, vnm, &sw_if_index))
	    {
	      error =
		clib_error_return (0,
				   "unknown interface `%U'",
				   format_unformat_error, input);
	      goto done;
	    }
	}
      else if (unformat (input, "size"))
	{
	  if (!unformat (input, "%u", &data_len))
	    {
	      error =
		clib_error_return (0,
				   "expecting size but got `%U'",
				   format_unformat_error, input);
	      goto done;
	    }
	  if (data_len > PING_MAXIMUM_DATA_SIZE)
	    {
	      error =
		clib_error_return (0,
				   "%d is bigger than maximum allowed payload size %d",
				   data_len, PING_MAXIMUM_DATA_SIZE);
	      goto done;
	    }
	}
      else if (unformat (input, "table-id"))
	{
	  if (!unformat (input, "%u", &table_id))
	    {
	      error =
		clib_error_return (0,
				   "expecting table-id but got `%U'",
				   format_unformat_error, input);
	      goto done;
	    }
	}
      else if (unformat (input, "interval"))
	{
	  if (!unformat (input, "%f", &ping_interval))
	    {
	      error =
		clib_error_return (0,
				   "expecting interval (floating point number) got `%U'",
				   format_unformat_error, input);
	      goto done;
	    }
	}
      else if (unformat (input, "repeat"))
	{
	  if (!unformat (input, "%u", &ping_repeat))
	    {
	      error =
		clib_error_return (0,
				   "expecting repeat count but got `%U'",
				   format_unformat_error, input);
	      goto done;
	    }
	}
      else if (unformat (input, "burst"))
	{
	  if (!unformat (input, "%u", &ping_burst))
	    {
	      error =
		clib_error_return (0,
				   "expecting burst count but got `%U'",
				   format_unformat_error, input);
	      goto done;
	    }
	}
      else if (unformat (input, "verbose"))
	{
	  verbose = 1;
	}
      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, input);
	  goto done;
	}
    }

/*
 * Operationally, one won't (and shouldn't) need to send more than a frame worth of pings.
 * But it may be handy during the debugging.
 */

#ifdef CLIB_DEBUG
#define MAX_PING_BURST (10*VLIB_FRAME_SIZE)
#else
#define MAX_PING_BURST (VLIB_FRAME_SIZE)
#endif

  if (ping_burst < 1 || ping_burst > MAX_PING_BURST)
    return clib_error_return (0, "burst size must be between 1 and %u",
			      MAX_PING_BURST);

  run_ping_ip46_address (vm, table_id, ping_ip4 ? &a4 : NULL,
			 ping_ip6 ? &a6 : NULL, sw_if_index, ping_interval,
			 ping_repeat, data_len, ping_burst, verbose);
done:
  return error;
}

/*?
 * This command sends an ICMP ECHO_REQUEST to network hosts. The address
 * can be an IPv4 or IPv6 address (or both at the same time).
 *
 * @cliexpar
 * @parblock
 * Example of how ping an IPv4 address:
 * @cliexstart{ping 172.16.1.2 source GigabitEthernet2/0/0 repeat 2}
 * 64 bytes from 172.16.1.2: icmp_seq=1 ttl=64 time=.1090 ms
 * 64 bytes from 172.16.1.2: icmp_seq=2 ttl=64 time=.0914 ms
 *
 * Statistics: 2 sent, 2 received, 0% packet loss
 * @cliexend
 *
 * Example of how ping both an IPv4 address and IPv6 address at the same time:
 * @cliexstart{ping 172.16.1.2 ipv6 fe80::24a5:f6ff:fe9c:3a36 source GigabitEthernet2/0/0 repeat 2 verbose}
 * Adjacency index: 10, sw_if_index: 1
 * Adj: ip6-discover-neighbor
 * Adj Interface: 0
 * Forced set interface: 1
 * Adjacency index: 0, sw_if_index: 4294967295
 * Adj: ip4-miss
 * Adj Interface: 0
 * Forced set interface: 1
 * Source address: 172.16.1.1
 * 64 bytes from 172.16.1.2: icmp_seq=1 ttl=64 time=.1899 ms
 * Adjacency index: 10, sw_if_index: 1
 * Adj: ip6-discover-neighbor
 * Adj Interface: 0
 * Forced set interface: 1
 * Adjacency index: 0, sw_if_index: 4294967295
 * Adj: ip4-miss
 * Adj Interface: 0
 * Forced set interface: 1
 * Source address: 172.16.1.1
 * 64 bytes from 172.16.1.2: icmp_seq=2 ttl=64 time=.0910 ms
 *
 * Statistics: 4 sent, 2 received, 50% packet loss
 * @cliexend
 * @endparblock
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (ping_command, static) =
{
  .path = "ping",
  .function = ping_ip_address,
  .short_help = "ping {<ip-addr> | ipv4 <ip4-addr> | ipv6 <ip6-addr>}"
  " [ipv4 <ip4-addr> | ipv6 <ip6-addr>] [source <interface>]"
  " [size <pktsize:60>] [interval <sec:1>] [repeat <cnt:5>] [table-id <id:0>]"
  " [burst <count:1>] [verbose]",
  .is_mp_safe = 1,
};
/* *INDENT-ON* */

static clib_error_t *
ping_cli_init (vlib_main_t * vm)
{
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  ping_main_t *pm = &ping_main;

  pm->ip6_main = &ip6_main;
  pm->ip4_main = &ip4_main;
  icmp6_register_type (vm, ICMP6_echo_reply, ip6_icmp_echo_reply_node.index);
  ip4_icmp_register_type (vm, ICMP4_echo_reply,
			  ip4_icmp_echo_reply_node.index);
  if (tm->n_vlib_mains > 1)
    clib_spinlock_init (&pm->ping_run_check_lock);

  ip4_icmp_register_type (vm, ICMP4_echo_request,
			  ip4_icmp_echo_request_node.index);

  return 0;
}

VLIB_INIT_FUNCTION (ping_cli_init);

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
    .version = VPP_BUILD_VER,
    .description = "Ping (ping)",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
