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
 * ip/icmp6.c: ip6 icmp
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

#include <vlib/vlib.h>
#include <vnet/ip/ip.h>
#include <vnet/pg/pg.h>
#include <vnet/ip/ip_sas.h>
#include <vnet/util/throttle.h>

/** ICMP throttling */
static throttle_t icmp_throttle;

static u8 *
format_ip6_icmp_type_and_code (u8 * s, va_list * args)
{
  icmp6_type_t type = va_arg (*args, int);
  u8 code = va_arg (*args, int);
  char *t = 0;

#define _(n,f) case n: t = #f; break;

  switch (type)
    {
      foreach_icmp6_type;

    default:
      break;
    }

#undef _

  if (!t)
    return format (s, "unknown 0x%x", type);

  s = format (s, "%s", t);

  t = 0;
  switch ((type << 8) | code)
    {
#define _(a,n,f) case (ICMP6_##a << 8) | (n): t = #f; break;

      foreach_icmp6_code;

#undef _
    }

  if (t)
    s = format (s, " %s", t);

  return s;
}

static u8 *
format_icmp6_header (u8 * s, va_list * args)
{
  icmp46_header_t *icmp = va_arg (*args, icmp46_header_t *);
  u32 max_header_bytes = va_arg (*args, u32);

  /* Nothing to do. */
  if (max_header_bytes < sizeof (icmp[0]))
    return format (s, "ICMP header truncated");

  s = format (s, "ICMP %U checksum 0x%x",
	      format_ip6_icmp_type_and_code, icmp->type, icmp->code,
	      clib_net_to_host_u16 (icmp->checksum));

  if (max_header_bytes >=
      sizeof (icmp6_neighbor_solicitation_or_advertisement_header_t) &&
      (icmp->type == ICMP6_neighbor_solicitation ||
       icmp->type == ICMP6_neighbor_advertisement))
    {
      icmp6_neighbor_solicitation_or_advertisement_header_t *icmp6_nd =
	(icmp6_neighbor_solicitation_or_advertisement_header_t *) icmp;
      s = format (s, "\n    target address %U",
		  format_ip6_address, &icmp6_nd->target_address);
    }

  return s;
}

u8 *
format_icmp6_input_trace (u8 * s, va_list * va)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*va, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*va, vlib_node_t *);
  icmp6_input_trace_t *t = va_arg (*va, icmp6_input_trace_t *);

  s = format (s, "%U",
	      format_ip6_header, t->packet_data, sizeof (t->packet_data));

  return s;
}

typedef enum
{
  ICMP_INPUT_NEXT_PUNT,
  ICMP_INPUT_N_NEXT,
} icmp_input_next_t;

typedef struct
{
  uword *type_and_code_by_name;

  uword *type_by_name;

  /* Vector dispatch table indexed by [icmp type]. */
  u8 input_next_index_by_type[256];

  /* Max valid code indexed by icmp type. */
  u8 max_valid_code_by_type[256];

  /* hop_limit must be >= this value for this icmp type. */
  u8 min_valid_hop_limit_by_type[256];

  u8 min_valid_length_by_type[256];
} icmp6_main_t;

icmp6_main_t icmp6_main;

static uword
ip6_icmp_input (vlib_main_t * vm,
		vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  icmp6_main_t *im = &icmp6_main;
  u32 *from, *to_next;
  u32 n_left_from, n_left_to_next, next_index;

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

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  vlib_buffer_t *b0;
	  ip6_header_t *ip0;
	  icmp46_header_t *icmp0;
	  icmp6_type_t type0;
	  u32 bi0, next0, error0, len0;

	  bi0 = to_next[0] = from[0];

	  from += 1;
	  n_left_from -= 1;
	  to_next += 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  ip0 = vlib_buffer_get_current (b0);
	  icmp0 = ip6_next_header (ip0);
	  type0 = icmp0->type;

	  error0 = ICMP6_ERROR_NONE;

	  next0 = im->input_next_index_by_type[type0];
	  error0 =
	    next0 == ICMP_INPUT_NEXT_PUNT ? ICMP6_ERROR_UNKNOWN_TYPE : error0;

	  /* Check code is valid for type. */
	  error0 =
	    icmp0->code >
	    im->max_valid_code_by_type[type0] ?
	    ICMP6_ERROR_INVALID_CODE_FOR_TYPE : error0;

	  /* Checksum is already validated by ip6_local node so we don't need to check that. */

	  /* Check that hop limit == 255 for certain types. */
	  error0 =
	    ip0->hop_limit <
	    im->min_valid_hop_limit_by_type[type0] ?
	    ICMP6_ERROR_INVALID_HOP_LIMIT_FOR_TYPE : error0;

	  len0 = clib_net_to_host_u16 (ip0->payload_length);
	  error0 =
	    len0 <
	    im->min_valid_length_by_type[type0] ?
	    ICMP6_ERROR_LENGTH_TOO_SMALL_FOR_TYPE : error0;

	  b0->error = node->errors[error0];

	  next0 = error0 != ICMP6_ERROR_NONE ? ICMP_INPUT_NEXT_PUNT : next0;

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

VLIB_REGISTER_NODE (ip6_icmp_input_node) = {
  .function = ip6_icmp_input,
  .name = "ip6-icmp-input",

  .vector_size = sizeof (u32),

  .format_trace = format_icmp6_input_trace,

  .n_errors = ICMP6_N_ERROR,
  .error_counters = icmp6_error_counters,

  .n_next_nodes = 1,
  .next_nodes = {
    [ICMP_INPUT_NEXT_PUNT] = "ip6-punt",
  },
};

typedef enum
{
  IP6_ICMP_ERROR_NEXT_DROP,
  IP6_ICMP_ERROR_NEXT_LOOKUP,
  IP6_ICMP_ERROR_N_NEXT,
} ip6_icmp_error_next_t;

void
icmp6_error_set_vnet_buffer (vlib_buffer_t * b, u8 type, u8 code, u32 data)
{
  vnet_buffer (b)->ip.icmp.type = type;
  vnet_buffer (b)->ip.icmp.code = code;
  vnet_buffer (b)->ip.icmp.data = data;
}

static u8
icmp6_icmp_type_to_error (u8 type)
{
  switch (type)
    {
    case ICMP6_destination_unreachable:
      return ICMP6_ERROR_DEST_UNREACH_SENT;
    case ICMP6_packet_too_big:
      return ICMP6_ERROR_PACKET_TOO_BIG_SENT;
    case ICMP6_time_exceeded:
      return ICMP6_ERROR_TTL_EXPIRE_SENT;
    case ICMP6_parameter_problem:
      return ICMP6_ERROR_PARAM_PROBLEM_SENT;
    default:
      return ICMP6_ERROR_DROP;
    }
}

static uword
ip6_icmp_error (vlib_main_t * vm,
		vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u32 *from, *to_next;
  uword n_left_from, n_left_to_next;
  ip6_icmp_error_next_t next_index;
  clib_thread_index_t thread_index = vm->thread_index;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  u64 seed = throttle_seed (&icmp_throttle, thread_index, vlib_time_now (vm));

  if (node->flags & VLIB_NODE_FLAG_TRACE)
    vlib_trace_frame_buffers_only (vm, node, from, frame->n_vectors,
				   /* stride */ 1,
				   sizeof (icmp6_input_trace_t));

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  /*
	   * Duplicate first buffer and free the original chain.  Keep
	   * as much of the original packet as possible, within the
	   * minimum MTU. We chat "a little" here by keeping whatever
	   * is available in the first buffer.
	   */

	  u32 pi0 = ~0;
	  u32 org_pi0 = from[0];
	  u32 next0 = IP6_ICMP_ERROR_NEXT_LOOKUP;
	  u8 error0 = ICMP6_ERROR_NONE;
	  vlib_buffer_t *p0, *org_p0;
	  ip6_header_t *ip0, *out_ip0;
	  icmp46_header_t *icmp0;
	  u32 sw_if_index0;
	  int bogus_length;

	  org_p0 = vlib_get_buffer (vm, org_pi0);
	  ip0 = vlib_buffer_get_current (org_p0);

	  /* Rate limit based on the src,dst addresses in the original packet
	   */
	  u64 r0 = (ip6_address_hash_to_u64 (&ip0->dst_address) ^
		    ip6_address_hash_to_u64 (&ip0->src_address));

	  if (throttle_check (&icmp_throttle, thread_index, r0, seed))
	    {
	      vlib_error_count (vm, node->node_index, ICMP6_ERROR_DROP, 1);
	      from += 1;
	      n_left_from -= 1;
	      continue;
	    }

	  p0 = vlib_buffer_copy_no_chain (vm, org_p0, &pi0);
	  if (!p0 || pi0 == ~0)	/* Out of buffers */
	    continue;

	  /* Speculatively enqueue p0 to the current next frame */
	  to_next[0] = pi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  sw_if_index0 = vnet_buffer (p0)->sw_if_index[VLIB_RX];

	  vlib_buffer_copy_trace_flag (vm, org_p0, pi0);

	  /* Add IP header and ICMPv6 header including a 4 byte data field */
	  vlib_buffer_advance (p0,
			       -(sizeof (ip6_header_t) +
				 sizeof (icmp46_header_t) + 4));

	  p0->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;
	  p0->current_length =
	    p0->current_length > 1280 ? 1280 : p0->current_length;

	  out_ip0 = vlib_buffer_get_current (p0);
	  icmp0 = (icmp46_header_t *) & out_ip0[1];

	  /* Fill ip header fields */
	  out_ip0->ip_version_traffic_class_and_flow_label =
	    clib_host_to_net_u32 (0x6 << 28);

	  out_ip0->payload_length =
	    clib_host_to_net_u16 (p0->current_length - sizeof (ip6_header_t));
	  out_ip0->protocol = IP_PROTOCOL_ICMP6;
	  out_ip0->hop_limit = 0xff;
	  out_ip0->dst_address = ip0->src_address;
	  /* Prefer a source address from "offending interface" */
	  if (!ip6_sas_by_sw_if_index (sw_if_index0, &out_ip0->dst_address,
				       &out_ip0->src_address))
	    { /* interface has no IP6 address - should not happen */
	      next0 = IP6_ICMP_ERROR_NEXT_DROP;
	      error0 = ICMP6_ERROR_DROP;
	    }

	  /* Fill icmp header fields */
	  icmp0->type = vnet_buffer (p0)->ip.icmp.type;
	  icmp0->code = vnet_buffer (p0)->ip.icmp.code;
	  *((u32 *) (icmp0 + 1)) =
	    clib_host_to_net_u32 (vnet_buffer (p0)->ip.icmp.data);
	  icmp0->checksum = 0;
	  icmp0->checksum =
	    ip6_tcp_udp_icmp_compute_checksum (vm, p0, out_ip0,
					       &bogus_length);

	  /* Update error status */
	  if (error0 == ICMP6_ERROR_NONE)
	    error0 = icmp6_icmp_type_to_error (icmp0->type);

	  vlib_error_count (vm, node->node_index, error0, 1);

	  /* Verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   pi0, next0);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  /*
   * push the original buffers to error-drop, so that
   * they can get the error counters handled, then freed
   */
  vlib_buffer_enqueue_to_single_next (vm, node,
				      vlib_frame_vector_args (frame),
				      IP6_ICMP_ERROR_NEXT_DROP,
				      frame->n_vectors);

  return frame->n_vectors;
}

VLIB_REGISTER_NODE (ip6_icmp_error_node) = {
  .function = ip6_icmp_error,
  .name = "ip6-icmp-error",
  .vector_size = sizeof (u32),

  .n_errors = ICMP6_N_ERROR,
  .error_counters = icmp6_error_counters,

  .n_next_nodes = IP6_ICMP_ERROR_N_NEXT,
  .next_nodes = {
    [IP6_ICMP_ERROR_NEXT_DROP] = "error-drop",
    [IP6_ICMP_ERROR_NEXT_LOOKUP] = "ip6-lookup",
  },

  .format_trace = format_icmp6_input_trace,
};


static uword
unformat_icmp_type_and_code (unformat_input_t * input, va_list * args)
{
  icmp46_header_t *h = va_arg (*args, icmp46_header_t *);
  icmp6_main_t *cm = &icmp6_main;
  u32 i;

  if (unformat_user (input, unformat_vlib_number_by_name,
		     cm->type_and_code_by_name, &i))
    {
      h->type = (i >> 8) & 0xff;
      h->code = (i >> 0) & 0xff;
    }
  else if (unformat_user (input, unformat_vlib_number_by_name,
			  cm->type_by_name, &i))
    {
      h->type = i;
      h->code = 0;
    }
  else
    return 0;

  return 1;
}

static void
icmp6_pg_edit_function (pg_main_t * pg,
			pg_stream_t * s,
			pg_edit_group_t * g, u32 * packets, u32 n_packets)
{
  vlib_main_t *vm = vlib_get_main ();
  u32 ip_offset, icmp_offset;
  int bogus_length;

  icmp_offset = g->start_byte_offset;
  ip_offset = (g - 1)->start_byte_offset;

  while (n_packets >= 1)
    {
      vlib_buffer_t *p0;
      ip6_header_t *ip0;
      icmp46_header_t *icmp0;

      p0 = vlib_get_buffer (vm, packets[0]);
      n_packets -= 1;
      packets += 1;

      ASSERT (p0->current_data == 0);
      ip0 = (void *) (p0->data + ip_offset);
      icmp0 = (void *) (p0->data + icmp_offset);

      icmp0->checksum = ip6_tcp_udp_icmp_compute_checksum (vm, p0, ip0,
							   &bogus_length);
      ASSERT (bogus_length == 0);
    }
}

typedef struct
{
  pg_edit_t type, code;
  pg_edit_t checksum;
} pg_icmp46_header_t;

always_inline void
pg_icmp_header_init (pg_icmp46_header_t * p)
{
  /* Initialize fields that are not bit fields in the IP header. */
#define _(f) pg_edit_init (&p->f, icmp46_header_t, f);
  _(type);
  _(code);
  _(checksum);
#undef _
}

static uword
unformat_pg_icmp_header (unformat_input_t * input, va_list * args)
{
  pg_stream_t *s = va_arg (*args, pg_stream_t *);
  pg_icmp46_header_t *p;
  u32 group_index;

  p = pg_create_edit_group (s, sizeof (p[0]), sizeof (icmp46_header_t),
			    &group_index);
  pg_icmp_header_init (p);

  p->checksum.type = PG_EDIT_UNSPECIFIED;

  {
    icmp46_header_t tmp;

    if (!unformat (input, "ICMP %U", unformat_icmp_type_and_code, &tmp))
      goto error;

    pg_edit_set_fixed (&p->type, tmp.type);
    pg_edit_set_fixed (&p->code, tmp.code);
  }

  /* Parse options. */
  while (1)
    {
      if (unformat (input, "checksum %U",
		    unformat_pg_edit, unformat_pg_number, &p->checksum))
	;

      /* Can't parse input: try next protocol level. */
      else
	break;
    }

  if (!unformat_user (input, unformat_pg_payload, s))
    goto error;

  if (p->checksum.type == PG_EDIT_UNSPECIFIED)
    {
      pg_edit_group_t *g = pg_stream_get_group (s, group_index);
      g->edit_function = icmp6_pg_edit_function;
      g->edit_function_opaque = 0;
    }

  return 1;

error:
  /* Free up any edits we may have added. */
  pg_free_edit_group (s);
  return 0;
}

void
icmp6_register_type (vlib_main_t * vm, icmp6_type_t type, u32 node_index)
{
  icmp6_main_t *im = &icmp6_main;

  ASSERT ((int) type < ARRAY_LEN (im->input_next_index_by_type));
  im->input_next_index_by_type[type]
    = vlib_node_add_next (vm, ip6_icmp_input_node.index, node_index);
}

static clib_error_t *
icmp6_init (vlib_main_t * vm)
{
  ip_main_t *im = &ip_main;
  ip_protocol_info_t *pi;
  icmp6_main_t *cm = &icmp6_main;
  clib_error_t *error;

  error = vlib_call_init_function (vm, ip_main_init);

  if (error)
    return error;

  pi = ip_get_protocol_info (im, IP_PROTOCOL_ICMP6);
  pi->format_header = format_icmp6_header;
  pi->unformat_pg_edit = unformat_pg_icmp_header;

  cm->type_by_name = hash_create_string (0, sizeof (uword));
#define _(n,t) hash_set_mem (cm->type_by_name, #t, (n));
  foreach_icmp6_type;
#undef _

  cm->type_and_code_by_name = hash_create_string (0, sizeof (uword));
#define _(a,n,t) hash_set_mem (cm->type_by_name, #t, (n) | (ICMP6_##a << 8));
  foreach_icmp6_code;
#undef _

  clib_memset (cm->input_next_index_by_type,
	       ICMP_INPUT_NEXT_PUNT, sizeof (cm->input_next_index_by_type));
  clib_memset (cm->max_valid_code_by_type, 0,
	       sizeof (cm->max_valid_code_by_type));

#define _(a,n,t) cm->max_valid_code_by_type[ICMP6_##a] = clib_max (cm->max_valid_code_by_type[ICMP6_##a], n);
  foreach_icmp6_code;
#undef _

  clib_memset (cm->min_valid_hop_limit_by_type, 0,
	       sizeof (cm->min_valid_hop_limit_by_type));
  cm->min_valid_hop_limit_by_type[ICMP6_router_solicitation] = 255;
  cm->min_valid_hop_limit_by_type[ICMP6_router_advertisement] = 255;
  cm->min_valid_hop_limit_by_type[ICMP6_neighbor_solicitation] = 255;
  cm->min_valid_hop_limit_by_type[ICMP6_neighbor_advertisement] = 255;
  cm->min_valid_hop_limit_by_type[ICMP6_redirect] = 255;

  clib_memset (cm->min_valid_length_by_type, sizeof (icmp46_header_t),
	       sizeof (cm->min_valid_length_by_type));
  cm->min_valid_length_by_type[ICMP6_router_solicitation] =
    sizeof (icmp6_neighbor_discovery_header_t);
  cm->min_valid_length_by_type[ICMP6_router_advertisement] =
    sizeof (icmp6_router_advertisement_header_t);
  cm->min_valid_length_by_type[ICMP6_neighbor_solicitation] =
    sizeof (icmp6_neighbor_solicitation_or_advertisement_header_t);
  cm->min_valid_length_by_type[ICMP6_neighbor_advertisement] =
    sizeof (icmp6_neighbor_solicitation_or_advertisement_header_t);
  cm->min_valid_length_by_type[ICMP6_redirect] =
    sizeof (icmp6_redirect_header_t);

  vlib_thread_main_t *tm = &vlib_thread_main;
  u32 n_vlib_mains = tm->n_vlib_mains;

  throttle_init (&icmp_throttle, n_vlib_mains, THROTTLE_BITS, 1e-3);

  return (NULL);
}

VLIB_INIT_FUNCTION (icmp6_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
