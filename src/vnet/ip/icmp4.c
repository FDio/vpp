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
 * ip/icmp4.c: ipv4 icmp
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


static char *icmp_error_strings[] = {
#define _(f,s) s,
  foreach_icmp4_error
#undef _
};

static u8 *
format_ip4_icmp_type_and_code (u8 * s, va_list * args)
{
  icmp4_type_t type = va_arg (*args, int);
  u8 code = va_arg (*args, int);
  char *t = 0;

#define _(n,f) case n: t = #f; break;

  switch (type)
    {
      foreach_icmp4_type;

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
#define _(a,n,f) case (ICMP4_##a << 8) | (n): t = #f; break;

      foreach_icmp4_code;

#undef _
    }

  if (t)
    s = format (s, " %s", t);

  return s;
}

static u8 *
format_ip4_icmp_header (u8 * s, va_list * args)
{
  icmp46_header_t *icmp = va_arg (*args, icmp46_header_t *);
  u32 max_header_bytes = va_arg (*args, u32);

  /* Nothing to do. */
  if (max_header_bytes < sizeof (icmp[0]))
    return format (s, "ICMP header truncated");

  s = format (s, "ICMP %U checksum 0x%x",
	      format_ip4_icmp_type_and_code, icmp->type, icmp->code,
	      clib_net_to_host_u16 (icmp->checksum));

  return s;
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

typedef enum
{
  ICMP_INPUT_NEXT_ERROR,
  ICMP_INPUT_N_NEXT,
} icmp_input_next_t;

typedef struct
{
  uword *type_and_code_by_name;

  uword *type_by_name;

  /* Vector dispatch table indexed by [icmp type]. */
  u8 ip4_input_next_index_by_type[256];
} icmp4_main_t;

icmp4_main_t icmp4_main;

static uword
ip4_icmp_input (vlib_main_t * vm,
		vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  icmp4_main_t *im = &icmp4_main;
  uword n_packets = frame->n_vectors;
  u32 *from, *to_next;
  u32 n_left_from, n_left_to_next, next;

  from = vlib_frame_vector_args (frame);
  n_left_from = n_packets;
  next = node->cached_next_index;

  if (node->flags & VLIB_NODE_FLAG_TRACE)
    vlib_trace_frame_buffers_only (vm, node, from, frame->n_vectors,
				   /* stride */ 1,
				   sizeof (icmp_input_trace_t));

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  vlib_buffer_t *p0;
	  ip4_header_t *ip0;
	  icmp46_header_t *icmp0;
	  icmp4_type_t type0;
	  u32 bi0, next0;

	  if (PREDICT_TRUE (n_left_from > 2))
	    {
	      vlib_prefetch_buffer_with_index (vm, from[2], LOAD);
	      p0 = vlib_get_buffer (vm, from[1]);
	      ip0 = vlib_buffer_get_current (p0);
	      CLIB_PREFETCH (ip0, CLIB_CACHE_LINE_BYTES, LOAD);
	    }

	  bi0 = to_next[0] = from[0];

	  from += 1;
	  n_left_from -= 1;
	  to_next += 1;
	  n_left_to_next -= 1;

	  p0 = vlib_get_buffer (vm, bi0);
	  ip0 = vlib_buffer_get_current (p0);
	  icmp0 = ip4_next_header (ip0);
	  type0 = icmp0->type;
	  next0 = im->ip4_input_next_index_by_type[type0];

	  p0->error = node->errors[ICMP4_ERROR_UNKNOWN_TYPE];
	  if (PREDICT_FALSE (next0 != next))
	    {
	      vlib_put_next_frame (vm, node, next, n_left_to_next + 1);
	      next = next0;
	      vlib_get_next_frame (vm, node, next, to_next, n_left_to_next);
	      to_next[0] = bi0;
	      to_next += 1;
	      n_left_to_next -= 1;
	    }
	}

      vlib_put_next_frame (vm, node, next, n_left_to_next);
    }

  return frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ip4_icmp_input_node,static) = {
  .function = ip4_icmp_input,
  .name = "ip4-icmp-input",

  .vector_size = sizeof (u32),

  .format_trace = format_icmp_input_trace,

  .n_errors = ARRAY_LEN (icmp_error_strings),
  .error_strings = icmp_error_strings,

  .n_next_nodes = 1,
  .next_nodes = {
    [ICMP_INPUT_NEXT_ERROR] = "error-punt",
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

	  ASSERT (ip0->checksum == ip4_header_checksum (ip0));
	  ASSERT (ip1->checksum == ip4_header_checksum (ip1));

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

	  sum0 = ip_csum_update (sum0, ip0->ttl, host_config_ttl,
				 ip4_header_t, ttl);
	  ip0->ttl = host_config_ttl;

	  sum0 = ip_csum_update (sum0, ip0->fragment_id, fid[0],
				 ip4_header_t, fragment_id);
	  ip0->fragment_id = fid[0];
	  fid += 1;

	  ip0->checksum = ip_csum_fold (sum0);

	  ASSERT (ip0->checksum == ip4_header_checksum (ip0));

	  p0->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;
	}

      vlib_put_next_frame (vm, node, next, n_left_to_next);
    }

  vlib_error_count (vm, ip4_icmp_input_node.index,
		    ICMP4_ERROR_ECHO_REPLIES_SENT, frame->n_vectors);

  return frame->n_vectors;
}

/* *INDENT-OFF* */
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
/* *INDENT-ON* */

typedef enum
{
  IP4_ICMP_ERROR_NEXT_DROP,
  IP4_ICMP_ERROR_NEXT_LOOKUP,
  IP4_ICMP_ERROR_N_NEXT,
} ip4_icmp_error_next_t;

void
icmp4_error_set_vnet_buffer (vlib_buffer_t * b, u8 type, u8 code, u32 data)
{
  vnet_buffer (b)->ip.icmp.type = type;
  vnet_buffer (b)->ip.icmp.code = code;
  vnet_buffer (b)->ip.icmp.data = data;
}

static u8
icmp4_icmp_type_to_error (u8 type)
{
  switch (type)
    {
    case ICMP4_destination_unreachable:
      return ICMP4_ERROR_DEST_UNREACH_SENT;
    case ICMP4_time_exceeded:
      return ICMP4_ERROR_TTL_EXPIRE_SENT;
    case ICMP4_parameter_problem:
      return ICMP4_ERROR_PARAM_PROBLEM_SENT;
    default:
      return ICMP4_ERROR_DROP;
    }
}

static uword
ip4_icmp_error (vlib_main_t * vm,
		vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u32 *from, *to_next;
  uword n_left_from, n_left_to_next;
  ip4_icmp_error_next_t next_index;
  ip4_main_t *im = &ip4_main;
  ip_lookup_main_t *lm = &im->lookup_main;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  if (node->flags & VLIB_NODE_FLAG_TRACE)
    vlib_trace_frame_buffers_only (vm, node, from, frame->n_vectors,
				   /* stride */ 1,
				   sizeof (icmp_input_trace_t));

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 pi0 = from[0];
	  u32 next0 = IP4_ICMP_ERROR_NEXT_LOOKUP;
	  u8 error0 = ICMP4_ERROR_NONE;
	  vlib_buffer_t *p0;
	  ip4_header_t *ip0, *out_ip0;
	  icmp46_header_t *icmp0;
	  u32 sw_if_index0, if_add_index0;
	  ip_csum_t sum;

	  /* Speculatively enqueue p0 to the current next frame */
	  to_next[0] = pi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  p0 = vlib_get_buffer (vm, pi0);
	  ip0 = vlib_buffer_get_current (p0);
	  sw_if_index0 = vnet_buffer (p0)->sw_if_index[VLIB_RX];

	  /*
	   * RFC1812 says to keep as much of the original packet as
	   * possible within the minimum MTU (576). We cheat "a little"
	   * here by keeping whatever fits in the first buffer, to be more
	   * efficient
	   */
	  if (PREDICT_FALSE (p0->total_length_not_including_first_buffer))
	    {
	      /* clear current_length of all other buffers in chain */
	      vlib_buffer_t *b = p0;
	      p0->total_length_not_including_first_buffer = 0;
	      while (b->flags & VLIB_BUFFER_NEXT_PRESENT)
		{
		  b = vlib_get_buffer (vm, b->next_buffer);
		  b->current_length = 0;
		}
	    }
	  p0->current_length =
	    p0->current_length > 576 ? 576 : p0->current_length;

	  /* Add IP header and ICMPv4 header including a 4 byte data field */
	  vlib_buffer_advance (p0,
			       -sizeof (ip4_header_t) -
			       sizeof (icmp46_header_t) - 4);
	  out_ip0 = vlib_buffer_get_current (p0);
	  icmp0 = (icmp46_header_t *) & out_ip0[1];

	  /* Fill ip header fields */
	  out_ip0->ip_version_and_header_length = 0x45;
	  out_ip0->tos = 0;
	  out_ip0->length = clib_host_to_net_u16 (p0->current_length);
	  out_ip0->fragment_id = 0;
	  out_ip0->flags_and_fragment_offset = 0;
	  out_ip0->ttl = 0xff;
	  out_ip0->protocol = IP_PROTOCOL_ICMP;
	  out_ip0->dst_address = ip0->src_address;
	  if_add_index0 = ~0;
	  if (PREDICT_TRUE (vec_len (lm->if_address_pool_index_by_sw_if_index)
			    > sw_if_index0))
	    if_add_index0 =
	      lm->if_address_pool_index_by_sw_if_index[sw_if_index0];
	  if (PREDICT_TRUE (if_add_index0 != ~0))
	    {
	      ip_interface_address_t *if_add =
		pool_elt_at_index (lm->if_address_pool, if_add_index0);
	      ip4_address_t *if_ip =
		ip_interface_address_get_address (lm, if_add);
	      out_ip0->src_address = *if_ip;
	    }
	  else
	    {
	      /* interface has no IP4 address - should not happen */
	      next0 = IP4_ICMP_ERROR_NEXT_DROP;
	      error0 = ICMP4_ERROR_DROP;
	    }
	  out_ip0->checksum = ip4_header_checksum (out_ip0);

	  /* Fill icmp header fields */
	  icmp0->type = vnet_buffer (p0)->ip.icmp.type;
	  icmp0->code = vnet_buffer (p0)->ip.icmp.code;
	  *((u32 *) (icmp0 + 1)) =
	    clib_host_to_net_u32 (vnet_buffer (p0)->ip.icmp.data);
	  icmp0->checksum = 0;
	  sum =
	    ip_incremental_checksum (0, icmp0,
				     p0->current_length -
				     sizeof (ip4_header_t));
	  icmp0->checksum = ~ip_csum_fold (sum);

	  /* Update error status */
	  if (error0 == ICMP4_ERROR_NONE)
	    error0 = icmp4_icmp_type_to_error (icmp0->type);
	  vlib_error_count (vm, node->node_index, error0, 1);

	  /* Verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   pi0, next0);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ip4_icmp_error_node) = {
  .function = ip4_icmp_error,
  .name = "ip4-icmp-error",
  .vector_size = sizeof (u32),

  .n_errors = ARRAY_LEN (icmp_error_strings),
  .error_strings = icmp_error_strings,

  .n_next_nodes = IP4_ICMP_ERROR_N_NEXT,
  .next_nodes = {
    [IP4_ICMP_ERROR_NEXT_DROP] = "error-drop",
    [IP4_ICMP_ERROR_NEXT_LOOKUP] = "ip4-lookup",
  },

  .format_trace = format_icmp_input_trace,
};
/* *INDENT-ON* */


static uword
unformat_icmp_type_and_code (unformat_input_t * input, va_list * args)
{
  icmp46_header_t *h = va_arg (*args, icmp46_header_t *);
  icmp4_main_t *cm = &icmp4_main;
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
icmp4_pg_edit_function (pg_main_t * pg,
			pg_stream_t * s,
			pg_edit_group_t * g, u32 * packets, u32 n_packets)
{
  vlib_main_t *vm = vlib_get_main ();
  u32 ip_offset, icmp_offset;

  icmp_offset = g->start_byte_offset;
  ip_offset = (g - 1)->start_byte_offset;

  while (n_packets >= 1)
    {
      vlib_buffer_t *p0;
      ip4_header_t *ip0;
      icmp46_header_t *icmp0;
      u32 len0;

      p0 = vlib_get_buffer (vm, packets[0]);
      n_packets -= 1;
      packets += 1;

      ASSERT (p0->current_data == 0);
      ip0 = (void *) (p0->data + ip_offset);
      icmp0 = (void *) (p0->data + icmp_offset);
      len0 = clib_net_to_host_u16 (ip0->length) - ip4_header_bytes (ip0);
      icmp0->checksum =
	~ip_csum_fold (ip_incremental_checksum (0, icmp0, len0));
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
      g->edit_function = icmp4_pg_edit_function;
      g->edit_function_opaque = 0;
    }

  return 1;

error:
  /* Free up any edits we may have added. */
  pg_free_edit_group (s);
  return 0;
}

void
ip4_icmp_register_type (vlib_main_t * vm, icmp4_type_t type, u32 node_index)
{
  icmp4_main_t *im = &icmp4_main;

  ASSERT ((int) type < ARRAY_LEN (im->ip4_input_next_index_by_type));
  im->ip4_input_next_index_by_type[type]
    = vlib_node_add_next (vm, ip4_icmp_input_node.index, node_index);
}

static clib_error_t *
icmp4_init (vlib_main_t * vm)
{
  ip_main_t *im = &ip_main;
  ip_protocol_info_t *pi;
  icmp4_main_t *cm = &icmp4_main;
  clib_error_t *error;

  error = vlib_call_init_function (vm, ip_main_init);

  if (error)
    return error;

  pi = ip_get_protocol_info (im, IP_PROTOCOL_ICMP);
  pi->format_header = format_ip4_icmp_header;
  pi->unformat_pg_edit = unformat_pg_icmp_header;

  cm->type_by_name = hash_create_string (0, sizeof (uword));
#define _(n,t) hash_set_mem (cm->type_by_name, #t, (n));
  foreach_icmp4_type;
#undef _

  cm->type_and_code_by_name = hash_create_string (0, sizeof (uword));
#define _(a,n,t) hash_set_mem (cm->type_by_name, #t, (n) | (ICMP4_##a << 8));
  foreach_icmp4_code;
#undef _

  memset (cm->ip4_input_next_index_by_type,
	  ICMP_INPUT_NEXT_ERROR, sizeof (cm->ip4_input_next_index_by_type));

  ip4_icmp_register_type (vm, ICMP4_echo_request,
			  ip4_icmp_echo_request_node.index);

  return 0;
}

VLIB_INIT_FUNCTION (icmp4_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
