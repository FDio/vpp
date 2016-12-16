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
 * ip/igmp.c: ipv4 igmp
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
#include <vnet/igmp/igmp.h>


static char * igmp_error_strings[] = {
#define _(f,s) s, \
  foreach_igmp_error
#undef _
};

static u8 * format_ip4_igmp_type_and_code (u8 * s, va_list * args)
{
  igmp_type_t type = va_arg (*args, int);
  u8 code = va_arg (*args, int);
  char * t = 0;

#define _(n,f) case n: t = #f; break;

  switch (type)
    {
      foreach_igmp_type;

    default:
      break;
    }

#undef _

  if (! t)
    return format (s, "unknown 0x%x", type);

  s = format (s, "%s", t);

  t = 0;
  switch ((type << 8) | code)
    {
#define _(a,n,f) case (IGMP_TYPE_##a << 8) | (n): t = #f; break;

      foreach_igmp_code;

#undef _
    }

  if (t)
    s = format (s, " %s", t);

  return s;
}


static u8 * format_igmp_header (u8 * s, va_list * args)
{
  igmp_header_t * igmp = va_arg (*args, igmp_header_t *);
  u32 max_header_bytes = va_arg (*args, u32);
	  /* Nothing to do. */
  if (max_header_bytes < sizeof (igmp[0]))
    return format (s, "IGMP header truncated");

  s = format (s, "IGMP %U checksum 0x%x",
		      format_ip4_igmp_type_and_code, igmp->type, igmp->code,
		      clib_net_to_host_u16 (igmp->checksum));

  return s;
}


static u8 * format_igmp_input_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  igmp_input_trace_t * t = va_arg (*args, igmp_input_trace_t *);

  s = format (s, "%U",
  	      format_ip4_header,
  	      t->packet_data, sizeof (t->packet_data));

  return s;
}

typedef enum {
  IGMP_INPUT_NEXT_MEMBERSHIP_QUERY,
  IGMP_INPUT_NEXT_LEAVE_GROUP_V2,
  IGMP_INPUT_NEXT_MEMBERSHIP_REPORT,
  IGMP_INPUT_NEXT_ERROR,
  IGMP_INPUT_N_NEXT,
} igmp_input_next_t;

typedef struct {
  uword * type_and_code_by_name;

  uword * type_by_name;

  /* Vector dispatch table indexed by [igmp type]. */
  u8 ip4_input_next_index_by_type[256];

  vlib_main_t * vlib_main;
  vnet_main_t * vnet_main;

} igmp_main_t;

igmp_main_t igmp_main;

static uword
ip4_igmp_input (vlib_main_t * vm,
		vlib_node_runtime_t * node,
		vlib_frame_t * frame)
{
  igmp_main_t * im = &igmp_main;
  uword n_packets = frame->n_vectors;
  u32 * from, * to_next;
  u32 n_left_from, n_left_to_next, next;
  from = vlib_frame_vector_args (frame);
  n_left_from = n_packets;
  next = node->cached_next_index;

  if (node->flags & VLIB_NODE_FLAG_TRACE)
    vlib_trace_frame_buffers_only (vm, node, from, frame->n_vectors,
				   /* stride */ 1,
				   sizeof (igmp_input_trace_t));

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  vlib_buffer_t * p0;
	  ip4_header_t * ip0;
	  igmp_message_t * igmp0;
	  igmp_type_t type0;
	  u32 bi0, next0;

          if (PREDICT_TRUE (n_left_from > 2))
            {
              vlib_prefetch_buffer_with_index (vm, from[2], LOAD);
              p0 = vlib_get_buffer (vm, from[1]);
              ip0 = vlib_buffer_get_current (p0);
              CLIB_PREFETCH(ip0, CLIB_CACHE_LINE_BYTES, LOAD);
            }


	  bi0 = to_next[0] = from[0];

	  from += 1;
	  n_left_from -= 1;
	  to_next += 1;
	  n_left_to_next -= 1;

	  p0 = vlib_get_buffer (vm, bi0);
	  ip0 = vlib_buffer_get_current (p0);
	  igmp0 = ip4_next_header (ip0);
	  type0 = igmp0->header.type;
	  next0 = im->ip4_input_next_index_by_type[type0];

	  p0->error = node->errors[IGMP_ERROR_UNKNOWN_TYPE];
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

VLIB_REGISTER_NODE (ip4_igmp_input_node,static) = {
  .function = ip4_igmp_input,
  .name = "ip4-igmp-input",

  .vector_size = sizeof (u32),

  .format_trace = format_igmp_header,

  .n_errors = ARRAY_LEN (igmp_error_strings),
  .error_strings = igmp_error_strings,

  .n_next_nodes = IGMP_INPUT_N_NEXT,
  .next_nodes = {
    [IGMP_INPUT_NEXT_MEMBERSHIP_QUERY] = "ip4-igmp-membership-query",
    [IGMP_INPUT_NEXT_LEAVE_GROUP_V2] = "ip4-igmp-leave-group-v2",
    [IGMP_INPUT_NEXT_MEMBERSHIP_REPORT] = "ip4-igmp-membership-report",
    [IGMP_INPUT_NEXT_ERROR] = "error-punt",
  },
};

typedef enum {
  IP4_IGMP_MEMBERSHIP_QUERY_NEXT_NODE,
  IP4_IGMP_MEMBERSHIP_QUERY_N_NEXT,
} ip4_igmp_membership_query_next_t;

static uword
ip4_igmp_membership_query (vlib_main_t * vm,
		vlib_node_runtime_t * node,
		vlib_frame_t * frame)
{
	  uword n_packets = frame->n_vectors;
	  u32 * from, * to_next;
	  u32 n_left_from, n_left_to_next, next;

	  from = vlib_frame_vector_args (frame);
	  n_left_from = n_packets;
	  next = node->cached_next_index;

	  if (node->flags & VLIB_NODE_FLAG_TRACE)
	    vlib_trace_frame_buffers_only (vm, node, from, frame->n_vectors,
					   /* stride */ 1,
					   sizeof (igmp_input_trace_t));

	  while (n_left_from > 0)
	    {
	      vlib_get_next_frame (vm, node, next, to_next, n_left_to_next);

	      while (n_left_from > 0 && n_left_to_next > 0)
		{
		  vlib_buffer_t * p0;
		  ip4_header_t * ip0;
		  u32 bi0, next0;

	          if (PREDICT_TRUE (n_left_from > 2))
	            {
	              vlib_prefetch_buffer_with_index (vm, from[2], LOAD);
	              p0 = vlib_get_buffer (vm, from[1]);
	              ip0 = vlib_buffer_get_current (p0);
	              CLIB_PREFETCH(ip0, CLIB_CACHE_LINE_BYTES, LOAD);
	            }

		  bi0 = to_next[0] = from[0];

		  from += 1;
		  n_left_from -= 1;
		  to_next += 1;
		  n_left_to_next -= 1;
		  p0 = vlib_get_buffer (vm, bi0);
		  ip0 = vlib_buffer_get_current (p0);

		  next0 = IP4_IGMP_MEMBERSHIP_QUERY_NEXT_NODE;

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


VLIB_REGISTER_NODE (ip4_igmp_membership_query_node, static) = {
  .function = ip4_igmp_membership_query,
  .name = "ip4-igmp-membership-query",
  .vector_size = sizeof (u32),

  .n_errors = ARRAY_LEN (igmp_error_strings),
  .error_strings = igmp_error_strings,
  .n_next_nodes = 1,
  .next_nodes = {
      [IP4_IGMP_MEMBERSHIP_QUERY_NEXT_NODE] = "ip4-igmp-last-node",
    },

  .format_trace = format_igmp_input_trace,
};

typedef enum {
  IP4_IGMP_LEAVE_GROUP_V2_NEXT_NODE,
  IP4_IGMP_LEAVE_GROUP_V2_N_NEXT,
}ip4_igmp_leave_group_v2_next_t;

static uword
ip4_igmp_leave_group_v2 (vlib_main_t * vm,
		vlib_node_runtime_t * node,
		vlib_frame_t * frame)
{
	  uword n_packets = frame->n_vectors;
	  u32 * from, * to_next;
	  u32 n_left_from, n_left_to_next, next;

	  from = vlib_frame_vector_args (frame);
	  n_left_from = n_packets;
	  next = node->cached_next_index;

	  if (node->flags & VLIB_NODE_FLAG_TRACE)
	    vlib_trace_frame_buffers_only (vm, node, from, frame->n_vectors,
					   /* stride */ 1,
					   sizeof (igmp_input_trace_t));

	  while (n_left_from > 0)
	    {
	      vlib_get_next_frame (vm, node, next, to_next, n_left_to_next);

	      while (n_left_from > 0 && n_left_to_next > 0)
		{
		  vlib_buffer_t * p0;
		  ip4_header_t * ip0;
		  u32 bi0, next0;

	          if (PREDICT_TRUE (n_left_from > 2))
	            {
	              vlib_prefetch_buffer_with_index (vm, from[2], LOAD);
	              p0 = vlib_get_buffer (vm, from[1]);
	              ip0 = vlib_buffer_get_current (p0);
	              CLIB_PREFETCH(ip0, CLIB_CACHE_LINE_BYTES, LOAD);
	            }

		  bi0 = to_next[0] = from[0];

		  from += 1;
		  n_left_from -= 1;
		  to_next += 1;
		  n_left_to_next -= 1;
		  p0 = vlib_get_buffer (vm, bi0);
		  ip0 = vlib_buffer_get_current (p0);

		  next0 = IP4_IGMP_LEAVE_GROUP_V2_NEXT_NODE;

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



VLIB_REGISTER_NODE (ip4_igmp_leave_group_v2_node, static) = {
  .function = ip4_igmp_leave_group_v2,
  .name = "ip4-igmp-leave-group-v2",
  .vector_size = sizeof (u32),

  .n_errors = ARRAY_LEN (igmp_error_strings),
  .error_strings = igmp_error_strings,
  .n_next_nodes = 1,
  .next_nodes = {
      [IP4_IGMP_LEAVE_GROUP_V2_NEXT_NODE] = "ip4-igmp-last-node",
    },

  .format_trace = format_igmp_input_trace,
};

typedef enum {
  IP4_IGMP_MEMBERSHIP_REPORT_NEXT_NODE,
  IP4_IGMP_MEMBERSHIP_REPORT_N_NEXT,
}ip4_igmp_membership_report_next_t;

static uword
ip4_igmp_membership_report(vlib_main_t * vm,
		vlib_node_runtime_t * node,
		vlib_frame_t * frame)
{


	  uword n_packets = frame->n_vectors;
	  u32 * from, * to_next;
	  u32 n_left_from, n_left_to_next, next;

	  from = vlib_frame_vector_args (frame);
	  n_left_from = n_packets;
	  next = node->cached_next_index;

	  if (node->flags & VLIB_NODE_FLAG_TRACE)
	    vlib_trace_frame_buffers_only (vm, node, from, frame->n_vectors,
					   /* stride */ 1,
					   sizeof (igmp_input_trace_t));

	  while (n_left_from > 0)
	    {
	      vlib_get_next_frame (vm, node, next, to_next, n_left_to_next);

	      while (n_left_from > 0 && n_left_to_next > 0)
		{
		  vlib_buffer_t * p0;
		  ip4_header_t * ip0;
		  u32 bi0, next0;

	          if (PREDICT_TRUE (n_left_from > 2))
	            {
	              vlib_prefetch_buffer_with_index (vm, from[2], LOAD);
	              p0 = vlib_get_buffer (vm, from[1]);
	              ip0 = vlib_buffer_get_current (p0);
	              CLIB_PREFETCH(ip0, CLIB_CACHE_LINE_BYTES, LOAD);
	            }

		  bi0 = to_next[0] = from[0];

		  from += 1;
		  n_left_from -= 1;
		  to_next += 1;
		  n_left_to_next -= 1;
		  p0 = vlib_get_buffer (vm, bi0);
		  ip0 = vlib_buffer_get_current (p0);

		  next0 = IP4_IGMP_MEMBERSHIP_REPORT_NEXT_NODE;
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


VLIB_REGISTER_NODE (ip4_igmp_membership_report_node, static) = {
  .function = ip4_igmp_membership_report,
  .name = "ip4-igmp-membership-report",

  .vector_size = sizeof (u32),

  .n_errors = ARRAY_LEN (igmp_error_strings),
  .error_strings = igmp_error_strings,
  .n_next_nodes = 1,
  .next_nodes = {
      [IP4_IGMP_MEMBERSHIP_REPORT_NEXT_NODE] = "ip4-igmp-last-node",
    },

  .format_trace = format_igmp_input_trace,
};

static uword
ip4_igmp_last_node (vlib_main_t * vm,
		vlib_node_runtime_t * node,
		vlib_frame_t * frame)
{
	return 0;
}


VLIB_REGISTER_NODE (ip4_igmp_last_node_node, static) = {
  .function = ip4_igmp_last_node,
  .name = "ip4-igmp-last-node",
  .vector_size = sizeof (u32),

  .n_errors = ARRAY_LEN (igmp_error_strings),
  .error_strings = igmp_error_strings,
  .format_trace = format_igmp_input_trace,
};

static uword unformat_igmp_type_and_code (unformat_input_t * input, va_list * args)
{
  igmp_header_t * h = va_arg (*args, igmp_header_t *);
  igmp_main_t * cm = &igmp_main;
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
igmp_pg_edit_function (pg_main_t * pg,
			pg_stream_t * s,
			pg_edit_group_t * g,
			u32 * packets,
			u32 n_packets)
{
  vlib_main_t * vm = vlib_get_main();
  u32 ip_offset, igmp_offset;

  igmp_offset = g->start_byte_offset;
  ip_offset = (g-1)->start_byte_offset;

  while (n_packets >= 1)
    {
      vlib_buffer_t * p0;
      ip4_header_t * ip0;
      igmp_header_t * igmp0;
      u32 len0;

      p0 = vlib_get_buffer (vm, packets[0]);
      n_packets -= 1;
      packets += 1;

      ASSERT (p0->current_data == 0);
      ip0 = (void *) (p0->data + ip_offset);
      igmp0 = (void *) (p0->data + igmp_offset);
      len0 = clib_net_to_host_u16 (ip0->length) - ip4_header_bytes (ip0);
      igmp0->checksum = ~ ip_csum_fold (ip_incremental_checksum (0, igmp0, len0));
    }
}

typedef struct {
  pg_edit_t type, code;
  pg_edit_t checksum;
} pg_igmp_header_t;

always_inline void
pg_igmp_header_init (pg_igmp_header_t * p)
{
  /* Initialize fields that are not bit fields in the IP header. */
#define _(f) pg_edit_init (&p->f, igmp_header_t, f);
  _ (code);
  _ (checksum);
#undef _
}

static uword
unformat_pg_igmp_header (unformat_input_t * input, va_list * args)
{
  pg_stream_t * s = va_arg (*args, pg_stream_t *);
  pg_igmp_header_t * p;
  u32 group_index;

  p = pg_create_edit_group (s, sizeof (p[0]), sizeof (igmp_header_t),
			    &group_index);
  pg_igmp_header_init (p);

  p->checksum.type = PG_EDIT_UNSPECIFIED;

  {
    igmp_header_t tmp;

    if (! unformat (input, "IGMP %U", unformat_igmp_type_and_code, &tmp))
      goto error;

    pg_edit_set_fixed (&p->type, tmp.type);
    pg_edit_set_fixed (&p->code, tmp.code);
  }

  /* Parse options. */
  while (1)
    {
      if (unformat (input, "checksum %U",
		    unformat_pg_edit,
		    unformat_pg_number, &p->checksum))
	;

      /* Can't parse input: try next protocol level. */
      else
	break;
    }

  if (! unformat_user (input, unformat_pg_payload, s))
    goto error;

  if (p->checksum.type == PG_EDIT_UNSPECIFIED)
    {
      pg_edit_group_t * g = pg_stream_get_group (s, group_index);
      g->edit_function = igmp_pg_edit_function;
      g->edit_function_opaque = 0;
    }

  return 1;

 error:
  /* Free up any edits we may have added. */
  pg_free_edit_group (s);
  return 0;
}

void ip4_igmp_register_type (vlib_main_t * vm, igmp_type_t type,
                             u32 node_index)
{
  igmp_main_t * im = &igmp_main;

  ASSERT ((int)type < ARRAY_LEN (im->ip4_input_next_index_by_type));
  im->ip4_input_next_index_by_type[type]
    = vlib_node_add_next (vm, ip4_igmp_input_node.index, node_index);
}

static clib_error_t *
igmp_init (vlib_main_t * vm)
{
  ip_main_t * im = &ip_main;
  ip_protocol_info_t * pi;
  igmp_main_t * cm = &igmp_main;
  clib_error_t * error;

  cm->vlib_main = vm;
  cm->vnet_main = vnet_get_main();

  error = vlib_call_init_function (vm, ip_main_init);

  if (error)
    return error;

  pi = ip_get_protocol_info (im, IP_PROTOCOL_IGMP);
  pi->format_header = format_igmp_header;
  pi->unformat_pg_edit = unformat_pg_igmp_header;

  cm->type_by_name = hash_create_string (0, sizeof (uword));
#define _(n,t) hash_set_mem (cm->type_by_name, #t, (n));
  foreach_igmp_type;
#undef _

  cm->type_and_code_by_name = hash_create_string (0, sizeof (uword));
#define _(a,n,t) hash_set_mem (cm->type_by_name, #t, (n) | (IGMP_TYPE_##a << 8));
  foreach_igmp_code;
#undef _

  memset (cm->ip4_input_next_index_by_type,
	  IGMP_INPUT_NEXT_ERROR,
	  sizeof (cm->ip4_input_next_index_by_type));

  ip4_igmp_register_type (vm, IGMP_TYPE_membership_query, ip4_igmp_membership_query_node.index);
  ip4_igmp_register_type (vm, IGMP_TYPE_leave_group_v2, ip4_igmp_leave_group_v2_node.index);
  ip4_igmp_register_type (vm, IGMP_TYPE_membership_report_v2, ip4_igmp_membership_report_node.index);
  return 0;
}

VLIB_INIT_FUNCTION (igmp_init);

igmp_main_t * igmp_get_main (vlib_main_t * vm)
{
  vlib_call_init_function (vm, igmp_init);
  return &igmp_main;
}



