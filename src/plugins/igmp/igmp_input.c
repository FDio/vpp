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

#include <vlib/vlib.h>
#include <vlibmemory/api.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <vnet/ip/ip.h>
#include <vlib/unix/unix.h>
#include <vnet/adj/adj_mcast.h>

#include <igmp/igmp.h>
#include <igmp/igmp_pkt.h>
#include <igmp/igmp_query.h>
#include <igmp/igmp_report.h>
#include <igmp/igmp_error.h>

#include <limits.h>

typedef enum
{
  IGMP_INPUT_NEXT_DROP,
  IGMP_INPUT_NEXT_PARSE_QUERY,
  IGMP_INPUT_NEXT_PARSE_REPORT,
  IGMP_INPUT_N_NEXT,
} igmp_input_next_t;

typedef enum
{
  IGMP_PARSE_QUERY_NEXT_DROP,
  IGMP_PARSE_QUERY_N_NEXT,
} igmp_parse_query_next_t;

typedef enum
{
  IGMP_PARSE_REPORT_NEXT_DROP,
  IGMP_PARSE_REPORT_N_NEXT,
} igmp_parse_report_next_t;

char *igmp_error_strings[] = {
#define _(sym,string) string,
  foreach_igmp_error
#undef _
};

typedef struct
{
  u32 next_index;
  u32 sw_if_index;

  u8 packet_data[64];
} igmp_input_trace_t;

static u8 *
format_igmp_input_trace (u8 * s, va_list * va)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*va, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*va, vlib_node_t *);
  igmp_input_trace_t *t = va_arg (*va, igmp_input_trace_t *);

  s = format (s, "sw_if_index %u next-index %u",
	      t->sw_if_index, t->next_index);
  s = format (s, "\n%U", format_igmp_header, t->packet_data,
	      sizeof (t->packet_data));
  return s;
}

static u8 *
format_igmp_parse_report_trace (u8 * s, va_list * va)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*va, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*va, vlib_node_t *);
  igmp_input_trace_t *t = va_arg (*va, igmp_input_trace_t *);

  s = format (s, "sw_if_index %u next-index %u",
	      t->sw_if_index, t->next_index);
  s = format (s, "\n%U", format_igmp_report_v3, t->packet_data,
	      sizeof (t->packet_data));
  return s;
}

static u8 *
format_igmp_parse_query_trace (u8 * s, va_list * va)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*va, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*va, vlib_node_t *);
  igmp_input_trace_t *t = va_arg (*va, igmp_input_trace_t *);

  s = format (s, "sw_if_index %u next-input %u",
	      t->sw_if_index, t->next_index);
  s = format (s, "\n%U", format_igmp_query_v3, t->packet_data,
	      sizeof (t->packet_data));
  return s;
}

static uword
igmp_input (vlib_main_t * vm, vlib_node_runtime_t * node,
	    vlib_frame_t * frame)
{
  igmp_parse_query_next_t next_index;
  u32 n_left_from, *from, *to_next;
  vlib_node_runtime_t *error_node;
  u8 error;

  error = IGMP_ERROR_NONE;
  error_node = node;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  igmp_header_t *igmp;
	  u16 checksum, csum;
	  vlib_buffer_t *b;
	  ip4_header_t *ip;
	  ip_csum_t sum;
	  u32 bi, next;

	  next = IGMP_INPUT_NEXT_DROP;
	  bi = from[0];
	  to_next[0] = bi;
	  from++;
	  to_next++;
	  n_left_from--;
	  n_left_to_next--;

	  b = vlib_get_buffer (vm, bi);
	  ip = vlib_buffer_get_current (b);

	  if (ip->protocol != IP_PROTOCOL_IGMP)
	    {
	      error = IGMP_ERROR_INVALID_PROTOCOL;
	      next = IGMP_INPUT_NEXT_DROP;
	      goto next_buffer;
	    }

	  vlib_buffer_advance (b, ip4_header_bytes (ip));

	  igmp = vlib_buffer_get_current (b);

	  checksum = igmp->checksum;
	  igmp->checksum = 0;
	  sum = ip_incremental_checksum (0, igmp,
					 clib_net_to_host_u16 (ip->length) -
					 ip4_header_bytes (ip));
	  igmp->checksum = checksum;
	  csum = ~ip_csum_fold (sum);
	  if (checksum != csum)
	    {
	      error = IGMP_ERROR_BAD_CHECKSUM;
	      next = IGMP_INPUT_NEXT_DROP;
	      goto next_buffer;
	    }
	  if (!igmp_config_lookup (vnet_buffer (b)->sw_if_index[VLIB_RX]))
	    {
	      error = IGMP_ERROR_NOT_ENABLED;
	      next = IGMP_INPUT_NEXT_DROP;
	      goto next_buffer;
	    }

	  /* TODO: IGMPv2 and IGMPv1 */
	  switch (igmp->type)
	    {
	    case IGMP_TYPE_membership_query:
	      next = IGMP_INPUT_NEXT_PARSE_QUERY;
	      break;
	    case IGMP_TYPE_membership_report_v3:
	      next = IGMP_INPUT_NEXT_PARSE_REPORT;
	      break;
	    default:
	      error = IGMP_ERROR_UNKNOWN_TYPE;
	      next = IGMP_INPUT_NEXT_DROP;
	      break;
	    }
	next_buffer:
	  b->error = error_node->errors[error];

	  if (node->flags & VLIB_NODE_FLAG_TRACE)
	    {
	      igmp_input_trace_t *tr;
	      tr = vlib_add_trace (vm, node, b, sizeof (*tr));
	      tr->next_index = next;
	      tr->sw_if_index = vnet_buffer (b)->sw_if_index[VLIB_RX];
	      clib_memcpy_fast (tr->packet_data, vlib_buffer_get_current (b),
				sizeof (tr->packet_data));
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi, next);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (igmp_input_node) =
{
  .function = igmp_input,
  .name = "igmp-input",
  .vector_size = sizeof (u32),

  .format_buffer = format_igmp_header,
  .format_trace = format_igmp_input_trace,

  .n_errors = IGMP_N_ERROR,
  .error_strings = igmp_error_strings,

  .n_next_nodes = IGMP_INPUT_N_NEXT,
  .next_nodes = {
      [IGMP_INPUT_NEXT_DROP] = "error-drop",
      [IGMP_INPUT_NEXT_PARSE_QUERY] = "igmp-parse-query",
      [IGMP_INPUT_NEXT_PARSE_REPORT] = "igmp-parse-report",
  }
};
/* *INDENT-ON* */

static uword
igmp_parse_query (vlib_main_t * vm, vlib_node_runtime_t * node,
		  vlib_frame_t * frame)
{
  u32 n_left_from, *from, *to_next;
  igmp_parse_query_next_t next_index;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  igmp_membership_query_v3_t *igmp;
	  igmp_query_args_t *args;
	  u32 bi, next, len;
	  vlib_buffer_t *b;

	  next = IGMP_PARSE_QUERY_NEXT_DROP;
	  bi = from[0];
	  to_next[0] = bi;
	  from++;
	  to_next++;
	  n_left_from--;
	  n_left_to_next--;

	  b = vlib_get_buffer (vm, bi);
	  igmp = vlib_buffer_get_current (b);
	  ASSERT (igmp->header.type == IGMP_TYPE_membership_query);

	  if (node->flags & VLIB_NODE_FLAG_TRACE)
	    {
	      igmp_input_trace_t *tr;
	      tr = vlib_add_trace (vm, node, b, sizeof (*tr));
	      tr->next_index = next;
	      tr->sw_if_index = vnet_buffer (b)->sw_if_index[VLIB_RX];
	      clib_memcpy_fast (tr->packet_data, vlib_buffer_get_current (b),
				sizeof (tr->packet_data));
	    }
	  len = igmp_membership_query_v3_length (igmp);

	  /*
	   * validate that the length on the packet on the wire
	   * corresponds to the length on the calculated v3 query
	   */
	  if (vlib_buffer_length_in_chain (vm, b) == len)
	    {
	      /*
	       * copy the contents of the query, and the interface, over
	       * to the main thread for processing
	       */
	      vlib_buffer_advance (b, -sizeof (u32));
	      args = vlib_buffer_get_current (b);
	      args->sw_if_index = vnet_buffer (b)->sw_if_index[VLIB_RX];

	      vl_api_rpc_call_main_thread (igmp_handle_query,
					   (u8 *) args, sizeof (*args) + len);
	    }
	  /*
	   * else a packet that is reporting more or less sources
	   * than it really has, bin it
	   */

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi, next);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (igmp_parse_query_node) =
{
  .function = igmp_parse_query,
  .name = "igmp-parse-query",
  .vector_size = sizeof (u32),

  .format_buffer = format_igmp_query_v3,
  .format_trace = format_igmp_parse_query_trace,

  .n_errors = IGMP_N_ERROR,
  .error_strings = igmp_error_strings,

  .n_next_nodes = IGMP_PARSE_QUERY_N_NEXT,
  .next_nodes = {
    [IGMP_PARSE_QUERY_NEXT_DROP] = "error-drop",
  }
};
/* *INDENT-ON* */

static uword
igmp_parse_report (vlib_main_t * vm, vlib_node_runtime_t * node,
		   vlib_frame_t * frame)
{
  u32 n_left_from, *from, *to_next;
  igmp_input_next_t next_index;
  vlib_node_runtime_t *error_node =
    vlib_node_get_runtime (vm, igmp_input_node.index);
  u8 error;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  igmp_membership_report_v3_t *igmp;
	  igmp_report_args_t *args;
	  u32 bi, next, len;
	  vlib_buffer_t *b;

	  next = IGMP_PARSE_REPORT_NEXT_DROP;

	  bi = from[0];
	  to_next[0] = bi;
	  from++;
	  to_next++;
	  n_left_from--;
	  n_left_to_next--;

	  b = vlib_get_buffer (vm, bi);

	  error = IGMP_ERROR_NONE;
	  b->error = error_node->errors[error];
	  igmp = vlib_buffer_get_current (b);
	  len = igmp_membership_report_v3_length (igmp);

	  ASSERT (igmp->header.type == IGMP_TYPE_membership_report_v3);

	  if (node->flags & VLIB_NODE_FLAG_TRACE)
	    {
	      igmp_input_trace_t *tr;
	      tr = vlib_add_trace (vm, node, b, sizeof (*tr));
	      tr->next_index = next;
	      tr->sw_if_index = vnet_buffer (b)->sw_if_index[VLIB_RX];
	      clib_memcpy_fast (tr->packet_data, vlib_buffer_get_current (b),
				sizeof (tr->packet_data));
	    }

	  /*
	   * validate that the length on the packet on the wire
	   * corresponds to the length on the calculated v3 query
	   */
	  if (vlib_buffer_length_in_chain (vm, b) == len)
	    {
	      /*
	       * copy the contents of the query, and the interface, over
	       * to the main thread for processing
	       */
	      vlib_buffer_advance (b, -sizeof (u32));
	      args = vlib_buffer_get_current (b);
	      args->sw_if_index = vnet_buffer (b)->sw_if_index[VLIB_RX];

	      vl_api_rpc_call_main_thread (igmp_handle_report,
					   (u8 *) args, sizeof (*args) + len);
	    }
	  /*
	   * else
	   *   this is a packet with more groups/sources than the
	   *   header reports. bin it
	   */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi, next);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (igmp_parse_report_node) =
{
  .function = igmp_parse_report,
  .name = "igmp-parse-report",
  .vector_size = sizeof (u32),

  .format_buffer = format_igmp_report_v3,
  .format_trace = format_igmp_parse_report_trace,

  .n_errors = IGMP_N_ERROR,
  .error_strings = igmp_error_strings,

  .n_next_nodes = IGMP_PARSE_REPORT_N_NEXT,
  .next_nodes = {
    [IGMP_PARSE_REPORT_NEXT_DROP] = "error-drop",
  }
};
/* *INDENT-ON* */

static clib_error_t *
igmp_input_init (vlib_main_t * vm)
{
  clib_error_t *error;

  if ((error = vlib_call_init_function (vm, igmp_init)))
    return error;

  ip4_register_protocol (IP_PROTOCOL_IGMP, igmp_input_node.index);

  IGMP_DBG ("input-initialized");

  return (error);
}

VLIB_INIT_FUNCTION (igmp_input_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
