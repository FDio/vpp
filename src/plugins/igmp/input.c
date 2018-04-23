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
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <vnet/ip/ip.h>
#include <vlib/unix/unix.h>
#include <vnet/adj/adj_mcast.h>

#include <igmp/igmp.h>
#include <igmp/error.h>

#include <limits.h>

/* TODO: mld...
typedef enum
{
  MLD_INPUT_NEXT_DROP,
  ...
} mld_input_next_t;
*/

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

  s =
    format (s, "sw_if_index %u next-index %u", t->sw_if_index, t->next_index);
  s =
    format (s, "\n%U", format_igmp_header, t->packet_data,
	    sizeof (t->packet_data));
  return s;
}

static u8 *
format_igmp_parse_report_trace (u8 * s, va_list * va)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*va, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*va, vlib_node_t *);
  igmp_input_trace_t *t = va_arg (*va, igmp_input_trace_t *);

  s =
    format (s, "sw_if_index %u next-index %u", t->sw_if_index, t->next_index);
  s =
    format (s, "\n%U", format_igmp_report_v3, t->packet_data,
	    sizeof (t->packet_data));
  return s;
}

static u8 *
format_igmp_parse_query_trace (u8 * s, va_list * va)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*va, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*va, vlib_node_t *);
  igmp_input_trace_t *t = va_arg (*va, igmp_input_trace_t *);

  s =
    format (s, "sw_if_index %u next-input %u", t->sw_if_index, t->next_index);
  s =
    format (s, "\n%U", format_igmp_query_v3, t->packet_data,
	    sizeof (t->packet_data));
  return s;
}

uword
igmp_input (vlib_main_t * vm, vlib_node_runtime_t * node,
	    vlib_frame_t * frame)
{
  IGMP_DBG ("IGMP_INPUT");
  u32 n_left_from, *from, *to_next;
  igmp_parse_query_next_t next_index;
  vlib_node_runtime_t *error_node =
    vlib_node_get_runtime (vm, igmp_input_node.index);
  u8 error;
  ip_csum_t sum;
  u16 csum;

  error = IGMP_ERROR_NONE;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  vlib_buffer_t *b;
	  ip4_header_t *ip;
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

	  if (ip->protocol != 2)
	    {
	      error = IGMP_ERROR_INVALID_PROTOCOL;
	      next = IGMP_INPUT_NEXT_DROP;
	      goto next_buffer;
	    }

	  vlib_buffer_advance (b, ip4_header_bytes (ip));

	  igmp_header_t *igmp = vlib_buffer_get_current (b);

	  u16 checksum = igmp->checksum;
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
	      clib_memcpy (tr->packet_data, vlib_buffer_get_current (b),
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

uword
igmp_parse_query (vlib_main_t * vm, vlib_node_runtime_t * node,
		  vlib_frame_t * frame)
{
  IGMP_DBG ("IGMP_PARSE_QUERY");

  u32 n_left_from, *from, *to_next;
  igmp_parse_query_next_t next_index;
  igmp_main_t *im = &igmp_main;
  igmp_config_t *config;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  vlib_buffer_t *b;
	  u32 sw_if_index, bi, next;
	  next = IGMP_PARSE_QUERY_NEXT_DROP;

	  bi = from[0];
	  to_next[0] = bi;
	  from++;
	  to_next++;
	  n_left_from--;
	  n_left_to_next--;

	  b = vlib_get_buffer (vm, bi);
	  sw_if_index = vnet_buffer (b)->sw_if_index[VLIB_RX];

	  igmp_membership_query_v3_t *igmp = vlib_buffer_get_current (b);
	  ASSERT (igmp->header.type == IGMP_TYPE_membership_query);

	  /* if group address is zero, this is a general query */
	  if (igmp->dst.as_u32 == 0)
	    {
	      config = igmp_config_lookup (im, sw_if_index);
	      if (!config)
		{
		  IGMP_DBG ("No config on interface %u", sw_if_index);
		}
	      else
		{
		  /* WIP
		   *
		   * TODO: divide to multipe reports in random time range [now, max resp time]
		   */
		  u32 seed = vlib_time_now (vm);
		  f64 next_resp_time = random_f64 (&seed) *
		    (f64) (igmp->header.code / 10) + vlib_time_now (vm);
		  config->flags |= IGMP_CONFIG_FLAG_CAN_SEND_REPORT;
		  igmp_create_int_timer (next_resp_time, sw_if_index,
					 igmp_send_report);
		  vlib_process_signal_event (vm,
					     igmp_timer_process_node.index,
					     IGMP_PROCESS_EVENT_UPDATE_TIMER,
					     0);
		}
	    }

	  if (node->flags & VLIB_NODE_FLAG_TRACE)
	    {
	      igmp_input_trace_t *tr;
	      tr = vlib_add_trace (vm, node, b, sizeof (*tr));
	      tr->next_index = next;
	      tr->sw_if_index = vnet_buffer (b)->sw_if_index[VLIB_RX];
	      clib_memcpy (tr->packet_data, vlib_buffer_get_current (b),
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

uword
igmp_parse_report (vlib_main_t * vm, vlib_node_runtime_t * node,
		   vlib_frame_t * frame)
{
  IGMP_DBG ("IGMP_PARSE_REPORT");

  igmp_main_t *im = &igmp_main;
  u32 n_left_from, *from, *to_next;
  igmp_input_next_t next_index;
  igmp_config_t *config;
  igmp_group_t *group;
  igmp_src_t *src;
  igmp_membership_group_v3_t *igmp_group;
  ip4_address_t *src_addr;
  igmp_key_t gkey;
  igmp_key_t skey;
  memset (&gkey, 0, sizeof (igmp_key_t));
  memset (&skey, 0, sizeof (igmp_key_t));
  ip46_address_t saddr;
  memset (&saddr, 0, sizeof (ip46_address_t));
  ip46_address_t gaddr;
  memset (&gaddr, 0, sizeof (ip46_address_t));
  u32 len;
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
	  vlib_buffer_t *b;
	  u32 sw_if_index, bi, next;
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

	  sw_if_index = vnet_buffer (b)->sw_if_index[VLIB_RX];

	  igmp_membership_report_v3_t *igmp = vlib_buffer_get_current (b);
	  ASSERT (igmp->header.type == IGMP_TYPE_membership_report_v3);
	  len = sizeof (igmp_membership_report_v3_t);

	  /* if interface (S,G)s were configured by CLI/API goto next frame */
	  config = igmp_config_lookup (im, sw_if_index);
	  if (config)
	    {
	      config->flags |= IGMP_CONFIG_FLAG_QUERY_RESP_RECVED;
	      if (config->cli_api_configured)
		{
		  IGMP_DBG ("Interface %u has (S,G)s configured by CLI/API",
			    sw_if_index);
		  error = IGMP_ERROR_CLI_API_CONFIG;
		  b->error = error_node->errors[error];
		  goto next_frame;
		}
	    }
	  IGMP_DBG ("interface %u", sw_if_index);
	  int i, j = 0;
	  for (i = 0; i < clib_net_to_host_u16 (igmp->n_groups); i++)
	    {
	      igmp_group = group_ptr (igmp, len);
	      src_addr = igmp_group->src_addresses;
	      if (igmp_group->type ==
		  IGMP_MEMBERSHIP_GROUP_mode_is_filter_include)
		{
		  ip46_address_set_ip4 ((ip46_address_t *) & gkey.data,
					&igmp_group->dst_address);

		  gkey.group_type =
		    IGMP_MEMBERSHIP_GROUP_mode_is_filter_include;

		  group = igmp_group_lookup (config, &gkey);
		  if (group)
		    {
		      for (j = 0;
			   j <
			   clib_net_to_host_u16 (igmp_group->n_src_addresses);
			   j++)
			{
			  /* update (S,G) expiration timer */
			  ip46_address_set_ip4 ((ip46_address_t *) &
						skey.data, src_addr);
			  src = igmp_src_lookup (group, &skey);
			  if (src)
			    src->exp_time =
			      vlib_time_now (vm) + IGMP_SRC_TIMER;
			  src_addr++;
			}
		    }
		}
	      else if (igmp_group->type ==
		       IGMP_MEMBERSHIP_GROUP_mode_is_filter_exclude)
		{
		  for (j = 0;
		       j < clib_net_to_host_u16 (igmp_group->n_src_addresses);
		       j++)
		    {
		      /* nothing for now... */
		      src_addr++;
		    }
		}
	      else if (igmp_group->type ==
		       IGMP_MEMBERSHIP_GROUP_change_to_filter_include)
		{
		  for (j = 0;
		       j < clib_net_to_host_u16 (igmp_group->n_src_addresses);
		       j++)
		    {
		      /* add new (S,G) to interface */
		      saddr.ip4 = *src_addr;
		      gaddr.ip4 = igmp_group->dst_address;
		      igmp_listen (vm, 1, sw_if_index, saddr, gaddr, 0);
		      src_addr++;
		    }
		}
	      else if (igmp_group->type ==
		       IGMP_MEMBERSHIP_GROUP_change_to_filter_exclude)
		{
		  for (j = 0;
		       j < clib_net_to_host_u16 (igmp_group->n_src_addresses);
		       j++)
		    {
		      /* remove (S,G) from interface */
		      saddr.ip4 = *src_addr;
		      gaddr.ip4 = igmp_group->dst_address;
		      igmp_listen (vm, 0, sw_if_index, saddr, gaddr, 0);
		      src_addr++;
		    }
		}
	      else if (igmp_group->type ==
		       IGMP_MEMBERSHIP_GROUP_allow_new_sources)
		{
		  for (j = 0;
		       j < clib_net_to_host_u16 (igmp_group->n_src_addresses);
		       j++)
		    {
		      /* nothing for now... */
		      src_addr++;
		    }
		}
	      else if (igmp_group->type ==
		       IGMP_MEMBERSHIP_GROUP_block_old_sources)
		{
		  for (j = 0;
		       j < clib_net_to_host_u16 (igmp_group->n_src_addresses);
		       j++)
		    {
		      /* remove (S,G) from interface */
		      saddr.ip4 = *src_addr;
		      gaddr.ip4 = igmp_group->dst_address;
		      igmp_listen (vm, 0, sw_if_index, saddr, gaddr, 0);
		      src_addr++;
		    }
		}
	      /*
	       * Unrecognized Record Type values MUST be silently ignored.
	       */

	      /* move ptr to next Group Record */
	      len +=
		sizeof (igmp_membership_group_v3_t) +
		(sizeof (ip4_address_t) * j);
	    }
	next_frame:
	  if (node->flags & VLIB_NODE_FLAG_TRACE)
	    {
	      igmp_input_trace_t *tr;
	      tr = vlib_add_trace (vm, node, b, sizeof (*tr));
	      tr->next_index = next;
	      tr->sw_if_index = vnet_buffer (b)->sw_if_index[VLIB_RX];
	      clib_memcpy (tr->packet_data, vlib_buffer_get_current (b),
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

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
