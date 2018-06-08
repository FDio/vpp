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
#include <igmp/error.h>

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

uword
igmp_input (vlib_main_t * vm, vlib_node_runtime_t * node,
	    vlib_frame_t * frame)
{
  igmp_parse_query_next_t next_index;
  u32 n_left_from, *from, *to_next;
  vlib_node_runtime_t *error_node;
  u8 error;

  error = IGMP_ERROR_NONE;
  error_node = vlib_node_get_runtime (vm, igmp_input_node.index);

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

/**
 * A copy of the query message sent from the worker to the main thread
 */
typedef struct igmp_query_args_t_
{
  u32 sw_if_index;
  igmp_membership_query_v3_t query[0];
} igmp_query_args_t;

static f64
igmp_get_random_resp_time (const igmp_header_t * header)
{
  u32 seed, now;

  seed = now = vlib_time_now (vlib_get_main ());

  return ((random_f64 (&seed) *
	   igmp_header_get_max_resp_time (header)) + now);

}

static ip4_address_t *
igmp_query_mk_source_list (const igmp_membership_query_v3_t * q)
{
  ip4_address_t *srcs = NULL;
  const ip4_address_t *s;
  u16 ii;

  vec_validate (srcs, q->n_src_addresses - 1);
  s = q->src_addresses;

  for (ii = 0; ii < q->n_src_addresses; ii++)
    {
      vec_add1 (srcs, *s);
      s++;
    }

  return (srcs);
}

static u32
ip4_address_match (const ip4_address_t * s1, const ip4_address_t * s2)
{
  if (s1->as_u32 == s2->as_u32)
    return (!0);

  return (0);
}


/**
 * Called from the main thread on reception of a Query message
 */
static void
igmp_handle_query (const igmp_query_args_t * args)
{
  igmp_config_t *config;

  config = igmp_config_lookup (args->sw_if_index);

  if (!config)
    /*
     * it's possible, though unlikey, the interface was disabled
     *  whilst we copied this query from the worker thread
     */
    return;

  /*
     Section 5.2
     "When a system receives a Query, it does not respond immediately.
     Instead, it delays its response by a random amount of time, bounded
     by the Max Resp Time value derived from the Max Resp Code in the
     received Query message.  A system may receive a variety of Queries on
     different interfaces and of different kinds (e.g., General Queries,
     Group-Specific Queries, and Group-and-Source-Specific Queries), each
     of which may require its own delayed response.
   */
  if (igmp_membership_query_v3_is_geeral (args->query))
    {
      /*
       * A general query has no info that needs saving from the response
       */
      if (IGMP_TIMER_ID_INVALID ==
	  config->timers[IGMP_CONFIG_TIMER_GENERAL_QUERY])
	{
	  /**
           * no currently running timer, schedule a new one
           */
	  config->timers[IGMP_CONFIG_TIMER_GENERAL_QUERY] =
	    igmp_timer_schedule (igmp_get_random_resp_time
				 (&args->query[0].header),
				 igmp_config_index (config),
				 igmp_send_general_report_v3, NULL);
	}
      /*
       * else
       *  don't reschedule timers, we'll reply soon enough..
       */
    }
  else
    {
      /*
       * G or SG query. we'll need to save the sources quered
       */
      igmp_key_t key = {
	.ip4 = args->query[0].group_address,
      };
      igmp_timer_id_t tid;
      igmp_group_t *group;
      ip4_address_t *srcs;

      group = igmp_group_lookup (config, &key);

      /*
       * If there is no group config, no worries, we can ignore this
       * query. If the group state does come soon, we'll send a
       * state-change report at that time.
       */
      if (!group)
	return;

      srcs = igmp_query_mk_source_list (args->query);
      tid = group->timers[IGMP_GROUP_TIMER_QUERY_REPLY];

      if (IGMP_TIMER_ID_INVALID == tid)
	{
	  /*
	   * There is a timer already running, merge the sources list
	   */
	  ip4_address_t *current, *s;

	  current = igmp_timer_get_data (tid);

	  vec_foreach (s, srcs)
	  {
	    if (~0 ==
		vec_search_with_function (current, s, ip4_address_match))
	      vec_add1 (current, *s);
	  }

	  igmp_timer_set_data (tid, current);
	}
      else
	{
	  /*
	   * schedule a new G-specific query
	   */
	  /* igmp_timer_schedule (igmp_get_random_resp_time(&args->query[0].header), */
	  /*                      igmp_group_index(group), */
	  /*                      igmp_send_group_report_v3, */
	  /*                      srcs); */
	}
    }
}

uword
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
	  vlib_buffer_t *b;
	  u32 bi, next;

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

	  /*
	   * copy the contents of the query, and the interface, over
	   * to the main thread for processing
	   */
	  vlib_buffer_advance (b, -sizeof (u32));
	  args = vlib_buffer_get_current (b);
	  args->sw_if_index = vnet_buffer (b)->sw_if_index[VLIB_RX];

	  vl_api_rpc_call_main_thread (igmp_handle_query,
				       (u8 *) args,
				       sizeof (args) +
				       igmp_membership_query_v3_length
				       (igmp));

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

typedef struct igmp_update_args_t_
{
  u32 sw_if_index;
  /* vector of source addresses */
  ip4_address_t *saddr;
  ip4_address_t gaddr;
  igmp_membership_group_v3_type_t type;
} igmp_update_args_t;

/**
 * Called from main thread only
 */
static void
igmp_update_args (igmp_update_args_t * args)
{
  /*
   * invoke the update function with the global IGMP spinlock held
   *  - this is much more scalpel esque than a worker thread sync
   */
  clib_spinlock_lock (&igmp_main.lock);
  clib_spinlock_lock (&igmp_main.lock);
}

static void
igmp_rpc_update (u32 sw_if_index,
		 ip4_address_t * saddr,
		 const ip4_address_t * gaddr,
		 igmp_membership_group_v3_type_t type)
{
  igmp_update_args_t args = {
    .sw_if_index = sw_if_index,
    .saddr = saddr,
    .gaddr = *gaddr,
    .type = type,
  };

  vl_api_rpc_call_main_thread (igmp_update_args,
			       (u8 *) & args, sizeof (args));
}

uword
igmp_parse_report (vlib_main_t * vm, vlib_node_runtime_t * node,
		   vlib_frame_t * frame)
{
  u32 n_left_from, *from, *to_next;
  igmp_input_next_t next_index;
  igmp_config_t *config;
  // igmp_group_t *group;
  // igmp_src_t *src;
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
	  config = igmp_config_lookup (sw_if_index);
	  if (config)
	    {
	      config->flags |= IGMP_CONFIG_FLAG_QUERY_RESP_RECVED;
	    }
	  IGMP_DBG ("interface %u", sw_if_index);
	  int i, j = 0;
	  for (i = 0; i < clib_net_to_host_u16 (igmp->n_groups); i++)
	    {
	      ip4_address_t *srcs;

	      igmp_group = group_ptr (igmp, len);
	      src_addr = igmp_group->src_addresses;
	      ip46_address_set_ip4 (&gkey, &igmp_group->group_address);

	      for (j = 0;
		   j < clib_net_to_host_u16 (igmp_group->n_src_addresses);
		   j++)
		{
		  vec_add1 (srcs, *src_addr);
		  src_addr++;
		}

	      igmp_rpc_update (sw_if_index, srcs,
			       &igmp_group->group_address, igmp_group->type);

	      /* if (igmp_group->type == */
	      /*     IGMP_MEMBERSHIP_GROUP_mode_is_filter_include) */
	      /*   { */
	      /*     ip46_address_set_ip4 (&gkey.addr, &igmp_group->dst_address); */

	      /*     gkey.group_type = */
	      /*       IGMP_MEMBERSHIP_GROUP_mode_is_filter_include; */

	      /*     group = igmp_group_lookup (config, &gkey); */
	      /*     if (group) */
	      /*       { */
	      /*         for (j = 0; */
	      /*           j < */
	      /*           clib_net_to_host_u16 (igmp_group->n_src_addresses); */
	      /*           j++) */
	      /*        { */
	      /*          /\* update (S,G) expiration timer *\/ */
	      /*          ip46_address_set_ip4 (&skey.addr, src_addr); */
	      /*          src = igmp_src_lookup (group, &skey); */
	      /*          if (src) */
	      /*            src->exp_time = */
	      /*              vlib_time_now (vm) + IGMP_SRC_TIMER; */
	      /*          src_addr++; */
	      /*        } */
	      /*       } */
	      /*   } */
	      /* else if (igmp_group->type == */
	      /*          IGMP_MEMBERSHIP_GROUP_mode_is_filter_exclude) */
	      /*   { */
	      /*     for (j = 0; */
	      /*          j < clib_net_to_host_u16 (igmp_group->n_src_addresses); */
	      /*          j++) */
	      /*       { */
	      /*         /\* nothing for now... *\/ */
	      /*         src_addr++; */
	      /*       } */
	      /*   } */
	      /* else if (igmp_group->type == */
	      /*          IGMP_MEMBERSHIP_GROUP_change_to_filter_include) */
	      /*   { */
	      /*     for (j = 0; */
	      /*          j < clib_net_to_host_u16 (igmp_group->n_src_addresses); */
	      /*          j++) */
	      /*       { */
	      /*         /\* add new (S,G) to interface *\/ */
	      /*         saddr.ip4 = *src_addr; */
	      /*         gaddr.ip4 = igmp_group->dst_address; */
	      /*         igmp_rpc_update (vm, sw_if_index, src_addr, &gaddr, */
	      /*                   IGMP_MODE_ROUTER); */
	      /*         src_addr++; */
	      /*       } */
	      /*   } */
	      /* else if (igmp_group->type == */
	      /*          IGMP_MEMBERSHIP_GROUP_change_to_filter_exclude) */
	      /*   { */
	      /*     for (j = 0; */
	      /*          j < clib_net_to_host_u16 (igmp_group->n_src_addresses); */
	      /*          j++) */
	      /*       { */
	      /*         /\* remove (S,G) from interface *\/ */
	      /*         saddr.ip4 = *src_addr; */
	      /*         gaddr.ip4 = igmp_group->dst_address; */
	      /*         igmp_listen (vm, 0, sw_if_index, &saddr, &gaddr, */
	      /*                   IGMP_MODE_ROUTER); */
	      /*         src_addr++; */
	      /*       } */
	      /*   } */
	      /* else if (igmp_group->type == */
	      /*          IGMP_MEMBERSHIP_GROUP_allow_new_sources) */
	      /*   { */
	      /*     for (j = 0; */
	      /*          j < clib_net_to_host_u16 (igmp_group->n_src_addresses); */
	      /*          j++) */
	      /*       { */
	      /*         /\* nothing for now... *\/ */
	      /*         src_addr++; */
	      /*       } */
	      /*   } */
	      /* else if (igmp_group->type == */
	      /*          IGMP_MEMBERSHIP_GROUP_block_old_sources) */
	      /*   { */
	      /*     for (j = 0; */
	      /*          j < clib_net_to_host_u16 (igmp_group->n_src_addresses); */
	      /*          j++) */
	      /*       { */
	      /*         /\* remove (S,G) from interface *\/ */
	      /*         saddr.ip4 = *src_addr; */
	      /*         gaddr.ip4 = igmp_group->dst_address; */
	      /*         igmp_listen (vm, 0, sw_if_index, &saddr, &gaddr, */
	      /*                   IGMP_MODE_ROUTER); */
	      /*         src_addr++; */
	      /*       } */
	      /*   } */
	      /*
	       * Unrecognized Record Type values MUST be silently ignored.
	       */

	      /* move ptr to next Group Record */
	      len +=
		sizeof (igmp_membership_group_v3_t) +
		(sizeof (ip4_address_t) * j);
	    }
	  //next_frame:
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
