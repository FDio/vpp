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
#include <vnet/mfib/mfib_entry.h>
#include <vlib/unix/unix.h>
#include <vnet/adj/adj_mcast.h>
#include <vnet/fib/fib_entry.h>
#include <vnet/fib/fib_table.h>
#include <vnet/mfib/mfib_table.h>

#include <igmp/igmp.h>
#include <igmp/igmp_format.h>
#include <igmp/igmp_pkt.h>

#include <limits.h>
#include <float.h>

igmp_main_t igmp_main;

/* *INDENT-OFF* */
/* General Query address */
const static mfib_prefix_t mpfx_general_query = {
  .fp_proto = FIB_PROTOCOL_IP4,
  .fp_len = 32,
  .fp_grp_addr = {
    .ip4 = {
      .as_u32 = IGMP_GENERAL_QUERY_ADDRESS,
    },
  },
};

/* Report address */
const static mfib_prefix_t mpfx_report = {
  .fp_proto = FIB_PROTOCOL_IP4,
  .fp_len = 32,
  .fp_grp_addr = {
    .ip4 = {
      .as_u32 = IGMP_MEMBERSHIP_REPORT_ADDRESS,
    },
  },
};
/* *INDENT-ON* */

u8 *
format_igmp_key (u8 * s, va_list * args)
{
  const igmp_key_t *key = va_arg (args, const igmp_key_t *);

  s = format (s, "%U", format_ip46_address, key, IP46_TYPE_IP4);

  return (s);
}

static void
igmp_src_free (igmp_src_t * src,
               igmp_group_t * group)
{
  igmp_main_t * im = &igmp_main;
  IGMP_DBG ("free-src: (%U, %U)",
            format_igmp_key, src->key,
            format_igmp_key, group->key);
  hash_unset_mem (group->igmp_src_by_key[IGMP_FILTER_MODE_INCLUDE],
                  src->key);
  hash_unset_mem (group->igmp_src_by_key[IGMP_FILTER_MODE_EXCLUDE],
                  src->key); clib_mem_free (src->key);
  pool_put (im->srcs, src);
}

void
igmp_clear_group (igmp_config_t * config, igmp_group_t * group)
{
  igmp_src_t *src;

  ASSERT (config);
  ASSERT (group);

  IGMP_DBG ("clear-group: %U %U",
            format_igmp_key, group->key,
            format_vnet_sw_if_index_name,
            vnet_get_main (), config->sw_if_index);
  /* *INDENT-OFF* */
  FOR_EACH_SRC (src, group, IGMP_FILTER_MODE_INCLUDE,
    ({
      igmp_src_free(src, group);
    }));
  /* *INDENT-ON* */

  hash_free (group->igmp_src_by_key[IGMP_FILTER_MODE_INCLUDE]);
  hash_free (group->igmp_src_by_key[IGMP_FILTER_MODE_EXCLUDE]);

  hash_unset_mem (config->igmp_group_by_key, group->key);
  clib_mem_free (group->key);
  pool_put (igmp_main.groups, group);
}

void
igmp_clear_config (igmp_config_t * config)
{
  igmp_group_t *group;

  IGMP_DBG ("clear-config: %U",
            format_vnet_sw_if_index_name,
            vnet_get_main (), config->sw_if_index);
  ASSERT (config); 
  /* *INDENT-OFF* */
  FOR_EACH_GROUP (group, config,
    ({
      igmp_clear_group (config, group);
    }));
  /* *INDENT-ON* */
}

static igmp_group_t *
igmp_group_alloc (igmp_config_t * config,
                  const igmp_key_t * gkey,
                  igmp_filter_mode_t mode)
{
  igmp_main_t * im = &igmp_main;
  igmp_group_t * group;
  IGMP_DBG ("new-group: %U", format_igmp_key, gkey);
  pool_get (im->groups, group);
  memset (group, 0, sizeof (igmp_group_t));
  group->key = clib_mem_alloc (sizeof (igmp_key_t));
  clib_memcpy (group->key, gkey, sizeof (igmp_key_t));
  group->igmp_src_by_key[IGMP_FILTER_MODE_INCLUDE] =
    hash_create_mem (0, sizeof (igmp_key_t), sizeof (uword));
  group->igmp_src_by_key[IGMP_FILTER_MODE_EXCLUDE] =
    hash_create_mem (0, sizeof (igmp_key_t), sizeof (uword));
  group->router_filter_mode = mode;
  hash_set_mem (config->igmp_group_by_key, group->key,
                group - im->groups); return (group);
}

static igmp_src_t *
igmp_src_alloc (igmp_group_t * group, const igmp_key_t * skey,
                igmp_mode_t mode)
{
  igmp_main_t * im = &igmp_main;
  igmp_src_t * src;
  IGMP_DBG ("new-src: (%U, %U)",
            format_igmp_key, skey, format_igmp_key, group->key);
  pool_get (im->srcs, src);
  memset (src, 0, sizeof (igmp_src_t));
  src->mode = mode;
  src->key = clib_mem_alloc (sizeof (*skey));
  clib_memcpy (src->key, skey, sizeof (*skey));
  hash_set_mem (group->igmp_src_by_key[IGMP_FILTER_MODE_INCLUDE],
                src->key, src - im->srcs); return (src);

  /* if (IGMP_MODE_ROUTER == config->mode) */
  /*       { */
  /*         /\* arm source timer (after expiration remove (S,G)) *\/ */
  /*         igmp_event (im, config, group, src); */
  /*         src->exp_time = vlib_time_now (vm) + IGMP_SRC_TIMER; */
  /*         igmp_create_src_timer (src->exp_time, config->sw_if_index, */
  /*                             group->key, src->key, igmp_src_exp); */
  /*       } */
}


/* void */
/* igmp_create_int_timer (f64 time, u32 sw_if_index, */
/* 		       igmp_timer_function_t * func) */
/* { */
/*   igmp_main_t *im = &igmp_main; */
/*   igmp_timer_t *timer; */

/*   pool_get (im->timers, timer); */
/*   memset (timer, 0, sizeof (igmp_timer_t)); */
/*   timer->func = func; */
/*   timer->exp_time = time; */
/*   timer->sw_if_index = sw_if_index; */

/*   igmp_sort_timers (im->timers); */
/* } */

/* /\** \brief igmp create group timer */
/*     @param time - expiration time (at this time the timer will expire) */
/*     @param sw_if_index - interface sw_if_index */
/*     @param gkey - key to find the group by */
/*     @param func - function to all after timer expiration */

/*     Creates new group timer. */
/* *\/ */
/* static void */
/* igmp_create_group_timer (f64 time, u32 sw_if_index, igmp_key_t * gkey, */
/* 			 igmp_timer_function_t * func) */
/* { */
/*   igmp_main_t *im = &igmp_main; */
/*   igmp_timer_t *timer; */

/*   pool_get (im->timers, timer); */
/*   memset (timer, 0, sizeof (igmp_timer_t)); */
/*   timer->func = func; */
/*   timer->exp_time = time; */
/*   timer->sw_if_index = sw_if_index; */


/*   ASSERT (gkey); */
/*   /\* duplicate keys, to prevent segmentation fault if (S,G) is removed *\/ */
/*   timer->data = clib_mem_alloc (sizeof (igmp_key_t)); */
/*   clib_memcpy (&((igmp_key_t *) timer->data)[0], gkey, sizeof (igmp_key_t)); */

/*   igmp_sort_timers (im->timers); */
/* } */

/* /\** \brief igmp create source timer */
/*     @param time - expiration time (at this time the timer will expire) */
/*     @param sw_if_index - interface sw_if_index */
/*     @param gkey - key to find the group by */
/*     @param skey - key to find the source by */
/*     @param func - function to all after timer expiration */

/*     Creates new source timer. */
/* *\/ */
/* static void */
/* igmp_create_src_timer (f64 time, u32 sw_if_index, igmp_key_t * gkey, */
/* 		       igmp_key_t * skey, igmp_timer_function_t * func) */
/* { */
/*   igmp_main_t *im = &igmp_main; */
/*   igmp_timer_t *timer; */

/*   pool_get (im->timers, timer); */
/*   memset (timer, 0, sizeof (igmp_timer_t)); */
/*   timer->func = func; */
/*   timer->exp_time = time; */
/*   timer->sw_if_index = sw_if_index; */

/*   ASSERT (gkey); */
/*   ASSERT (skey); */
/*   /\* duplicate keys, to prevent segmentation fault if (S,G) is removed *\/ */
/*   timer->data = clib_mem_alloc (sizeof (igmp_key_t) * 2); */
/*   clib_memcpy (&((igmp_key_t *) timer->data)[0], gkey, sizeof (igmp_key_t)); */
/*   clib_memcpy (&((igmp_key_t *) timer->data)[1], skey, sizeof (igmp_key_t)); */

/*   igmp_sort_timers (im->timers); */
/* } */


/*
  static void
  igmp_create_report_v2 (vlib_buffer_t * b, igmp_config_t * config)
  {
  ip_csum_t sum;
  u16 csum;
  igmp_main_t *im = &igmp_main;
  igmp_sg_t *sg;

  sg = vec_elt_at_index (config->sg, im->next_index.sg_index);

  igmp_message_t *igmp = (igmp_message_t *) (vlib_buffer_get_current (b));
  memset (igmp, 0, sizeof (igmp_message_t));

  clib_memcpy (&igmp->dst, &sg->gaddr.ip4, sizeof (ip4_address_t));
  igmp->header.type =
  (sg->group_type == IGMP_MEMBERSHIP_GROUP_block_old_sources) ?
  IGMP_TYPE_leave_group_v2 : IGMP_TYPE_membership_report_v2;
  sum = ip_incremental_checksum (0, igmp, sizeof (igmp_message_t));
  csum = ~ip_csum_fold (sum);
  igmp->header.checksum = csum;

  b->current_data += sizeof (igmp_message_t);
  b->current_length += sizeof (igmp_message_t);
  }
*/


/** \brief igmp create report all (v3)
    @param b - vlib buffer
    @param config - igmp configuration
    @param group - igmp group

    Create IGMPv3 report. If group is NULL, send all groups on interface.
*/
/* static void */
/* igmp_create_report_v3 (vlib_buffer_t * b, igmp_config_t * config, */
/* 		       igmp_group_t * group) */
/* { */
/*   igmp_membership_group_v3_t *igmp_group; */
/*   igmp_membership_report_v3_t *igmp; */
/*   ip_csum_t sum; */
/*   u16 csum; */
/*   u32 len; */

/*   len = sizeof (igmp_membership_report_v3_t); */
/*   igmp = vlib_buffer_get_current (b); */
/*   memset (igmp, 0, sizeof (igmp_membership_report_v3_t)); */

/*   igmp->header.type = IGMP_TYPE_membership_report_v3; */
/*   igmp->n_groups = clib_net_to_host_u16 ((group) ? */
/* 					 1 : */
/* 					 hash_elts */
/* 					 (config->igmp_group_by_key)); */

/*   IGMP_DBG ("create-report: %U ..", */
/*             format_vnet_sw_if_index_name, */
/*             vnet_get_main (), config->sw_if_index); */

/*   /\* get pointer to first group *\/ */
/*   igmp_group = igmp->groups; */

/*   if (group) */
/*     { */
/*       /\* if group is not NULL, send the specified group *\/ */
/*       len += igmp_report_v3_add_group (igmp_group, group); */
/*     } */
/*   else */
/*     { */
/*       /\* *INDENT-OFF* *\/ */
/*       FOR_EACH_GROUP (group, config, */
/*         ({ */
/*           len += igmp_report_v3_add_group(igmp_group, group); */
/* 	  igmp_group = group_ptr (igmp, len); */
/* 	})); */
/*       /\* *INDENT-ON* *\/ */
/*     } */

/*   sum = ip_incremental_checksum (0, igmp, len); */
/*   csum = ~ip_csum_fold (sum); */
/*   igmp->header.checksum = csum; */

/*   b->current_data += len; */
/*   b->current_length += len; */
/* } */

/** \brief igmp query response expiration (igmp_timer_function_t)

    If a response to a query didn't come in time, remove (S,G)s.
*/
/* static void */
/* igmp_query_resp_exp (vlib_main_t * vm, vlib_node_runtime_t * rt, */
/* 		     igmp_main_t * im, igmp_timer_t * timer) */
/* { */
/*   igmp_config_t *config; */
/* /\* TODO: group-specific query: pass group key in timer *\/ */
/*   igmp_group_t *group = NULL; */

/*   u32 sw_if_index = timer->sw_if_index; */

/*   pool_put (im->timers, timer); */

/*   config = igmp_config_lookup (im, sw_if_index); */
/*   if (!config) */
/*     return; */

/*   IGMP_DBG ("query-expired: %U", */
/*             format_vnet_sw_if_index_name, */
/*             vnet_get_main (), config->sw_if_index); */

/*   /\* if group != NULL this is a group-specific qeury timer *\/ */
/*   if (PREDICT_FALSE (group != NULL)) */
/*     { */
/*       if ((group->flags & IGMP_GROUP_FLAG_QUERY_RESP_RECVED) == 0) */
/* 	{ */
/* 	  igmp_clear_group (config, group); */
/* 	  return; */
/* 	} */
/*     } */
/*   /\* if report not received in max resp time clear igmp on interface *\/ */
/*   if ((config->flags & IGMP_CONFIG_FLAG_QUERY_RESP_RECVED) == 0) */
/*     { */
/*       igmp_clear_config (config); */
/*     } */
/* } */

/** \brief igmp create query (v3)
    @param b - vlib buffer
    @param config - configuration that sends the query
    @param group - if not NULL, create Group-specific query

    Create igmp v3 qeury inside vlib buffer b.
    If group == NULL create general query,
    else, create group specific query.
*/
/* static void */
/* igmp_create_query_v3 (vlib_buffer_t * b, igmp_config_t * config, */
/* 		      igmp_group_t * group) */
/* { */
/*   vlib_main_t *vm = vlib_get_main (); */
/*   igmp_membership_query_v3_t *igmp; */
/*   ip_csum_t sum; */
/*   u16 csum; */

/*   igmp = vlib_buffer_get_current (b); */
/*   memset (igmp, 0, sizeof (igmp_membership_query_v3_t)); */

/*   igmp->header.type = IGMP_TYPE_membership_query; */
/*   igmp->header.code = 100; */

/*   config->flags &= ~IGMP_CONFIG_FLAG_QUERY_RESP_RECVED; */
/*   igmp_create_int_timer (vlib_time_now (vm) + ((f64) igmp->header.code / 10), */
/* 			 config->sw_if_index, igmp_query_resp_exp); */

/*   if (PREDICT_FALSE (group != NULL)) */
/*     clib_memcpy (&igmp->dst, &group->key->addr.ip4, sizeof (ip4_address_t)); */

/*   sum = */
/*     ip_incremental_checksum (0, igmp, sizeof (igmp_membership_query_v3_t)); */
/*   csum = ~ip_csum_fold (sum); */
/*   igmp->header.checksum = csum; */

/*   b->current_data += sizeof (igmp_membership_query_v3_t); */
/*   b->current_length += sizeof (igmp_membership_query_v3_t); */
/* } */

/** \brief igmp create ip4
    @param b - vlib buffer
    @param config - igmp configuration
    @param group - igmp membership group
    @param msg_type - message type

    Create ip4 header in vlib buffer b.
*/
/* static void */
/* igmp_create_ip4 (vlib_buffer_t * b, igmp_config_t * config, */
/* 		 igmp_group_t * group, */
/* 		 igmp_msg_type_t msg_type, create_msg_t create_msg) */
/* { */
/*   ip_lookup_main_t *lm = &ip4_main.lookup_main; */
/*   ip4_header_t *ip4; */

/*   ip4 = vlib_buffer_get_current (b); */
/*   memset (ip4, 0, sizeof (ip4_header_t)); */
/*   ip4->ip_version_and_header_length = 0x45; */
/*   ip4->ttl = 1; */
/*   ip4->protocol = IP_PROTOCOL_IGMP; */
/*   ip4->tos = 0xc0; */

/*   ip4_src_address_for_packet (lm, config->sw_if_index, &ip4->src_address); */

/*   switch (msg_type) */
/*     { */
/*     case IGMP_MSG_REPORT: */
/*       ip4->dst_address.as_u32 = IGMP_MEMBERSHIP_REPORT_ADDRESS; */
/*       break; */
/*     case IGMP_MSG_QUERY: */
/*       if (group != NULL) */
/* 	clib_memcpy (&ip4->dst_address, &group->key->addr.ip4, */
/* 		     sizeof (ip4_address_t)); */
/*       else */
/* 	ip4->dst_address.as_u32 = IGMP_GENERAL_QUERY_ADDRESS; */
/*       break; */
/*     } */

/*   b->current_data += ip4_header_bytes (ip4); */
/*   b->current_length += ip4_header_bytes (ip4); */

/*   create_msg (b, config, group); */
/*   ip4->length = clib_host_to_net_u16 (b->current_length); */

/*   ip4->checksum = ip4_header_checksum (ip4); */
/* } */

/** \brief igmp send message
    @param vm - vlib main
    @param node - vlib runtime node
    @param im - igmp main
    @param config - igmp configuration
    @param group - igmp mebership group
    @param msg_type - message tpye

    Send an igmp message. Get free vlib buffer fill it with igmp packet and transmit.
*/
/* static void */
/* igmp_send_msg (vlib_main_t * vm, vlib_node_runtime_t * node, */
/* 	       igmp_main_t * im, igmp_config_t * config, igmp_group_t * group, */
/* 	       igmp_msg_type_t msg_type, create_msg_t create_msg) */
/* { */
/*   u32 bi0 = 0; */
/*   int bogus_length = 0; */
/*   vlib_buffer_t *p0; */
/*   vlib_frame_t *f; */
/*   u32 *to_next; */
/*   vlib_buffer_free_list_t *fl; */


/*   u32 thread_index = vlib_get_thread_index (); */
/*   u32 *to_next; */
/*   igmp_next_t next_index = IGMP_NEXT_IP4_REWRITE_MCAST_NODE; */

/*   u32 n_free_bufs = vec_len (im->buffers[thread_index]); */
/*   if (PREDICT_FALSE (n_free_bufs < 1)) */
/*     { */
/*       vec_validate (im->buffers[thread_index], 1 + n_free_bufs - 1); */
/*       n_free_bufs += */
/* 	vlib_buffer_alloc (vm, &im->buffers[thread_index][n_free_bufs], 1); */
/*       _vec_len (im->buffers[thread_index]) = n_free_bufs; */
/*     } */

/*   u32 n_left_to_next; */
/*   igmp_next_t next0 = next_index; */
/*   vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next); */

/*   if (n_left_to_next > 0) */
/*     { */
/*       vlib_buffer_t *b = 0; */
/*       u32 bi = 0; */

/*       if (n_free_bufs) */
/* 	{ */
/* 	  u32 last_buf = vec_len (im->buffers[thread_index]) - 1; */
/* 	  bi = im->buffers[thread_index][last_buf]; */
/* 	  b = vlib_get_buffer (vm, bi); */
/* 	  _vec_len (im->buffers[thread_index]) = last_buf; */
/* 	  n_free_bufs--; */
/* 	  if (PREDICT_FALSE (n_free_bufs == 0)) */
/* 	    { */
/* 	      n_free_bufs += vlib_buffer_alloc (vm, */
/* 						&im->buffers[thread_index] */
/* 						[n_free_bufs], 1); */
/* 	      _vec_len (im->buffers[thread_index]) = n_free_bufs; */
/* 	    } */

/* 	  b->current_data = 0; */
/* 	  b->current_length = 0; */

/* 	  igmp_create_ip4 (b, config, group, msg_type, create_msg); */

/* 	  b->current_data = 0; */

/* 	  b->total_length_not_including_first_buffer = 0; */
/* 	  b->flags = VLIB_BUFFER_TOTAL_LENGTH_VALID; */
/* 	  vnet_buffer (b)->sw_if_index[VLIB_RX] = (u32) ~ 0; */
/* 	  vnet_buffer (b)->ip.adj_index[VLIB_TX] = config->adj_index; */
/* 	  b->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED; */
/* 	} */

/*       to_next[0] = bi; */
/*       to_next += 1; */
/*       n_left_to_next -= 1; */

/*       vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next, */
/* 				       n_left_to_next, bi, next0); */
/*     } */
/*   vlib_put_next_frame (vm, node, next_index, n_left_to_next); */
/* } */

/** \brief igmp send query (igmp_timer_function_t)

    Send an igmp query.
    If the timer holds group key, send Group-Specific query,
    else send General query.
*/
/* static void */
/* igmp_send_query (vlib_main_t * vm, vlib_node_runtime_t * rt, igmp_main_t * im, */
/* 		 igmp_timer_t * timer) */
/* { */
/*   igmp_config_t *config; */
/* /\* TODO: group-specific query: pass group key in timer *\/ */
/*   igmp_group_t *group = NULL; */

/*   u32 sw_if_index = timer->sw_if_index; */

/*   pool_put (im->timers, timer); */

/*   config = igmp_config_lookup (im, sw_if_index); */
/*   if (!config) */
/*     return; */

/*   /\* TODO: implement IGMPv2 *\/ */
/*   igmp_send_msg (vm, rt, im, config, group, */
/* 		 IGMP_MSG_QUERY, igmp_create_query_v3); */

/*   /\* in case of group query we don't want to set up another qery timer *\/ */
/*   if (PREDICT_TRUE (!group)) */
/*     igmp_create_int_timer (vlib_time_now (vm) + IGMP_QUERY_TIMER, sw_if_index, */
/* 			   igmp_send_query); */
/* } */

/** \brief igmp send report (igmp_timer_function_t)

    Send igmp membership report.
*/
/* void */
/* igmp_send_report (vlib_main_t * vm, vlib_node_runtime_t * rt, */
/* 		  igmp_main_t * im, igmp_timer_t * timer) */
/* { */
/*   igmp_config_t *config; */

/*   u32 sw_if_index = timer->sw_if_index; */

/*   pool_put (im->timers, timer); */

/*   config = igmp_config_lookup (im, sw_if_index); */
/*   if (!config) */
/*     return; */

/*   if (config->flags & IGMP_CONFIG_FLAG_CAN_SEND_REPORT) */
/*     { */
/*       /\* pass NULL as group to send all groups at once *\/ */
/*       igmp_send_msg (vm, rt, im, config, NULL, */
/* 		     IGMP_MSG_REPORT, igmp_create_report_v3); */
/*       /\* WIP: unset flag after all reports sent *\/ */
/*       config->flags &= ~IGMP_CONFIG_FLAG_CAN_SEND_REPORT; */
/*     } */
/* } */

/** \brief igmp send state changed (igmp_timer_function_t)

    Send report if an (S,G) filter has changed.
*/
/* static void */
/* igmp_send_state_changed (vlib_main_t * vm, vlib_node_runtime_t * rt, */
/* 			 igmp_main_t * im, igmp_timer_t * timer) */
/* { */
/*   igmp_config_t *config; */
/*   igmp_group_t *group; */
/*   igmp_src_t *src; */
/*   igmp_key_t gkey; */

/*   u32 sw_if_index = timer->sw_if_index; */

/*   ASSERT (timer->data); */
/*   clib_memcpy (&gkey, timer->data, sizeof (igmp_key_t)); */

/*   pool_put (im->timers, timer); */

/*   config = igmp_config_lookup (im, sw_if_index); */
/*   if (!config) */
/*     return; */

/*   group = igmp_group_lookup (config, &gkey); */
/*   if (!group) */
/*     return; */

/*   IGMP_DBG ("state-changed: %U %U", */
/*             format_igmp_key, group->key, */
/*             format_vnet_sw_if_index_name, */
/*             vnet_get_main (), config->sw_if_index); */

/*   igmp_send_msg (vm, rt, im, config, group, */
/* 		 IGMP_MSG_REPORT, igmp_create_report_v3); */

/*   if (group->type == IGMP_MEMBERSHIP_GROUP_change_to_include) */
/*     { */
/*       igmp_key_t new_gkey; */
/*       igmp_group_t *new_group; */
/*       igmp_src_t *new_src; */

/*       clib_memcpy (&new_gkey.addr, &group->key->addr, */
/* 		   sizeof (ip46_address_t)); */
/*       new_gkey.group_type = IGMP_MEMBERSHIP_GROUP_mode_is_include; */

/*       new_group = igmp_group_lookup (config, &new_gkey); */
/*       if (!new_group) */
/* 	{ */
/* 	  /\* get valid pointer to old group *\/ */
/* 	  group = igmp_group_lookup (config, &gkey); */
/*           new_group = igmp_group_alloc (config, &new_gkey); */
/* 	} */
/*       /\* *INDENT-OFF* *\/ */
/*       /\* loop through old group sources *\/ */
/*       FOR_EACH_SRC (src, group, IGMP_FILTER_MODE_INCLUDE,*/
/*         ({ */
/* 	  /\* add sources to new group *\/ */
/* 	  new_src = igmp_src_lookup (new_group, src->key); */
/* 	  if (!new_src) */
/* 	    { */
/*               new_src = igmp_src_alloc (new_group, src->key); */
/* 	    } */
/* 	})); */
/*       /\* *INDENT-ON* *\/ */
/*     } */

/*   /\* remove group *\/ */
/*   igmp_clear_group (config, group); */
/* } */

/** \brief igmp source expiration (igmp_timer_function_t)

    Remove expired (S,G) from group.
*/
/* static void */
/* igmp_src_exp (vlib_main_t * vm, vlib_node_runtime_t * rt, */
/* 	      igmp_main_t * im, igmp_timer_t * timer) */
/* { */
/*   igmp_config_t *config; */
/*   igmp_group_t *group; */
/*   igmp_src_t *src; */

/*   ASSERT (timer->data); */

/*   igmp_key_t *gkey = (igmp_key_t *) & ((igmp_key_t *) timer->data)[0]; */
/*   igmp_key_t *skey = (igmp_key_t *) & ((igmp_key_t *) timer->data)[1]; */

/*   config = igmp_config_lookup (im, timer->sw_if_index); */
/*   if (!config) */
/*     goto done; */
/*   group = igmp_group_lookup (config, gkey); */
/*   if (!group) */
/*     goto done; */
/*   src = igmp_src_lookup (group, skey); */
/*   if (!src) */
/*     goto done; */
/*   /\* check if this timer is valid *\/ */
/*   if (timer->exp_time != src->exp_time) */
/*     { */
/*       timer->exp_time = src->exp_time; */
/*       igmp_sort_timers (im->timers); */
/*       return; */
/*     } */

/*   /\* source timer expired, remove src *\/ */
/*   igmp_update (vm, timer->sw_if_index, */
/*                &skey->addr, &gkey->addr, */
/*                IGMP_MEMBERSHIP_GROUP_block_old_sources); */
/* done: */
/*   clib_mem_free (timer->data); */
/*   pool_put (im->timers, timer); */
/* } */

int igmp_handle_query (int q)
{
  /*
    Section 5.2
    "When a system receives a Query, it does not respond immediately.
    Instead, it delays its response by a random amount of time, bounded
    by the Max Resp Time value derived from the Max Resp Code in the
    received Query message.  A system may receive a variety of Queries on
    different interfaces and of different kinds (e.g., General Queries,
    Group-Specific Queries, and Group-and-Source-Specific Queries), each
    of which may require its own delayed response.

    Before scheduling a response to a Query, the system must first
    consider previously scheduled pending responses and in many cases
    schedule a combined response.  Therefore, the system must be able to
    maintain the following state:

    o A timer per interface for scheduling responses to General Queries.

    o A per-group and interface timer for scheduling responses to Group-
    Specific and Group-and-Source-Specific Queries.

    o A per-group and interface list of sources to be reported in the
    response to a Group-and-Source-Specific Query."
  */

  /*
    5.2
    "When a new Query with the Router-Alert option arrives on an
    interface"
    UNSUPPORTED
  */
  /*
   * Section A.2 no host suppression
   */

  return (1);}

int
igmp_update (vlib_main_t * vm, u32 sw_if_index,
             const ip46_address_t * saddrs,
             const ip46_address_t * gaddr,
             igmp_mode_t mode,
             igmp_membership_group_v3_type_t group_type)
{
  //igmp_main_t *im = &igmp_main;
  const ip46_address_t * saddr;
  igmp_config_t * config;
  igmp_group_t * group;
  /* igmp_key_t skey; */
  /* igmp_key_t gkey; */
  /*
   * RFC 3376 Section 2
   " For a given combination of socket, interface, and multicast address,
   only a single filter mode and source list can be in effect at any one
   time.  However, either the filter mode or the source list, or both,
   may be changed by subsequent IPMulticastListen requests that specify
   the same socket, interface, and multicast address.  Each subsequent
   request completely replaces any earlier request for the given socket,
   interface and multicast address."
  */
  int rv = 0;
  IGMP_DBG ("update: (%U %U) %U %U mode:%d",
            format_igmp_key, saddrs,
            format_igmp_key, gaddr,
            format_vnet_sw_if_index_name, vnet_get_main (),
            sw_if_index, format_igmp_membership_group_type,
            group_type, mode);
  /*
   * find configuration, if it dosn't exist, then this interface is
   * not IGMP enabled
   */
  config = igmp_config_lookup (sw_if_index);

  if (!config)
    {
      rv = VNET_API_ERROR_INVALID_INTERFACE; goto error;
    }
  if (config->mode != mode)
    {
      rv = VNET_API_ERROR_INVALID_INTERFACE; goto error;
    }

  /* find igmp group, if it dosn't exist, create new */
  group = igmp_group_lookup (config, gaddr);

  if (!group)
    {
      group = igmp_group_alloc (config, gaddr, group_type);

      /* new group implies create all source */
      vec_foreach (saddr, saddrs)
        {
          igmp_src_alloc (group, saddr, mode);
        }

      /*
       * Send state changed event report for the group
       */
      igmp_send_state_change_group_report_v3 (config->sw_if_index,
                                              group);
    }
  /*   } */
  /* else */
  /*   { */
  /*     rv = -1; */
  /*     goto error; */
  /*   } */
  /*   } */
  /* else */
  /*   { */
  /*     config = igmp_config_lookup (im, sw_if_index); */
  /*     if (config) */
  /*       { */
  /*         gkey.group_type = IGMP_MEMBERSHIP_GROUP_mode_is_filter_include; */
  /*         group = igmp_group_lookup (config, &gkey); */
  /*         if (group) */
  /*           { */
  /*             src = igmp_src_lookup (group, &skey); */
  /*             if (src) */
  /*            { */
  /*              /\* add source to block_all_sources group *\/ */
  /*              igmp_key_t new_gkey = { */
  /*                .addr = gkey.addr, */
  /*                .group_type = IGMP_MEMBERSHIP_GROUP_block_old_sources, */
  /*              }; */
  /*              igmp_group_t *new_group; */
  /*              igmp_src_t *new_src; */

  /*              new_group = igmp_group_lookup (config, &new_gkey); */
  /*              if (!new_group) */
  /*                { */
  /*                  new_group = igmp_group_alloc (config, &new_gkey); */
  /*                  /\* refetch the old group in case the pools realloc *\/ */
  /*                  group = igmp_group_lookup (config, &gkey); */
  /*                } */
  /*              new_src = igmp_src_lookup (new_group, &skey); */
  /*              if (!new_src) */
  /*                { */
  /*                  new_src = igmp_src_alloc (new_group, &skey); */
  /*                  src = igmp_src_lookup (group, &skey); */
  /*                } */

  /*              /\* notify all registered api clients *\/ */
  /*              if (IGMP_MODE_ROUTER == config->mode) */
  /*                igmp_event (im, config, new_group, new_src); */
  /*              else */
  /*                igmp_create_group_timer (0, sw_if_index, new_group->key, */
  /*                                         igmp_send_state_changed); */
  /*              /\* remove source form mode_is_filter_include group *\/ */
  /*              igmp_src_free (src, group, config); */
  /*            } */
  /*             else */
  /*            { */
  /*              rv = -1; */
  /*              goto error; */
  /*            } */
  /*           } */
  /*         else */
  /*           { */
  /*             rv = -1; */
  /*             goto error; */
  /*           } */
  /*       } */
  /*     else */
  /*       { */
  /*         rv = -1; */
  /*         goto error; */
  /*       } */
  /*   } */

  /*
    4.2.12
    If a change of source list results in both allowing new sources and
    blocking old sources, then two Group Records are sent for the same
    multicast address, one of type ALLOW_NEW_SOURCES and one of type
    BLOCK_OLD_SOURCES."
  */
  /* Immediate state-change report required after invocation of API
     RFC 3376, section 5.1
  */
  /*
   * RFC 3376 Section 5.1
   *  To cover the possibility of the State-Change Report being missed by
   * one or more multicast routers, it is retransmitted [Robustness
   * Variable] - 1 more times, at intervals chosen at random from the
   * range (0, [Unsolicited Report Interval]).
   *
   If more changes to the same interface state entry occur before all
   the retransmissions of the State-Change Report for the first change
   have been completed, each such additional change triggers the
   immediate transmission of a new State-Change Report.

  */
  /*
    4.2.16
    "   If the set of Group Records required in a Report does not fit within
    the size limit of a single Report message (as determined by the MTU
    of the network on which it will be sent), the Group Records are sent
    in as many Report messages as needed to report the entire set.

    If a single Group Record contains so many source addresses that it
    does not fit within the size limit of a single Report message, if its
    Type is not MODE_IS_EXCLUDE or CHANGE_TO_EXCLUDE_MODE, it is split
    into multiple Group Records, each containing a different subset of
    the source addresses and each sent in a separate Report message.  If
    its Type is MODE_IS_EXCLUDE or CHANGE_TO_EXCLUDE_MODE, a single Group
    Record is sent, containing as many source addresses as can fit, and   the remaining source addresses are not reported; though the choice of
    which sources to report is arbitrary, it is preferable to report the
    same set of sources in each subsequent report, rather than reporting
    different sources each time."
  */

 error:
  return (rv);
}

/**
 * the set of present sources minus the new set
 */
static ip46_address_t *
igmp_group_present_minus_new (igmp_group_t *group,
                              igmp_filter_mode_t mode,
                              const ip46_address_t *saddrs)
{
  const ip46_address_t *s1;
  ip46_address_t *pmn;
  igmp_src_t *src;

  pmn = NULL;

  /* *INDENT-OFF* */
  if (0 == vec_len(saddrs))
    {
      FOR_EACH_SRC(src, group, mode,
        ({
          vec_add1(pmn, *src->key);
        }));
    }
  else
    {
      FOR_EACH_SRC(src, group, mode,
        ({
          vec_foreach(s1, saddrs)
            {
              if (s1->ip4.as_u32 == src->key->ip4.as_u32)
                break;
            }

          if (s1->ip4.as_u32 != src->key->ip4.as_u32)
            vec_add1(pmn, *s1);
        }));
    }
  /* *INDENT-OFF* */

  return (pmn);
}

/**
 * the set of new sources minus the present set
 */
static ip46_address_t *
igmp_group_new_minus_present (igmp_group_t *group,
                              igmp_filter_mode_t mode,
                              const ip46_address_t *saddrs)
{
  const ip46_address_t *s1;
  ip46_address_t *npm;
  igmp_src_t *src;

  npm = NULL;

  vec_foreach(s1, saddrs)
    {
      FOR_EACH_SRC(src, group, mode,
        ({
          if (s1->ip4.as_u32 == src->key->ip4.as_u32)
            break;
        }));

      if (s1->ip4.as_u32 != src->key->ip4.as_u32)
        vec_add1(npm, *s1);
    }

  return (npm);
}


static u32
igmp_group_n_srcs (igmp_group_t *group,
                   igmp_filter_mode_t mode)
{
  return (hash_elts(group->igmp_src_by_key[mode]));
}

int
igmp_listen (vlib_main_t * vm,
             igmp_filter_mode_t mode,
             u32 sw_if_index,
             const ip46_address_t * saddrs,
             const ip46_address_t * gaddr)
{
  //igmp_main_t *im = &igmp_main;
  const ip46_address_t * saddr;
  igmp_config_t * config;
  igmp_group_t * group;
  igmp_src_t * src;
  /* igmp_key_t skey; */
  /* igmp_key_t gkey; */
  /*
   * RFC 3376 Section 2
   " For a given combination of socket, interface, and multicast address,
   only a single filter mode and source list can be in effect at any one
   time.  However, either the filter mode or the source list, or both,
   may be changed by subsequent IPMulticastListen requests that specify
   the same socket, interface, and multicast address.  Each subsequent
   request completely replaces any earlier request for the given socket,
   interface and multicast address."
  */
  int rv = 0;
  IGMP_DBG ("listen: (%U, %U) %U %U",
            format_igmp_src_addr_list, saddrs,
            format_igmp_key, gaddr,
            format_vnet_sw_if_index_name, vnet_get_main (),
            sw_if_index, format_igmp_filter_mode, mode);
  /*
   * find configuration, if it dosn't exist, then this interface is
   * not IGMP enabled
   */
  config = igmp_config_lookup (sw_if_index);

  if (!config)
    {
      rv = VNET_API_ERROR_INVALID_INTERFACE;
      goto error;
    }
  if (config->mode != IGMP_MODE_HOST)
    {
      rv = VNET_API_ERROR_INVALID_INTERFACE;
      goto error;
    }

  /* find igmp group, if it dosn't exist, create new */
  group = igmp_group_lookup (config, gaddr);

  if (!group)
    {
      group = igmp_group_alloc (config, gaddr, mode);

      /* new group implies create all source */
      vec_foreach (saddr, saddrs)
        {
          igmp_src_alloc (group, saddr, mode);
        }

      /*
       * Send state changed event report for the group
       */
      igmp_send_state_change_group_report_v3 (config->sw_if_index,
                                              group);
    }
  else
    {
      IGMP_DBG ("... update (%U, %U) %U %U",
                format_igmp_src_addr_list, saddrs,
                format_igmp_key, gaddr,
                format_vnet_sw_if_index_name, vnet_get_main (),
                sw_if_index, format_igmp_filter_mode, mode);

      /*
       * RFC 3367 Section 5.1
       *
       *   Old State         New State         State-Change Record Sent
       *   ---------         ---------         ------------------------
       *
       * 1) INCLUDE (A)       INCLUDE (B)       ALLOW (B-A), BLOCK (A-B)
       * 2) EXCLUDE (A)       EXCLUDE (B)       ALLOW (A-B), BLOCK (B-A)
       * 3) INCLUDE (A)       EXCLUDE (B)       TO_EX (B)
       * 4) EXCLUDE (A)       INCLUDE (B)       TO_IN (B)
       *
       * N.B. We do not split state-change records for pending transfer
       * hence there is no merge logic required.
       */

      if (IGMP_FILTER_MODE_INCLUDE == mode)
        {
          ip46_address_t *added, *removed;
          u32 n_bytes, n_groups;
          vlib_buffer_t *b;

          /*
           * find the list of sources that have been added and removed from
           * the include set
           */
          removed = igmp_group_present_minus_new(group, IGMP_FILTER_MODE_INCLUDE, saddrs);
          added = igmp_group_new_minus_present(group, IGMP_FILTER_MODE_INCLUDE, saddrs);

          if (!(vec_len(added) || vec_len(removed)))
            /* no change => done */
            goto error;

          b = igmp_pkt_build_report_v3 (sw_if_index, group);
          n_bytes = n_groups = 0;

          if (vec_len(added)) {
            n_bytes += igmp_pkt_report_v3_add_report(b, group->key,
                                                     added,
                                                     IGMP_MEMBERSHIP_GROUP_allow_new_sources);
            n_groups++;
          }

          if (vec_len(removed)) {
            n_bytes += igmp_pkt_report_v3_add_report(b, group->key,
                                                     removed,
                                                     IGMP_MEMBERSHIP_GROUP_block_old_sources);
            n_groups++;
          }

          IGMP_DBG ("... added %U", format_igmp_src_addr_list, added);
          IGMP_DBG ("... removed %U", format_igmp_src_addr_list, removed);

          igmp_pkt_send_report_v3 (b, config->sw_if_index, n_bytes, n_groups);

          /*
           * clear the group of the old sources and populate it with the new
           * set requested
           */
          FOR_EACH_SRC (src, group, IGMP_FILTER_MODE_INCLUDE,
            ({
              igmp_src_free(src, group);
            }));
          vec_foreach (saddr, saddrs)
            {
              igmp_src_alloc (group, saddr, mode);
            }

          if (0 == igmp_group_n_srcs(group, mode))
            igmp_clear_group(config, group);

          vec_free (added);
          vec_free (removed);
        }
      else
        {
          /*
           * The control plane is excluding some sources.
           *  - First; check for those that are present in the include list
           *  - Second; check add them to the exlude list 
           */
          /* ip4_address_t *removed_includes; */

          /* removed_includes = igmp_group_mk_overlap(group, */
          /*                                          IGMP_FILTER_MODE_INCLUDE, */
          /*                                          saddrs); */

          /* if (vec_len(removed_includes) == */
          /*     igmp_group_n_srcs(group, IGMP_FILTER_MODE_INCLUDE)) */
          /*   { */
          /*     /\* */
          /*      * all change from include to exclude (case 3 above) */
          /*      *\/ */
          /*   } */
          /* else */
          /*   { */
          /*     /\* */
          /*      * some changes from exclude to include - case 1 */
          /*      *\/ */
          /*   } */
          /* vec_free (removed_includes); */
        }
    }

 error:
  return (rv);
}

/** \brief igmp hardware interface link up down
    @param vnm - vnet main
    @param hw_if_index - interface hw_if_index
    @param flags - hw interface flags

    If an interface goes down, remove its (S,G)s.
*/
static walk_rc_t
igmp_sw_if_down (vnet_main_t * vnm, u32 sw_if_index, void *ctx)
{
  igmp_config_t * config;
  config = igmp_config_lookup (sw_if_index);
  IGMP_DBG ("down: %U",
            format_vnet_sw_if_index_name, vnet_get_main (),
            sw_if_index); if (NULL != config)
                            {
                              igmp_clear_config (config);}

  return (WALK_CONTINUE);}

static clib_error_t *
igmp_hw_interface_link_up_down (vnet_main_t * vnm,
                                u32 hw_if_index, u32 flags)
{
  clib_error_t * error = NULL;
  /* remove igmp state from down interfaces */
  if (!(flags & VNET_HW_INTERFACE_FLAG_LINK_UP))
    vnet_hw_interface_walk_sw (vnm, hw_if_index, igmp_sw_if_down,
                               NULL); return error;}

VNET_HW_INTERFACE_LINK_UP_DOWN_FUNCTION
(igmp_hw_interface_link_up_down);
int igmp_enable_disable (u32 sw_if_index, u8 enable,
                         igmp_mode_t mode)
{
  igmp_config_t * config;
  igmp_main_t * im = &igmp_main;
  u32 mfib_index;
  IGMP_DBG ("%s:  %U", (enable ? "Enabled" : "Disabled"),
            format_vnet_sw_if_index_name, vnet_get_main (),
            sw_if_index); fib_route_path_t for_us_path =
                            {
                              .frp_proto = fib_proto_to_dpo (FIB_PROTOCOL_IP4),.frp_addr =
                              zero_addr,.frp_sw_if_index = 0xffffffff,.frp_fib_index =
                              0,.frp_weight = 1,.frp_flags = FIB_ROUTE_PATH_LOCAL,};
  fib_route_path_t via_itf_path =
    {
      .frp_proto = fib_proto_to_dpo (FIB_PROTOCOL_IP4),.frp_addr =
      zero_addr,.frp_sw_if_index = sw_if_index,.frp_fib_index =
      0,.frp_weight = 1,};
  /* find configuration, if it dosn't exist, create new */
  config = igmp_config_lookup (sw_if_index);
  mfib_index =
    mfib_table_get_index_for_sw_if_index (FIB_PROTOCOL_IP4,
                                          sw_if_index);
  if (!config && enable)
    {
      vec_validate_init_empty (im->igmp_config_by_sw_if_index,
                               sw_if_index, ~0);
      pool_get (im->configs, config);
      memset (config, 0, sizeof (igmp_config_t));
      config->sw_if_index = sw_if_index;
      config->igmp_group_by_key =
        hash_create_mem (0, sizeof (igmp_key_t), sizeof (uword));
      /* use IGMPv3 by default */
      config->igmp_ver = IGMP_V3;
      config->robustness_var = IGMP_DEFAULT_ROBUSTNESS_VARIABLE;
      // config->flags |= IGMP_CONFIG_FLAG_QUERY_RESP_RECVED;
      config->mode = mode;

      /* if (IGMP_MODE_ROUTER == mode) */
      /*       { */
      /*         /\* create query timer *\/ */
      /*         igmp_create_int_timer (vlib_time_now (vm) + IGMP_QUERY_TIMER, */
      /*                             sw_if_index, igmp_send_query); */
      /*       } */

      config->adj_index =
        adj_mcast_add_or_lock (FIB_PROTOCOL_IP4, VNET_LINK_IP4,
                               config->sw_if_index);
      im->igmp_config_by_sw_if_index[config->sw_if_index] =
        (config - im->configs);
      {
        vec_validate (im->n_configs_per_mfib_index, mfib_index);
        im->n_configs_per_mfib_index[mfib_index]++;
        if (1 == im->n_configs_per_mfib_index[mfib_index])
          {
	    /* first config in this FIB */
	    mfib_table_entry_path_update (mfib_index,
					  &mpfx_general_query,
					  MFIB_SOURCE_IGMP,
					  &for_us_path,
					  MFIB_ITF_FLAG_FORWARD);
	    mfib_table_entry_path_update (mfib_index,
					  &mpfx_report,
					  MFIB_SOURCE_IGMP,
					  &for_us_path,
					  MFIB_ITF_FLAG_FORWARD);}
        mfib_table_entry_path_update (mfib_index,
                                      &mpfx_general_query,
                                      MFIB_SOURCE_IGMP,
                                      &via_itf_path,
                                      MFIB_ITF_FLAG_ACCEPT);
        mfib_table_entry_path_update (mfib_index, &mpfx_report,
                                      MFIB_SOURCE_IGMP, &via_itf_path,
                                      MFIB_ITF_FLAG_ACCEPT);}
    }
  else
    if (config && !enable)
      {
        vec_validate (im->n_configs_per_mfib_index, mfib_index);
        im->n_configs_per_mfib_index[mfib_index]--;
        if (0 == im->n_configs_per_mfib_index[mfib_index])
          {
	    /* last config in this FIB */
	    mfib_table_entry_path_remove (mfib_index,
					  &mpfx_general_query,
					  MFIB_SOURCE_IGMP, &for_us_path);
	    mfib_table_entry_path_remove (mfib_index,
					  &mpfx_report,
					  MFIB_SOURCE_IGMP, &for_us_path);}

        mfib_table_entry_path_remove (mfib_index,
                                      &mpfx_general_query,
                                      MFIB_SOURCE_IGMP, &via_itf_path);
        mfib_table_entry_path_remove (mfib_index,
                                      &mpfx_report,
                                      MFIB_SOURCE_IGMP, &via_itf_path);
        igmp_clear_config (config);
        im->igmp_config_by_sw_if_index[config->sw_if_index] = ~0;
        hash_free (config->igmp_group_by_key);
        pool_put (im->configs, config);}

  return (0);}

/** \brief igmp initialization
    @param vm - vlib main

    initialize igmp plugin. Initialize igmp_main, set mfib to allow igmp traffic.
*/
static clib_error_t * igmp_init (vlib_main_t * vm)
{
  clib_error_t * error;
  igmp_main_t * im = &igmp_main;
  vlib_thread_main_t * tm = vlib_get_thread_main ();
  if ((error = vlib_call_init_function (vm, ip4_lookup_init)))
    return error;
  im->igmp_api_client_by_client_index =
    hash_create (0, sizeof (u32));
  vec_validate_aligned (im->buffers, tm->n_vlib_mains - 1,
                        CLIB_CACHE_LINE_BYTES);
  ip4_register_protocol (IP_PROTOCOL_IGMP, igmp_input_node.index);
  im->logger = vlib_log_register_class ("igmp", 0);
  IGMP_DBG ("initialized"); return (error);}

VLIB_INIT_FUNCTION (igmp_init);
/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "IGMP messaging",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
