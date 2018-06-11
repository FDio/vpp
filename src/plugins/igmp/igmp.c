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

#include <limits.h>
#include <float.h>

igmp_main_t igmp_main;

void
igmp_clear_group (igmp_config_t * config, igmp_group_t * group)
{
  igmp_src_t *src;

  ASSERT (config);
  ASSERT (group);

  IGMP_DBG ("group_type %u, sw_if_index %d", group->type,
	    config->sw_if_index);

  /* *INDENT-OFF* */
  pool_foreach (src, group->srcs, (
    {
      clib_mem_free (src->key);
    }));
  /* *INDENT-ON* */
  pool_free (group->srcs);
  hash_free (group->igmp_src_by_key);

  hash_unset_mem (config->igmp_group_by_key, group->key);
  clib_mem_free (group->key);
  pool_put (config->groups, group);
}

void
igmp_clear_config (igmp_config_t * config)
{
  igmp_main_t *im = &igmp_main;
  igmp_group_t *group;

  ASSERT (config);
  /* *INDENT-OFF* */
  pool_foreach (group, config->groups, (
    {
      igmp_clear_group (config, group);
    }));
  /* *INDENT-ON* */
  pool_free (config->groups);
  hash_free (config->igmp_group_by_key);

  hash_unset (im->igmp_config_by_sw_if_index, config->sw_if_index);
  pool_put (im->configs, config);
}

/** \brief igmp timer compare
    @param _a - igmp timer
    @param _b - igmp timer

    Compare function for igmp_timer_t sorting.
*/
int
igmp_timer_compare (const void *_a, const void *_b)
{
  const igmp_timer_t *a = _a;
  const igmp_timer_t *b = _b;
  f64 dt = b->exp_time - a->exp_time;
  return dt < 0 ? -1 : (dt > 0 ? +1 : 0);
}

void
igmp_sort_timers (igmp_timer_t * timers)
{
  vlib_main_t *vm = vlib_get_main ();

  qsort (timers, vec_len (timers), sizeof (igmp_timer_t), igmp_timer_compare);

  vlib_process_signal_event (vm, igmp_timer_process_node.index,
			     IGMP_PROCESS_EVENT_UPDATE_TIMER, 0);
}

void
igmp_create_int_timer (f64 time, u32 sw_if_index,
		       igmp_timer_function_t * func)
{
  igmp_main_t *im = &igmp_main;
  igmp_timer_t *timer;

  pool_get (im->timers, timer);
  memset (timer, 0, sizeof (igmp_timer_t));
  timer->func = func;
  timer->exp_time = time;
  timer->sw_if_index = sw_if_index;

  igmp_sort_timers (im->timers);
}

void
igmp_create_group_timer (f64 time, u32 sw_if_index, igmp_key_t * gkey,
			 igmp_timer_function_t * func)
{
  igmp_main_t *im = &igmp_main;
  igmp_timer_t *timer;

  pool_get (im->timers, timer);
  memset (timer, 0, sizeof (igmp_timer_t));
  timer->func = func;
  timer->exp_time = time;
  timer->sw_if_index = sw_if_index;


  ASSERT (gkey);
  /* duplicate keys, to prevent segmentation fault if (S,G) is removed */
  timer->data = clib_mem_alloc (sizeof (igmp_key_t));
  clib_memcpy (&((igmp_key_t *) timer->data)[0], gkey, sizeof (igmp_key_t));

  igmp_sort_timers (im->timers);
}

void
igmp_create_src_timer (f64 time, u32 sw_if_index, igmp_key_t * gkey,
		       igmp_key_t * skey, igmp_timer_function_t * func)
{
  igmp_main_t *im = &igmp_main;
  igmp_timer_t *timer;

  pool_get (im->timers, timer);
  memset (timer, 0, sizeof (igmp_timer_t));
  timer->func = func;
  timer->exp_time = time;
  timer->sw_if_index = sw_if_index;

  ASSERT (gkey);
  ASSERT (skey);
  /* duplicate keys, to prevent segmentation fault if (S,G) is removed */
  timer->data = clib_mem_alloc (sizeof (igmp_key_t) * 2);
  clib_memcpy (&((igmp_key_t *) timer->data)[0], gkey, sizeof (igmp_key_t));
  clib_memcpy (&((igmp_key_t *) timer->data)[1], skey, sizeof (igmp_key_t));

  igmp_sort_timers (im->timers);
}

/** \brief igmp get next timer
    @param im - igmp main

    Get next timer.
*/
always_inline igmp_timer_t *
igmp_get_next_timer (igmp_main_t * im)
{
  if (pool_elts (im->timers) > 0)
    return vec_elt_at_index (im->timers, pool_elts (im->timers) - 1);
  return NULL;
}

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

/* TODO: divide (S,G)s to multiple reports...
 * - create report limited by <packet size|number of (S,G)s>?
 * - save loop state
 * - on next timer continue loop
 * - case of new query -> reset loop
 */

/** \brief igmp create report all (v3)
    @param b - vlib buffer
    @param config - igmp configuration
    @param group - igmp group

    Create IGMPv3 report. If group is NULL, send all groups on interface.
*/
static void
igmp_create_report_v3 (vlib_buffer_t * b, igmp_config_t * config,
		       igmp_group_t * group)
{
  ip_csum_t sum;
  u16 csum;
  u32 len = 0;
  int i;

  igmp_src_t *src;

  igmp_membership_group_v3_t *igmp_group;

  len = sizeof (igmp_membership_report_v3_t);

  igmp_membership_report_v3_t *igmp =
    (igmp_membership_report_v3_t *) (vlib_buffer_get_current (b));
  memset (igmp, 0, sizeof (igmp_membership_report_v3_t));

  igmp->header.type = IGMP_TYPE_membership_report_v3;
  igmp->n_groups =
    clib_net_to_host_u16 ((group) ? 1 : pool_elts (config->groups));

  /* get pointer to first group */
  igmp_group = igmp->groups;

  /* if group is not NULL, send the specified group */
  if (group)
    {
      memset (igmp_group, 0, sizeof (igmp_membership_group_v3_t));
      igmp_group->type = group->type;
      igmp_group->n_src_addresses =
	clib_host_to_net_u16 (pool_elts (group->srcs));
      igmp_group->dst_address = group->addr.ip4;
      i = 0;
      /* *INDENT-OFF* */
      pool_foreach (src, group->srcs, (
	{
	  igmp_group->src_addresses[i++] = src->addr.ip4;
	}));
      /* *INDENT-ON* */
      len += sizeof (ip4_address_t) * i;
      len += sizeof (igmp_membership_group_v3_t);
    }
  else
    {
      /* *INDENT-OFF* */
      pool_foreach (group, config->groups, (
	{
	  memset (igmp_group, 0, sizeof (igmp_membership_group_v3_t));
	  igmp_group->type = group->type;
	  igmp_group->n_src_addresses =
	    clib_host_to_net_u16 (pool_elts (group->srcs));
	  igmp_group->dst_address = group->addr.ip4;
	  i = 0;
	  pool_foreach (src, group->srcs, (
	    {
	      igmp_group->src_addresses[i++] = src->addr.ip4;
	    }));
	  len += sizeof (ip4_address_t) * i;
	  len += sizeof (igmp_membership_group_v3_t);
	  igmp_group = group_ptr (igmp, len);
	}));
      /* *INDENT-ON* */
    }

  sum = ip_incremental_checksum (0, igmp, len);
  csum = ~ip_csum_fold (sum);
  igmp->header.checksum = csum;

  b->current_data += len;
  b->current_length += len;
}

/** \brief igmp create query (v3)
    @param b - vlib buffer
    @param config - configuration that sends the query
    @param group - if not NULL, create Group-specific query

    Create igmp v3 qeury inside vlib buffer b.
    If group == NULL create general query,
    else, create group specific query.
*/
static void
igmp_create_query_v3 (vlib_buffer_t * b, igmp_config_t * config,
		      igmp_group_t * group)
{
  vlib_main_t *vm = vlib_get_main ();
  ip_csum_t sum;
  u16 csum;

  igmp_membership_query_v3_t *igmp =
    (igmp_membership_query_v3_t *) (vlib_buffer_get_current (b));
  memset (igmp, 0, sizeof (igmp_membership_query_v3_t));

  igmp->header.type = IGMP_TYPE_membership_query;
  igmp->header.code = 100;

  config->flags &= ~IGMP_CONFIG_FLAG_QUERY_RESP_RECVED;
  igmp_create_int_timer (vlib_time_now (vm) + (f64) (igmp->header.code / 10),
			 config->sw_if_index, igmp_query_resp_exp);

  if (PREDICT_FALSE (group != NULL))
    clib_memcpy (&igmp->dst, &group->addr.ip4, sizeof (ip4_address_t));

  sum =
    ip_incremental_checksum (0, igmp, sizeof (igmp_membership_query_v3_t));
  csum = ~ip_csum_fold (sum);
  igmp->header.checksum = csum;

  b->current_data += sizeof (igmp_membership_query_v3_t);
  b->current_length += sizeof (igmp_membership_query_v3_t);
}

/** \brief igmp create ip4
    @param b - vlib buffer
    @param config - igmp configuration
    @param group - igmp membership group
    @param is_report - if zero create query, else create report

    Create ip4 header in vlib buffer b.
*/
static void
igmp_create_ip4 (vlib_buffer_t * b, igmp_config_t * config,
		 igmp_group_t * group, u8 is_report)
{
  ip_lookup_main_t *lm = &ip4_main.lookup_main;

  ip4_header_t *ip4 = (ip4_header_t *) (vlib_buffer_get_current (b));
  memset (ip4, 0, sizeof (ip4_header_t));
  ip4->ip_version_and_header_length = 0x45;
  ip4->ttl = 1;
  ip4->protocol = 2;
  ip4->tos = 0xc0;

  u32 if_add_index =
    lm->if_address_pool_index_by_sw_if_index[config->sw_if_index];
  if (PREDICT_TRUE (if_add_index != ~0))
    {
      ip_interface_address_t *if_add =
	pool_elt_at_index (lm->if_address_pool, if_add_index);
      ip4_address_t *if_ip = ip_interface_address_get_address (lm, if_add);
      clib_memcpy (&ip4->src_address, if_ip, sizeof (ip4_address_t));
    }

  if (is_report)
    ip4->dst_address.as_u32 =
      clib_host_to_net_u32 (IGMP_MEMBERSHIP_REPORT_ADDRESS);
  else
    {
      if ((group != NULL))
	clib_memcpy (&ip4->dst_address, &group->addr.ip4,
		     sizeof (ip4_address_t));
      else
	ip4->dst_address.as_u32 =
	  clib_host_to_net_u32 (IGMP_GENERAL_QUERY_ADDRESS);
    }

  b->current_data += ip4_header_bytes (ip4);
  b->current_length += ip4_header_bytes (ip4);

  config->next_create_msg (b, config, group);
  ip4->length = clib_host_to_net_u16 (b->current_length);

  ip4->checksum = ip4_header_checksum (ip4);
}


/** \brief igmp send message
    @param vm - vlib main
    @param node - vlib runtime node
    @param im - igmp main
    @param config - igmp configuration
    @param group - igmp mebership group
    @param is_report - 0 == qeury, else report

    Send an igmp message. Get free vlib buffer fill it with igmp packet and transmit.
*/
static void
igmp_send_msg (vlib_main_t * vm, vlib_node_runtime_t * node,
	       igmp_main_t * im, igmp_config_t * config, igmp_group_t * group,
	       u8 is_report)
{
  u32 thread_index = vlib_get_thread_index ();
  u32 *to_next;
  u32 next_index = IGMP_NEXT_IP4_REWRITE_MCAST_NODE;

  u32 n_free_bufs = vec_len (im->buffers[thread_index]);
  if (PREDICT_FALSE (n_free_bufs < 1))
    {
      vec_validate (im->buffers[thread_index], 1 + n_free_bufs - 1);
      n_free_bufs +=
	vlib_buffer_alloc (vm, &im->buffers[thread_index][n_free_bufs], 1);
      _vec_len (im->buffers[thread_index]) = n_free_bufs;
    }

  u32 n_left_to_next;
  u32 next0 = next_index;
  vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

  if (n_left_to_next > 0)
    {
      vlib_buffer_t *b = 0;
      u32 bi = 0;

      if (n_free_bufs)
	{
	  u32 last_buf = vec_len (im->buffers[thread_index]) - 1;
	  bi = im->buffers[thread_index][last_buf];
	  b = vlib_get_buffer (vm, bi);
	  _vec_len (im->buffers[thread_index]) = last_buf;
	  n_free_bufs--;
	  if (PREDICT_FALSE (n_free_bufs == 0))
	    {
	      n_free_bufs += vlib_buffer_alloc (vm,
						&im->buffers[thread_index]
						[n_free_bufs], 1);
	      _vec_len (im->buffers[thread_index]) = n_free_bufs;
	    }

	  b->current_data = 0;
	  b->current_length = 0;

	  igmp_create_ip4 (b, config, group, is_report);

	  b->current_data = 0;

	  b->total_length_not_including_first_buffer = 0;
	  b->flags = VLIB_BUFFER_TOTAL_LENGTH_VALID;
	  vnet_buffer (b)->sw_if_index[VLIB_RX] = (u32) ~ 0;
	  vnet_buffer (b)->ip.adj_index[VLIB_TX] = config->adj_index;
	  b->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;
	}

      to_next[0] = bi;
      to_next += 1;
      n_left_to_next -= 1;

      vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
				       n_left_to_next, bi, next0);
    }
  vlib_put_next_frame (vm, node, next_index, n_left_to_next);
}

void
igmp_send_query (vlib_main_t * vm, vlib_node_runtime_t * rt, igmp_main_t * im,
		 igmp_timer_t * timer)
{
  igmp_config_t *config;
/* TODO: group-specific query: pass group key in timer */
  igmp_group_t *group = NULL;

  u32 sw_if_index = timer->sw_if_index;

  pool_put (im->timers, timer);

  config = igmp_config_lookup (im, sw_if_index);
  if (!config)
    return;

  /* TODO: implement IGMPv2 */
  config->next_create_msg = igmp_create_query_v3;
  igmp_send_msg (vm, rt, im, config, group, /* is_report */ 0);

  /* in case of group query we don't want to set up another qery timer */
  if (PREDICT_TRUE (!group))
    igmp_create_int_timer (vlib_time_now (vm) + IGMP_QUERY_TIMER, sw_if_index,
			   igmp_send_query);
}

void
igmp_query_resp_exp (vlib_main_t * vm, vlib_node_runtime_t * rt,
		     igmp_main_t * im, igmp_timer_t * timer)
{
  igmp_config_t *config;
/* TODO: group-specific query: pass group key in timer */
  igmp_group_t *group = NULL;

  u32 sw_if_index = timer->sw_if_index;

  pool_put (im->timers, timer);

  config = igmp_config_lookup (im, sw_if_index);
  if (!config)
    return;

  /* if group != NULL this is a group-specific qeury timer */
  if (PREDICT_FALSE (group != NULL))
    {
      if ((group->flags & IGMP_GROUP_FLAG_QUERY_RESP_RECVED) == 0)
	{
	  igmp_clear_group (config, group);
	  return;
	}
    }
  /* if report not received in max resp time clear igmp on interface */
  if ((config->flags & IGMP_CONFIG_FLAG_QUERY_RESP_RECVED) == 0)
    {
      igmp_clear_config (config);
    }
}

void
igmp_send_report (vlib_main_t * vm, vlib_node_runtime_t * rt,
		  igmp_main_t * im, igmp_timer_t * timer)
{
  igmp_config_t *config;

  u32 sw_if_index = timer->sw_if_index;

  pool_put (im->timers, timer);

  config = igmp_config_lookup (im, sw_if_index);
  if (!config)
    return;

  if (config->flags & IGMP_CONFIG_FLAG_CAN_SEND_REPORT)
    {
      /* TODO: implement IGMPv2 and IGMPv1 */
      config->next_create_msg = igmp_create_report_v3;
      /* pass NULL as group to send all groups at once */
      igmp_send_msg (vm, rt, im, config, NULL, /* is_report */ 1);
      /* WIP: unset flag after all reports sent */
      config->flags &= ~IGMP_CONFIG_FLAG_CAN_SEND_REPORT;
    }
}

void
igmp_send_state_changed (vlib_main_t * vm, vlib_node_runtime_t * rt,
			 igmp_main_t * im, igmp_timer_t * timer)
{
  igmp_config_t *config;
  igmp_group_t *group;
  igmp_src_t *src;
  igmp_key_t gkey;

  u32 sw_if_index = timer->sw_if_index;
  IGMP_DBG ("sw_if_index %d", sw_if_index);

  ASSERT (timer->data);
  clib_memcpy (&gkey, timer->data, sizeof (igmp_key_t));

  pool_put (im->timers, timer);

  config = igmp_config_lookup (im, sw_if_index);
  if (!config)
    return;

  group = igmp_group_lookup (config, &gkey);
  if (!group)
    return;

  config->next_create_msg = igmp_create_report_v3;
  igmp_send_msg (vm, rt, im, config, group, /* is_report */ 1);

  IGMP_DBG ("group_type %u", group->type);

  if (group->type == IGMP_MEMBERSHIP_GROUP_change_to_filter_include)
    {
      igmp_key_t new_gkey;
      igmp_group_t *new_group;
      igmp_src_t *new_src;

      clib_memcpy (&new_gkey.data, &group->addr, sizeof (ip46_address_t));
      new_gkey.group_type = IGMP_MEMBERSHIP_GROUP_mode_is_filter_include;

      new_group = igmp_group_lookup (config, &new_gkey);
      if (!new_group)
	{
	  IGMP_DBG ("creating new group...");
	  pool_get (config->groups, new_group);
	  /* get valid pointer to old group */
	  group = igmp_group_lookup (config, &gkey);

	  memset (new_group, 0, sizeof (igmp_group_t));

	  clib_memcpy (&new_group->addr, &group->addr,
		       sizeof (ip46_address_t));
	  new_group->n_srcs = 0;
	  new_group->type = new_gkey.group_type;

	  new_group->key = clib_mem_alloc (sizeof (igmp_key_t));
	  clib_memcpy (new_group->key, &new_gkey, sizeof (igmp_key_t));
	  new_group->igmp_src_by_key =
	    hash_create_mem (0, sizeof (igmp_key_t), sizeof (uword));
	  hash_set_mem (config->igmp_group_by_key, new_group->key,
			new_group - config->groups);
	}
      /* *INDENT-OFF* */
      /* loop through old group sources */
      pool_foreach (src, group->srcs, (
	{
	  /* add sources to new group */
	  new_src = igmp_src_lookup (new_group, src->key);
	  if (!new_src)
	    {
	      pool_get (new_group->srcs, new_src);
	      memset (new_src, 0, sizeof (igmp_src_t));
	      new_group->n_srcs += 1;
	      new_src->key = clib_mem_alloc (sizeof (igmp_key_t));
	      clib_memcpy (new_src->key, src->key, sizeof (igmp_key_t));
	      clib_memcpy (&new_src->addr, &src->addr,
	        sizeof (ip46_address_t));

	      hash_set_mem (new_group->igmp_src_by_key, new_src->key,
		    new_src - new_group->srcs);
	    }
	}));
      /* *INDENT-ON* */
    }

  /* remove group */
  IGMP_DBG ("remove group");
  igmp_clear_group (config, group);
  if (pool_elts (config->groups) == 0)
    {
      hash_unset (im->igmp_config_by_sw_if_index, config->sw_if_index);
      pool_put (im->configs, config);
    }
}

void
igmp_src_exp (vlib_main_t * vm, vlib_node_runtime_t * rt,
	      igmp_main_t * im, igmp_timer_t * timer)
{
  igmp_config_t *config;
  igmp_group_t *group;
  igmp_src_t *src;

  ASSERT (timer->data);

  igmp_key_t *gkey = (igmp_key_t *) & ((igmp_key_t *) timer->data)[0];
  igmp_key_t *skey = (igmp_key_t *) & ((igmp_key_t *) timer->data)[1];

  config = igmp_config_lookup (im, timer->sw_if_index);
  if (!config)
    goto done;
  group = igmp_group_lookup (config, gkey);
  if (!group)
    goto done;
  src = igmp_src_lookup (group, skey);
  if (!src)
    goto done;
  /* check if this timer is valid */
  if (timer->exp_time != src->exp_time)
    {
      timer->exp_time = src->exp_time;
      igmp_sort_timers (im->timers);
      return;
    }

  ip46_address_t saddr;
  ip46_address_t gaddr;
  clib_memcpy (&saddr, skey->data, sizeof (ip46_address_t));
  clib_memcpy (&gaddr, gkey->data, sizeof (ip46_address_t));

  /* source timer expired, remove src */
  igmp_listen (vm, 0, timer->sw_if_index, saddr, gaddr, 0);
done:
  clib_mem_free (timer->data);
  pool_put (im->timers, timer);
}

/** \brief igmp timer process
    @param vm - vlib main
    @param rt - vlib runtime node
    @param f - vlib frame

    Handle igmp timers.
*/
static uword
igmp_timer_process (vlib_main_t * vm, vlib_node_runtime_t * rt,
		    vlib_frame_t * f)
{
  igmp_main_t *im = &igmp_main;
  uword *event_data = 0, event_type;
  f64 time_start;
  igmp_timer_t *timer = NULL;
  while (1)
    {
      /* suspend util timer expires */
      if (NULL != timer)
	vlib_process_wait_for_event_or_clock (vm,
					      timer->exp_time - time_start);
      else
	vlib_process_wait_for_event (vm);
      time_start = vlib_time_now (vm);
      event_type = vlib_process_get_events (vm, &event_data);
      vec_reset_length (event_data);
      if (event_type == IGMP_PROCESS_EVENT_UPDATE_TIMER)
	goto next_timer;
      IGMP_DBG ("time: %f", vlib_time_now (vm));
      /* timer expired */
      if (NULL != timer && timer->func != NULL)
	timer->func (vm, rt, im, timer);
    next_timer:
      timer = igmp_get_next_timer (im);
    }
  return 0;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (igmp_timer_process_node) =
{
  .function = igmp_timer_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "igmp-timer-process",
  .n_next_nodes = IGMP_N_NEXT,
  .next_nodes =  {
    [IGMP_NEXT_IP4_REWRITE_MCAST_NODE] = "ip4-rewrite-mcast",
    [IGMP_NEXT_IP6_REWRITE_MCAST_NODE] = "ip6-rewrite-mcast",
  }
};
/* *INDENT-ON* */

int
igmp_listen (vlib_main_t * vm, u8 enable, u32 sw_if_index,
	     ip46_address_t saddr, ip46_address_t gaddr,
	     u8 cli_api_configured)
{
  igmp_main_t *im = &igmp_main;
  igmp_config_t *config;
  igmp_group_t *group;
  igmp_src_t *src;
  igmp_key_t skey;
  igmp_key_t gkey;

  igmp_membership_group_v3_type_t group_type =
    (cli_api_configured) ?
    IGMP_MEMBERSHIP_GROUP_change_to_filter_include :
    IGMP_MEMBERSHIP_GROUP_mode_is_filter_include;
  int rv = 0;

  /* set the lookup keys */
  skey.group_type = 0;
  gkey.group_type = group_type;
  clib_memcpy (&skey.data, &saddr, sizeof (ip46_address_t));
  clib_memcpy (&gkey.data, &gaddr, sizeof (ip46_address_t));

  if (enable)
    {
      /* find configuration, if it dosn't exist, create new */
      config = igmp_config_lookup (im, sw_if_index);
      if (!config)
	{
	  pool_get (im->configs, config);
	  memset (config, 0, sizeof (igmp_config_t));
	  config->sw_if_index = sw_if_index;
	  config->igmp_group_by_key =
	    hash_create_mem (0, sizeof (igmp_key_t), sizeof (uword));
	  config->cli_api_configured = cli_api_configured;
	  /* use IGMPv3 by default */
	  config->igmp_ver = IGMP_V3;
	  config->robustness_var = IGMP_DEFAULT_ROBUSTNESS_VARIABLE;
	  config->flags |= IGMP_CONFIG_FLAG_QUERY_RESP_RECVED;

	  if (!cli_api_configured)
	    {
	      /* create qery timer */
	      igmp_create_int_timer (vlib_time_now (vm) + IGMP_QUERY_TIMER,
				     sw_if_index, igmp_send_query);
	    }
	  config->adj_index =
	    adj_mcast_add_or_lock (FIB_PROTOCOL_IP4, VNET_LINK_IP4,
				   config->sw_if_index);
	  hash_set (im->igmp_config_by_sw_if_index,
		    config->sw_if_index, config - im->configs);
	}
      else if (config->cli_api_configured != cli_api_configured)
	{
	  rv = -2;
	  goto error;
	}
      /* find igmp group, if it dosn't exist, create new */
      group = igmp_group_lookup (config, &gkey);
      if (!group)
	{
	  pool_get (config->groups, group);
	  memset (group, 0, sizeof (igmp_group_t));
	  group->key = clib_mem_alloc (sizeof (igmp_key_t));
	  clib_memcpy (group->key, &gkey, sizeof (igmp_key_t));
	  clib_memcpy (&group->addr, &gaddr, sizeof (ip46_address_t));
	  group->igmp_src_by_key =
	    hash_create_mem (0, sizeof (igmp_key_t), sizeof (uword));
	  group->n_srcs = 0;
	  group->type = gkey.group_type;
	  if (cli_api_configured)
	    {
	      /* create state-changed report timer with zero timeout */
	      igmp_create_group_timer (0, sw_if_index, group->key,
				       igmp_send_state_changed);
	    }

	  hash_set_mem (config->igmp_group_by_key, group->key,
			group - config->groups);
	}
      /* find source, if it dosn't exist, create new */
      src = igmp_src_lookup (group, &skey);
      if (!src)
	{
	  pool_get (group->srcs, src);
	  memset (src, 0, sizeof (igmp_src_t));
	  group->n_srcs += 1;
	  src->key = clib_mem_alloc (sizeof (igmp_key_t));
	  clib_memcpy (src->key, &skey, sizeof (igmp_key_t));
	  clib_memcpy (&src->addr, &saddr, sizeof (ip46_address_t));
	  if (!cli_api_configured)
	    {
	      /* arm source timer (after expiration remove (S,G)) */
	      igmp_event (im, config, group, src);
	      src->exp_time = vlib_time_now (vm) + IGMP_SRC_TIMER;
	      igmp_create_src_timer (src->exp_time, config->sw_if_index,
				     group->key, src->key, igmp_src_exp);
	    }

	  hash_set_mem (group->igmp_src_by_key, src->key, src - group->srcs);
	}
      else
	{
	  rv = -1;
	  goto error;
	}
    }
  else
    {
      config = igmp_config_lookup (im, sw_if_index);
      if (config)
	{
	  gkey.group_type = IGMP_MEMBERSHIP_GROUP_mode_is_filter_include;
	  group = igmp_group_lookup (config, &gkey);
	  if (group)
	    {
	      src = igmp_src_lookup (group, &skey);
	      if (src)
		{
		  /* add source to block_all_sources group */
		  igmp_key_t new_gkey;
		  igmp_group_t *new_group;

		  clib_memcpy (&new_gkey, &gkey, sizeof (igmp_key_t));
		  new_gkey.group_type =
		    IGMP_MEMBERSHIP_GROUP_block_old_sources;
		  new_group = igmp_group_lookup (config, &new_gkey);
		  if (!new_group)
		    {
		      pool_get (config->groups, new_group);

		      group = igmp_group_lookup (config, &gkey);

		      memset (new_group, 0, sizeof (igmp_group_t));
		      new_group->key = clib_mem_alloc (sizeof (igmp_key_t));
		      clib_memcpy (new_group->key, &new_gkey,
				   sizeof (igmp_key_t));
		      clib_memcpy (&new_group->addr, &group->addr,
				   sizeof (ip46_address_t));
		      new_group->igmp_src_by_key =
			hash_create_mem (0, sizeof (igmp_key_t),
					 sizeof (uword));
		      new_group->n_srcs = 0;
		      new_group->type = new_gkey.group_type;
		      hash_set_mem (config->igmp_group_by_key, new_group->key,
				    new_group - config->groups);
		    }
		  igmp_src_t *new_src;
		  new_src = igmp_src_lookup (new_group, &skey);
		  if (!new_src)
		    {
		      pool_get (new_group->srcs, new_src);
		      memset (new_src, 0, sizeof (igmp_src_t));
		      new_group->n_srcs += 1;
		      new_src->key = clib_mem_alloc (sizeof (igmp_key_t));
		      clib_memcpy (new_src->key, src->key,
				   sizeof (igmp_key_t));
		      clib_memcpy (&new_src->addr, &src->addr,
				   sizeof (ip46_address_t));
		      hash_set_mem (new_group->igmp_src_by_key, new_src->key,
				    new_src - new_group->srcs);
		    }

		  /* notify all registered api clients */
		  if (!cli_api_configured)
		    igmp_event (im, config, new_group, new_src);
		  else
		    igmp_create_group_timer (0, sw_if_index, new_group->key,
					     igmp_send_state_changed);
		  /* remove source form mode_is_filter_include group */
		  hash_unset_mem (group->igmp_src_by_key, src->key);
		  clib_mem_free (src->key);
		  pool_put (group->srcs, src);
		  group->n_srcs -= 1;
		  if (group->n_srcs <= 0)
		    igmp_clear_group (config, group);
		  if (pool_elts (config->groups) <= 0)
		    igmp_clear_config (config);
		}
	      else
		{
		  rv = -1;
		  goto error;
		}
	    }
	  else
	    {
	      rv = -1;
	      goto error;
	    }
	}
      else
	{
	  rv = -1;
	  goto error;
	}
    }

error:
  return rv;
}

/** \brief igmp hardware interface link up down
    @param vnm - vnet main
    @param hw_if_index - interface hw_if_index
    @param flags - hw interface flags

    If an interface goes down, remove its (S,G)s.
*/
static clib_error_t *
igmp_hw_interface_link_up_down (vnet_main_t * vnm, u32 hw_if_index, u32 flags)
{
  igmp_main_t *im = &igmp_main;
  igmp_config_t *config;
  clib_error_t *error = NULL;
  /* remove igmp from a down interface to prevent crashes... */
  config =
    igmp_config_lookup (im,
			vnet_get_hw_interface (vnm,
					       hw_if_index)->sw_if_index);
  if (config)
    {
      if ((flags & VNET_HW_INTERFACE_FLAG_LINK_UP) == 0)
	igmp_clear_config (config);
    }
  return error;
}

VNET_HW_INTERFACE_LINK_UP_DOWN_FUNCTION (igmp_hw_interface_link_up_down);

/** \brief igmp initialization
    @param vm - vlib main

    initialize igmp plugin. Initialize igmp_main, set mfib to allow igmp traffic.
*/
static clib_error_t *
igmp_init (vlib_main_t * vm)
{
  clib_error_t *error;
  igmp_main_t *im = &igmp_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  int i;
  if ((error = vlib_call_init_function (vm, ip4_lookup_init)))
    return error;
  im->igmp_config_by_sw_if_index = hash_create (0, sizeof (u32));
  im->igmp_api_client_by_client_index = hash_create (0, sizeof (u32));
  vec_validate_aligned (im->buffers, tm->n_vlib_mains - 1,
			CLIB_CACHE_LINE_BYTES);
  ip4_register_protocol (IP_PROTOCOL_IGMP, igmp_input_node.index);
  igmp_type_info_t *ti;
  igmp_report_type_info_t *rti;
#define igmp_type(n,s)				\
do {						\
  vec_add2 (im->type_infos, ti, 1);		\
  ti->type = n;					\
  ti->name = (u8 *) #s;				\
} while (0);
#define igmp_report_type(n,s)				\
do {						\
  vec_add2 (im->report_type_infos, rti, 1);		\
  rti->type = n;					\
  rti->name = (u8 *) #s;				\
} while (0);
#include "igmp.def"
#undef igmp_type
#undef igmp_report_type
  for (i = 0; i < vec_len (im->type_infos); i++)
    {
      ti = im->type_infos + i;
      hash_set (im->type_info_by_type, ti->type, i);
    }

  for (i = 0; i < vec_len (im->report_type_infos); i++)
    {
      rti = im->report_type_infos + i;
      hash_set (im->report_type_info_by_report_type, rti->type, i);
    }

  /* General Query address */
  ip46_address_t addr0 = {
    .as_u64[0] = 0,
    .as_u64[1] = 0
  };
  addr0.ip4.as_u32 = clib_host_to_net_u32 (IGMP_GENERAL_QUERY_ADDRESS);

  /* Report address */
  ip46_address_t addr1 = {
    .as_u64[0] = 0,
    .as_u64[1] = 0
  };
  addr1.ip4.as_u32 = clib_host_to_net_u32 (IGMP_MEMBERSHIP_REPORT_ADDRESS);

  fib_route_path_t path = {
    .frp_proto = fib_proto_to_dpo (FIB_PROTOCOL_IP4),
    .frp_addr = zero_addr,
    .frp_sw_if_index = 0xffffffff,
    .frp_fib_index = 0,
    .frp_weight = 0,
    .frp_flags = FIB_ROUTE_PATH_LOCAL,
  };

  const mfib_prefix_t mpfx0 = {
    .fp_proto = FIB_PROTOCOL_IP4,
    .fp_len = 32,
    .fp_grp_addr = addr0,
  };

  const mfib_prefix_t mpfx1 = {
    .fp_proto = FIB_PROTOCOL_IP4,
    .fp_len = 32,
    .fp_grp_addr = addr1,
  };

  /* configure MFIB to accept IGMPv3 general query
   * and reports from all interfaces
   */
  mfib_table_entry_path_update (0, &mpfx0,
				MFIB_SOURCE_DEFAULT_ROUTE, &path,
				MFIB_ITF_FLAG_FORWARD);
  mfib_table_entry_path_update (0, &mpfx1,
				MFIB_SOURCE_DEFAULT_ROUTE, &path,
				MFIB_ITF_FLAG_FORWARD);
  mfib_table_entry_update (0, &mpfx0, MFIB_SOURCE_DEFAULT_ROUTE,
			   0, MFIB_ENTRY_FLAG_ACCEPT_ALL_ITF);
  mfib_table_entry_update (0, &mpfx1, MFIB_SOURCE_DEFAULT_ROUTE,
			   0, MFIB_ENTRY_FLAG_ACCEPT_ALL_ITF);
  return (error);
}

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
