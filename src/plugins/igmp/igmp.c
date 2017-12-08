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

/* clear all (S,G)s on specified config and remove this config from pool */
void
igmp_clear_config (igmp_config_t * config)
{
  igmp_main_t *im = &igmp_main;
  igmp_sg_t *sg;

  ASSERT (config);
  /* *INDENT-OFF* */
  pool_foreach (sg, config->sg, (
    {
      clib_mem_free (sg->key);
    }));
  /* *INDENT-ON* */
  pool_free (config->sg);
  hash_free (config->igmp_sg_by_key);

  hash_unset_mem (im->igmp_config_by_sw_if_index, &config->sw_if_index);
  pool_put (im->configs, config);
}

/* sort igmp timers, so that the first to expire is at end */
int
igmp_timer_compare (const void *_a, const void *_b)
{
  const igmp_per_int_timer_t *a = _a;
  const igmp_per_int_timer_t *b = _b;
  f64 dt = b->exp_time - a->exp_time;
  return dt < 0 ? -1 : (dt > 0 ? +1 : 0);
}

void
igmp_sort_timers (void *timers, u32 len, ssize_t size)
{
  qsort (timers, len, size, igmp_timer_compare);
  int i;
  for (i = 0; i < len; i++)
    DBG ("%u:%f", i,
	 ((igmp_per_int_timer_t *) ((void *) timers + (size * i)))->exp_time);
}

/* create new per interface timer
 * 
 * - delayed reports
 * - query msg
 * - query resp
 */
void
igmp_create_timer (igmp_timer_type_t type, f64 time, u32 sw_if_index,
		   igmp_sg_key_t * key)
{
  igmp_main_t *im = &igmp_main;
  igmp_per_int_timer_t *t;
  igmp_per_sg_timer_t *t1;

  switch (type)
    {
      /* PER INTERFACE TIMERS */
    case IGMP_PER_INT_TIMER_TYPE_REPORT_DELAY:

      /* if there is a pending report,
       * pending report expire sooner ? do nothing
       * new report expire sooner ? change pending report timer
       */
      /* *INDENT-OFF* */
      pool_foreach (t, im->per_int_timers, (
        {
          if ((t->type == type) && (t->sw_if_index == sw_if_index))
            {
              if (t->exp_time <= time)
                return;
              else
                { 
                  t->exp_time = time;
                  goto sort;
                }
            }
        }));
      /* *INDENT-ON* */

      pool_get (im->per_int_timers, t);
      memset (t, 0, sizeof (igmp_per_int_timer_t));
      t->type = type;
      t->exp_time = time;
      t->sw_if_index = sw_if_index;
      break;
    case IGMP_PER_INT_TIMER_TYPE_QUERY_SEND:
      pool_get (im->per_int_timers, t);
      memset (t, 0, sizeof (igmp_per_int_timer_t));
      t->type = type;
      t->exp_time = time;
      t->sw_if_index = sw_if_index;
      break;
    case IGMP_PER_INT_TIMER_TYPE_QUERY_RESP:
      pool_get (im->per_int_timers, t);
      memset (t, 0, sizeof (igmp_per_int_timer_t));
      t->type = type;
      t->exp_time = time;
      t->sw_if_index = sw_if_index;
      break;
      /* PER (S,G) TIMERS */
    case IGMP_PER_SG_TIMER_TYPE_SG_EXP:
      pool_get (im->per_sg_timers, t1);
      memset (t1, 0, sizeof (igmp_per_sg_timer_t));
      t1->type = type;
      t1->exp_time = time;
      t1->sw_if_index = sw_if_index;
      t1->key = key;
      break;
    default:
      return;
    }
sort:
  if (type < IGMP_PER_INT_TIMER_TYPE_END)
    igmp_sort_timers (im->per_int_timers,
		      vec_len (im->per_int_timers),
		      sizeof (igmp_per_int_timer_t));
  else
    igmp_sort_timers (im->per_sg_timers,
		      vec_len (im->per_sg_timers),
		      sizeof (igmp_per_sg_timer_t));
}

/* get next timer to expire */
always_inline igmp_per_int_timer_t *
igmp_get_next_timer (igmp_main_t * im)
{
  igmp_per_int_timer_t *t = NULL;
  igmp_per_sg_timer_t *t1 = NULL;

  if (pool_elts (im->per_int_timers) > 0)
    t =
      vec_elt_at_index (im->per_int_timers,
			pool_elts (im->per_int_timers) - 1);
  if (pool_elts (im->per_sg_timers) > 0)
    t1 =
      vec_elt_at_index (im->per_sg_timers, pool_elts (im->per_sg_timers) - 1);
  if (t && t1)
    {
      DBG ("a: %f b: %f", t->exp_time, t1->exp_time);
      if (igmp_timer_compare (t, t1) > 0)
	{
	  DBG ("a");
	  return t;
	}
      else
	{
	  DBG ("b");
	  return (igmp_per_int_timer_t *) t1;
	}
    }
  else if (t)
    return t;
  else if (t1)
    return (igmp_per_int_timer_t *) t1;
  else
    return NULL;
}

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

/* create IGMPv3 report with single (S,G)
 * used to send state chenge reports
 */
static void
igmp_create_report_v31 (vlib_buffer_t * b, igmp_config_t * config)
{
  ip_csum_t sum;
  u16 csum;
  igmp_main_t *im = &igmp_main;
  igmp_sg_t *sg;
  u32 len = 0;

  sg = vec_elt_at_index (config->sg, im->next_index.sg_index);

  len = sizeof (igmp_membership_report_v3_t);
  igmp_membership_report_v3_t *igmp =
    (igmp_membership_report_v3_t *) (vlib_buffer_get_current (b));
  memset (igmp, 0, sizeof (igmp_membership_report_v3_t));

  igmp->header.type = IGMP_TYPE_membership_report_v3;
  igmp->n_groups = clib_host_to_net_u16 (1);

  len += sizeof (igmp_membership_group_v3_t);
  memset (igmp->groups, 0, sizeof (igmp_membership_group_v3_t));
  igmp->groups[0].type = sg->group_type;
  if (sg->group_type == IGMP_MEMBERSHIP_GROUP_change_to_filter_include)
    sg->group_type = IGMP_MEMBERSHIP_GROUP_mode_is_filter_include;
  igmp->groups[0].n_aux_u32s = 0;
  clib_memcpy (&igmp->groups[0].dst_address, &sg->gaddr.ip4,
	       sizeof (ip4_address_t));

  igmp->groups[0].n_src_addresses = clib_host_to_net_u16 (1);

  len += sizeof (ip4_address_t);
  clib_memcpy (&igmp->groups[0].src_addresses[0], &sg->saddr.ip4,
	       sizeof (ip4_address_t));

  sum = ip_incremental_checksum (0, igmp, len);
  csum = ~ip_csum_fold (sum);
  igmp->header.checksum = csum;

  b->current_data += len;
  b->current_length += len;
}

u8
ip4_lookup (ip4_address_t * a, igmp_membership_report_v3_t * igmp, u16 n,
	    igmp_membership_group_v3_type_t type)
{
  u16 i;
  u8 rv = 0;
  u32 l = sizeof (igmp_membership_report_v3_t);

  for (i = 0; i < n; i++)
    {
      if ((!ip4_address_compare (a, &group_ptr (igmp, l)->dst_address)) &&
	  (type == group_ptr (igmp, l)->type))
	{
	  rv = 1;
	  break;
	}
      l += sizeof (igmp_membership_group_v3_t) +
	clib_net_to_host_u16 (group_ptr (igmp, l)->n_src_addresses) *
	sizeof (ip4_address_t);
    }

  return rv;
}

/* create IGMPv3 report with all (S,G)s on config
 * used to respond to general queries
 */
static void
igmp_create_report_v32 (vlib_buffer_t * b, igmp_config_t * config)
{
  ip_csum_t sum;
  u16 csum;
  igmp_sg_t *sg0, *sg1;
  u32 len = 0;
  u16 n_groups = 0, n_srcs = 0;
  u32 grp_s = sizeof (igmp_membership_group_v3_t);

  len = sizeof (igmp_membership_report_v3_t);
  igmp_membership_report_v3_t *igmp =
    (igmp_membership_report_v3_t *) (vlib_buffer_get_current (b));
  memset (igmp, 0, sizeof (igmp_membership_report_v3_t));

  igmp->header.type = IGMP_TYPE_membership_report_v3;

/* TODO: divide (S,G)s to multiple reports...
 * - create report limited by <packet size|number of (S,G)s>?
 * - save loop state
 * - on next timer continue loop
 * - case of new query -> reset loop
 */
  /* *INDENT-OFF* */
  pool_foreach (sg0, config->sg, (
    {
      if (ip4_lookup (&sg0->gaddr.ip4, igmp, n_groups, sg0->group_type))
	continue;
      memset (igmp + len, 0, grp_s);
      clib_memcpy (&group_ptr (igmp, len)->dst_address, &sg0->gaddr.ip4, sizeof (ip4_address_t));
      group_ptr (igmp, len)->type = sg0->group_type;
      len += grp_s;
      n_srcs = 0;
      pool_foreach (sg1, config->sg, (
	{
	  if ((!ip4_address_compare (&group_ptr (igmp, len - grp_s)->dst_address,
	       &sg1->gaddr.ip4)) && (group_ptr (igmp, len - grp_s)->type == (sg1->group_type)))
	    {
	      clib_memcpy (group_ptr (igmp, len	+ sizeof (ip4_address_t) * n_srcs),
			   &sg1->saddr.ip4, sizeof (ip4_address_t));
	      n_srcs++;
	    }
	}));
      group_ptr (igmp, len - grp_s)->n_src_addresses = clib_host_to_net_u16 (n_srcs);
      len += sizeof (ip4_address_t) * n_srcs;
      n_groups++;
    }));
  /* *INDENT-ON* */

  igmp->n_groups = clib_host_to_net_u16 (n_groups);

  sum = ip_incremental_checksum (0, igmp, len);
  csum = ~ip_csum_fold (sum);
  igmp->header.checksum = csum;

  b->current_data += len;
  b->current_length += len;
}

static void
igmp_create_general_query_v3 (vlib_buffer_t * b, igmp_config_t * config)
{
  vlib_main_t *vm = vlib_get_main ();
  ip_csum_t sum;
  u16 csum;

  igmp_message_t *igmp = (igmp_message_t *) (vlib_buffer_get_current (b));
  memset (igmp, 0, sizeof (igmp_membership_query_v3_t));

  igmp->header.type = IGMP_TYPE_membership_query;
  igmp->header.code = 100;

  config->query_resp = 0;
  igmp_create_timer (IGMP_PER_INT_TIMER_TYPE_QUERY_RESP,
		     vlib_time_now (vm) + (f64) (igmp->header.code / 10),
		     config->sw_if_index, NULL);
  vlib_process_signal_event (vm, igmp_timer_process_node.index,
			     IGMP_PROCESS_EVENT_UPDATE_TIMER, 0);

  sum =
    ip_incremental_checksum (0, igmp, sizeof (igmp_membership_query_v3_t));
  csum = ~ip_csum_fold (sum);
  igmp->header.checksum = csum;

  b->current_data += sizeof (igmp_membership_query_v3_t);
  b->current_length += sizeof (igmp_membership_query_v3_t);
}


static void
igmp_create_ip4 (vlib_buffer_t * b, igmp_config_t * config, u8 is_report)
{
  ip_lookup_main_t *lm = &ip4_main.lookup_main;

  ip4_header_t *ip4 = (ip4_header_t *) (vlib_buffer_get_current (b));
  memset (ip4, 0, sizeof (ip4_header_t));
  ip4->ip_version_and_header_length = 0x45;
  ip4->ttl = 1;
  ip4->protocol = 2;

  u32 if_add_index =
    lm->if_address_pool_index_by_sw_if_index[config->sw_if_index];
  if (PREDICT_TRUE (if_add_index != ~0))
    {
      ip_interface_address_t *if_add =
	pool_elt_at_index (lm->if_address_pool, if_add_index);
      ip4_address_t *if_ip = ip_interface_address_get_address (lm, if_add);
      clib_memcpy (&ip4->src_address, if_ip, sizeof (ip4_address_t));
    }
  ip4->dst_address.as_u8[0] = 224;
  ip4->dst_address.as_u8[1] = 0;
  ip4->dst_address.as_u8[2] = 0;
  ip4->dst_address.as_u8[3] = is_report ? 22 : 1;

  b->current_data += ip4_header_bytes (ip4);
  b->current_length += ip4_header_bytes (ip4);

  config->next_create_msg (b, config);
  ip4->length = clib_host_to_net_u16 (b->current_length);

  ip4->checksum = ip4_header_checksum (ip4);
}

static void
igmp_send_msg (vlib_main_t * vm, vlib_node_runtime_t * node,
		  igmp_main_t * im, igmp_config_t * config, u8 is_report)
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

	  igmp_create_ip4 (b, config, is_report);

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

static uword
igmp_timer_process (vlib_main_t * vm, vlib_node_runtime_t * rt,
		    vlib_frame_t * f)
{
  igmp_main_t *im = &igmp_main;
  uword *event_data = 0, event_type;
  f64 time_start;
  igmp_config_t *config;
  igmp_sg_t *sg;
  u8 enabled = 0;
  igmp_per_int_timer_t *timer = NULL;
  igmp_per_sg_timer_t *timer1= NULL;
  igmp_timer_type_t timer_type;

  while (1)
    {
      if (enabled)
	vlib_process_wait_for_event_or_clock (vm,
					      timer->exp_time - time_start);
      else
	vlib_process_wait_for_event (vm);

      time_start = vlib_time_now (vm);

      event_type = vlib_process_get_events (vm, &event_data);
      vec_reset_length (event_data);

      if (event_type == IGMP_PROCESS_EVENT_UPDATE_TIMER)
	goto next_timer;

      /* send Membership Report immediately (API/CLI configured (S,G)) */
      else if (event_type == IGMP_PROCESS_EVENT_REPORT_IMMED)
	{
	  config =
	    vec_elt_at_index (im->configs, im->next_index.config_index);
	  sg = vec_elt_at_index (config->sg, im->next_index.sg_index);

	  /* IGMPv2 and IGMPv1 is WIP */
	  if (config->igmp_ver == IGMP_V3)
	    config->next_create_msg = igmp_create_report_v31;
	  else
	    config->next_create_msg = igmp_create_report_v2;

	  igmp_send_msg (vm, rt, im, config, /* is_report */ 1);

	  if (config->igmp_ver == IGMP_V3)
	    config->next_create_msg = igmp_create_report_v32;

	  /* remove API/CLI configured (S,G) */
	  if (sg->group_type ==
	      IGMP_MEMBERSHIP_GROUP_block_old_sources)
	    {
	      hash_unset_mem (config->igmp_sg_by_key, sg->key);
	      clib_mem_free (sg->key);
	      pool_put (config->sg, sg);
	      if (pool_elts (config->sg) == 0)
		{
		  hash_unset_mem (im->igmp_config_by_sw_if_index,
				  &config->sw_if_index);
		  pool_put (im->configs, config);
		}
	    }
	  goto next_timer;
	}


      DBG ("time: %f", vlib_time_now (vm));

      /* timer expired */
      timer_type = timer->type;
      config = igmp_config_lookup (im, timer->sw_if_index);
      if (config)
	{
	  switch (timer_type)
	    {
	    case IGMP_PER_INT_TIMER_TYPE_REPORT_DELAY:

	      /* send delayed IGMP report */
	      if (config->igmp_ver == IGMP_V3)
		config->next_create_msg = igmp_create_report_v32;
	      igmp_send_msg (vm, rt, im, config, /* is_report */ 1);

	      pool_put (im->per_int_timers, timer);
	      break;
	    case IGMP_PER_INT_TIMER_TYPE_QUERY_SEND:

	      /* this case includes creation of new timer
	       * timers are sorted after creation,
	       * so current timer needs to be removed from pool here
	       */
	      pool_put (im->per_int_timers, timer);

	      /* send query request */
	      if (config->igmp_ver == IGMP_V3)
		config->next_create_msg = igmp_create_general_query_v3;
	      igmp_send_msg (vm, rt, im, config, /* is_report */ 0);

	      /* create new query timer */
	      igmp_create_timer (IGMP_PER_INT_TIMER_TYPE_QUERY_SEND,
				 time_start + IGMP_QUERY_TIMER,
				 config->sw_if_index, NULL);
	      break;
	    case IGMP_PER_INT_TIMER_TYPE_QUERY_RESP:

	      if (!config->query_resp)
		{
		  DBG ("remove config %u time:%f", config->sw_if_index,
		     vlib_time_now (vm));
		  /* no response in given interval, remove interface config */
		  igmp_clear_config (config);
		}

	      pool_put (im->per_int_timers, timer);
	      break;
	    case IGMP_PER_SG_TIMER_TYPE_SG_EXP:

	      DBG("SG timer: %f", vlib_time_now (vm));
	      /* current timer is igmp_per_sg_timer_t type */
	      timer1 = (igmp_per_sg_timer_t *) timer;

	      sg = igmp_sg_lookup (config, timer1->key);
	      if (sg)
		{
		  if (timer1->exp_time != sg->exp_time)
		    {
		      timer1->exp_time = sg->exp_time;
		      igmp_sort_timers (im->per_sg_timers,
					vec_len (im->per_sg_timers),
					sizeof (igmp_per_sg_timer_t));
		      goto next_timer;
		    }
		  /* source timer expired, remove (S,G) */
		  igmp_configure_internal (vm, 0, timer1->sw_if_index,
					   timer1->key->saddr,
					   timer1->key->gaddr, 0);
		}
	      pool_put (im->per_sg_timers, timer1);
	      break;
	    default:
	      DBG ("type: %u", timer->type);
	      break;
	    }
	}
      else
	{
	  if (timer_type < IGMP_PER_INT_TIMER_TYPE_END)
	    pool_put (im->per_int_timers, timer);
	  else
	    pool_put (im->per_sg_timers, (igmp_per_sg_timer_t *) timer);
	}

    next_timer:
      timer = igmp_get_next_timer (im);
      if (timer == NULL)
	enabled = 0;
      else
	enabled = 1;
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
igmp_configure_internal (vlib_main_t * vm, u8 enable, u32 sw_if_index,
			 ip46_address_t saddr, ip46_address_t gaddr,
			 u8 cli_api_configured)
{
  igmp_main_t *im = &igmp_main;
  igmp_config_t *config;
  igmp_sg_t *sg;
  igmp_sg_key_t key;
  int rv = 0;

  /* set the lookup key */
  clib_memcpy (&key.saddr, &saddr, sizeof (ip46_address_t));
  clib_memcpy (&key.gaddr, &gaddr, sizeof (ip46_address_t));

  if (enable)
    {
      config = igmp_config_lookup (im, sw_if_index);
      if (!config)
	{
	  pool_get (im->configs, config);
	  memset (config, 0, sizeof (igmp_config_t));
	  config->sw_if_index = sw_if_index;
	  config->igmp_sg_by_key =
	    hash_create_mem (0, sizeof (igmp_sg_key_t), sizeof (uword));
	  config->cli_api_configured = cli_api_configured;
	  /* use IGMPv3 by default */
	  config->igmp_ver = IGMP_V3;
	  if (!cli_api_configured)
	    {
	      igmp_create_timer (IGMP_PER_INT_TIMER_TYPE_QUERY_SEND,
				 vlib_time_now (vm) + IGMP_QUERY_TIMER,
				 sw_if_index, NULL);
	      vlib_process_signal_event (vm, igmp_timer_process_node.index,
					 IGMP_PROCESS_EVENT_UPDATE_TIMER, 0);
	    }
	  config->adj_index =
	    adj_mcast_add_or_lock (FIB_PROTOCOL_IP4, VNET_LINK_IP4,
				   config->sw_if_index);
	  hash_set_mem (im->igmp_config_by_sw_if_index, &config->sw_if_index,
			config - im->configs);
	}
      else if (config->cli_api_configured != cli_api_configured)
	{
	  rv = -2;
	  goto error;
	}
      sg = igmp_sg_lookup (config, &key);
      if (!sg)
	{
	  pool_get (config->sg, sg);
	  memset (sg, 0, sizeof (igmp_sg_t));
	  sg->key = clib_mem_alloc (sizeof (igmp_sg_key_t));
	  clib_memcpy (sg->key, &key, sizeof (igmp_sg_key_t));
	  clib_memcpy (&sg->saddr, &saddr, sizeof (ip46_address_t));
	  clib_memcpy (&sg->gaddr, &gaddr, sizeof (ip46_address_t));
	  sg->group_type = IGMP_MEMBERSHIP_GROUP_change_to_filter_include;
	  if (!cli_api_configured)
	    {
	      sg->group_type = IGMP_MEMBERSHIP_GROUP_mode_is_filter_include;
	      sg->exp_time = vlib_time_now (vm) + IGMP_SG_TIMER;
	      igmp_create_timer (IGMP_PER_SG_TIMER_TYPE_SG_EXP,
				 sg->exp_time, config->sw_if_index, sg->key);
	      vlib_process_signal_event (vm, igmp_timer_process_node.index,
					 IGMP_PROCESS_EVENT_UPDATE_TIMER, 0);
	      /* notify all registered api clients */
	      igmp_event (im, config, sg);
	    }
	  hash_set_mem (config->igmp_sg_by_key, sg->key, sg - config->sg);
	}
      else
	{
	  rv = -1;
	  goto error;
	}

      im->next_index.config_index = config - im->configs;
      im->next_index.sg_index = sg - config->sg;
    }
  else
    {
      config = igmp_config_lookup (im, sw_if_index);
      if (config)
	{
	  sg = igmp_sg_lookup (config, &key);
	  if (sg)
	    {
	      sg->group_type = IGMP_MEMBERSHIP_GROUP_block_old_sources;
	      im->next_index.config_index = config - im->configs;
	      im->next_index.sg_index = sg - config->sg;
	      /* notify all registered api clients */
	      if (!cli_api_configured)
		igmp_event (im, config, sg);
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

int
igmp_configure (vlib_main_t * vm, u8 enable, u32 sw_if_index,
		ip46_address_t saddr, ip46_address_t gaddr)
{
  int rv;
  rv = igmp_configure_internal (vm, enable, sw_if_index, saddr,
				gaddr, /* CLI/API configured */ 1);
  if (rv < 0)
    return rv;
  /* signal the process to report status change */
  vlib_process_signal_event (vm, igmp_timer_process_node.index,
			     IGMP_PROCESS_EVENT_REPORT_IMMED, 0);
  return rv;
}

static clib_error_t *
igmp_init (vlib_main_t * vm)
{
  igmp_main_t *im = &igmp_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();


  im->igmp_config_by_sw_if_index =
    hash_create_mem (0, sizeof (u32), sizeof (uword));
  im->igmp_api_client_by_client_index = 
    hash_create_mem (0, sizeof (u32), sizeof (uword));

  vec_validate_aligned (im->buffers, tm->n_vlib_mains - 1,
			CLIB_CACHE_LINE_BYTES);

  ip4_register_protocol (IP_PROTOCOL_IGMP, igmp_input_node.index);

  /* General Query address */
  ip46_address_t addr0;
  addr0.ip4.as_u8[0] = 224;
  addr0.ip4.as_u8[1] = 0;
  addr0.ip4.as_u8[2] = 0;
  addr0.ip4.as_u8[3] = 1;
  /* Report address */
  ip46_address_t addr1;
  addr1.ip4.as_u8[0] = 224;
  addr1.ip4.as_u8[1] = 0;
  addr1.ip4.as_u8[2] = 0;
  addr1.ip4.as_u8[3] = 22;
  
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
  /* configure MFIB to accept IGMPv3 general query and reports from all interfaces */
  mfib_table_entry_path_update (0, &mpfx0, MFIB_SOURCE_DEFAULT_ROUTE, &path,
                                MFIB_ITF_FLAG_FORWARD);
  mfib_table_entry_path_update (0, &mpfx1, MFIB_SOURCE_DEFAULT_ROUTE, &path,
                                MFIB_ITF_FLAG_FORWARD);

  mfib_table_entry_update (0, &mpfx0, MFIB_SOURCE_DEFAULT_ROUTE, 0, MFIB_ENTRY_FLAG_ACCEPT_ALL_ITF);
  mfib_table_entry_update (0, &mpfx1, MFIB_SOURCE_DEFAULT_ROUTE, 0, MFIB_ENTRY_FLAG_ACCEPT_ALL_ITF);

  return 0;
}

VLIB_INIT_FUNCTION (igmp_init);

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
    .version = VPP_BUILD_VER,
    .description = "IGMP messaging",
};
/* *INDENT-ON* */
