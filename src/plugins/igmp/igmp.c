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
#include <vnet/ip/igmp_packet.h>
#include <vlib/unix/unix.h>
#include <vnet/adj/adj_mcast.h>

#include <igmp/igmp.h>

#include <limits.h>

#define IGMP_DBG 1

#if IGMP_DBG
#define DBG(...) clib_waring(__VA_ARGS__)
#else
#define DBG(...)
#endif /* IGMP_DBG */

typedef enum
{
  IGMP_NEXT_IP4_REWRITE_MCAST_NODE,
  IGMP_NEXT_IP6_REWRITE_MCAST_NODE,
  IGMP_N_NEXT,
} igmp_next_t;

igmp_main_t igmp_main;

/* The list is sorted by remaining timeout before next report send.
 * Enqueue new config before current config to keep the list sorted,
 */
static_always_inline void
igmp_enq_config (igmp_main_t * im, igmp_config_t * conf)
{
  if (im->configs == NULL)
    {
      conf->next = conf;
      conf->prev = conf;
    }
  else
    {
      conf->next = im->configs;
      conf->prev = im->configs->prev;
      im->configs->prev->next = conf;
      im->configs->prev = conf;
    }
    im->configs = conf;
}

static_always_inline void
igmp_deq_config (igmp_main_t * im, igmp_config_t * conf, u8 free_ptr)
{
  conf->prev->next = conf->next;
  conf->next->prev = conf->prev;
  if (free_ptr)
    {
      if (im->configs == conf)
        im->configs = conf->next == conf ? NULL : conf->next;
      clib_mem_free (conf);
      conf = NULL;
    }
}

static_always_inline igmp_config_t *
igmp_config_lookup (igmp_main_t * im, igmp_config_key_t * key, u32 sw_if_index,
		    ip46_address_t *saddr ,ip46_address_t *gaddr)
{
  igmp_config_t *conf = NULL;
  uword *p;

  memset (key, 0, sizeof (igmp_config_key_t));

  key->sw_if_index = sw_if_index;
  memcpy (&key->saddr, saddr, sizeof (ip46_address_t));
  memcpy (&key->gaddr, gaddr, sizeof (ip46_address_t));

  p = hash_get_mem (im->igmp_config_context_by_key, key);
  if (p)
    conf = (igmp_config_t *) p[0];

  return conf;
}

static void
igmp_create_report_v2 (igmp_config_t * conf, vlib_buffer_t * b)
{
  ip_csum_t sum;
  u16 csum;

  igmp_message_t *igmp = (igmp_message_t *)(vlib_buffer_get_current (b));
  memset (igmp, 0, sizeof (igmp_message_t));

  clib_memcpy (&igmp->dst, &conf->gaddr.ip4, sizeof (ip4_address_t));
  igmp->header.type = IGMP_TYPE_membership_report_v2;
  sum = ip_incremental_checksum (0, igmp, sizeof (igmp_message_t));
  csum = ~ip_csum_fold (sum);
  igmp->header.checksum = csum;

  b->current_length += sizeof (igmp_message_t);
}

static void
igmp_create_leave_v2 (igmp_config_t * conf, vlib_buffer_t * b)
{
  ip_csum_t sum;
  u16 csum;

  igmp_message_t *igmp = (igmp_message_t *)(vlib_buffer_get_current (b));
  memset (igmp, 0, sizeof (igmp_message_t));

  clib_memcpy (&igmp->dst, &conf->gaddr.ip4, sizeof (ip4_address_t));
  igmp->header.type = IGMP_TYPE_leave_group_v2;
  sum = ip_incremental_checksum (0, igmp, sizeof (igmp_message_t));
  csum = ~ip_csum_fold (sum);
  igmp->header.checksum = csum;

  b->current_length += sizeof (igmp_message_t);
}

/* TODO: finish IGMPv3 report

static void
igmp_create_report_v3 (igmp_config_t * conf, vlib_buffer_t *b)
{
  ip_csum_t sum;
  u16 csum;

  igmp_membership_report_v3_t *igmp =
    (igmp_membership_report_v3_t *)(vlib_buffer_get_current (b));

  igmp->header.type = IGMP_TYPE_membership_report_v3;
  igmp->n_groups = 1;

  igmp->groups[0].type = 0;
  igmp->groups[0].n_aux_u32s = 0;

  igmp->groups[0].n_src_address = 1;
  clib_memcpy (&igmp->groups[0].dst_address, &conf->gaddr.ip4, sizeof (ip4_address_t));
  clib_memcpy (&igmp->groups[0].src_address[0], &conf->saddr.ip4, sizeof (ip4_address_t));

  sum = ip_incremental_checksum (0, igmp, sizeof (igmp_membership_report_v3_t));
  csum = ~ip_csum_fold (sum);
  igmp->header.checksum = csum;

  b->current_length += sizeof (igmp_membership_report_v3_t);
}
*/

static void
igmp_send (vlib_main_t * vm, vlib_node_runtime_t * node, igmp_main_t * im, igmp_config_t * conf)
{
  u32 thread_index = vlib_get_thread_index ();
  u32 *to_next;
  u32 next_index = IGMP_NEXT_IP4_REWRITE_MCAST_NODE;

  u32 n_free_bufs = vec_len (im->buffers[thread_index]);
  if (PREDICT_FALSE (n_free_bufs < 1))
    {
      vec_validate (im->buffers[thread_index],
		    1 + n_free_bufs - 1);
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

      /* fill buffer */
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
	        &im->buffers[thread_index][n_free_bufs], 1);
	      _vec_len (im->buffers[thread_index]) = n_free_bufs;
	    }

	  b->current_data = 0;

	  /* create ip4 header */
	  ip4_header_t *ip4 = (ip4_header_t*)(vlib_buffer_get_current (b));
	  memset (ip4, 0, sizeof (ip4_header_t));
	  ip4->ip_version_and_header_length = 0x45;
	  ip4->length = sizeof (igmp_header_t) + sizeof (ip4_header_t);
	  ip4->ttl = 64;
	  ip4->protocol = 2;
	  clib_memcpy (&ip4->src_address, &conf->saddr.ip4, sizeof (ip4_address_t));
	  clib_memcpy (&ip4->dst_address, &conf->gaddr.ip4, sizeof (ip4_address_t));
	  ip4->checksum = ip4_header_checksum (ip4);

	  b->current_length = ip4_header_bytes (ip4);

	  /* create IGMP header */
	  conf->next_create_msg (conf, b);

	  b->total_length_not_including_first_buffer = 0;
	  b->flags = VLIB_BUFFER_TOTAL_LENGTH_VALID;
	  vnet_buffer (b)->sw_if_index[VLIB_RX] = (u32) ~0;
	  vnet_buffer (b)->ip.adj_index[VLIB_TX] = conf->adj_index;
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

static void
mld_send (vlib_main_t * vm, vlib_node_runtime_t * node, igmp_main_t * im, igmp_config_t * conf)
{
  /* TODO: MLD
   * 
   * create ip6 header
   * implement create_msg_t mld report/done
   */
  return;
}

uword
igmp_process (vlib_main_t * vm, vlib_node_runtime_t * rt, vlib_frame_t * f)
{
  uword *event_data = 0, event_type;
  u8 enabled = 0;
  f64 last_run_duration = 0;
  igmp_main_t *im = &igmp_main;
  igmp_config_t *conf;

  f64 to = 0;

  while (1)
    {
      if (enabled && im->configs)
	{
	  conf = im->configs;
	  to = conf->interval - (vlib_time_now (vm) - conf->last_send);
	  vlib_process_wait_for_event_or_clock (vm, to - last_run_duration);
	}
      else
	vlib_process_wait_for_event (vm);

      event_type = vlib_process_get_events (vm, &event_data);
      vec_reset_length (event_data);

      switch (event_type)
	{
	case ~0:
	  break;
	case IGMP_PROCESS_EVENT_START:
	  enabled = 1;
	  conf = im->configs;
	  break;
	case IGMP_PROCESS_EVENT_STOP:
	  enabled = 0;
	  continue;
	default:
	  break;
	}

      last_run_duration = vlib_time_now (vm);

      if (ip46_address_is_ip4 (&conf->saddr))
        igmp_send (vm, rt, im, conf);
      else
	mld_send (vm, rt, im, conf);

      conf->last_send = vlib_time_now (vm);

      if (conf->pending_del)
	{
	  hash_unset_mem (im->igmp_config_context_by_key, conf->key);
	  igmp_deq_config (im, conf, /* free pointer */ 1);
	  if (im->configs == NULL)
	    vlib_process_signal_event (vm, igmp_process_node.index, IGMP_PROCESS_EVENT_STOP, 0);
	}

      /* advance linked list */
      if (im->configs != NULL)
	im->configs = im->configs->next;

      last_run_duration = vlib_time_now (vm) - last_run_duration;
    }
  return 0;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (igmp_process_node) = {
  .function = igmp_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "igmp-process",

  .n_next_nodes = IGMP_N_NEXT,
  .next_nodes = {
        [IGMP_NEXT_IP4_REWRITE_MCAST_NODE] = "ip4-rewrite-mcast",
        [IGMP_NEXT_IP6_REWRITE_MCAST_NODE] = "ip6-rewrite-mcast",
  }
};
/* *INDENT-ON* */

int
igmp_configure (vlib_main_t * vm, u8 enable, u32 sw_if_index,
		ip46_address_t saddr, ip46_address_t gaddr)
{
  igmp_main_t *im = &igmp_main;
  igmp_config_t *conf;
  igmp_config_key_t key;

  if (enable)
    {
      conf = igmp_config_lookup (im, &key, sw_if_index, &saddr, &gaddr);
      if (conf)
	  goto error;

      conf = clib_mem_alloc (sizeof (igmp_config_t));
      memset (conf, 0, sizeof (*conf));
      conf->key = clib_mem_alloc (sizeof (key));
      clib_memcpy (conf->key, &key, sizeof (key));

      conf->sw_if_index = sw_if_index;
      clib_memcpy (&conf->saddr, &saddr, sizeof (ip46_address_t));
      clib_memcpy (&conf->gaddr, &gaddr, sizeof (ip46_address_t));
      conf->adj_index = adj_mcast_add_or_lock (
		FIB_PROTOCOL_IP4, VNET_LINK_IP4, conf->sw_if_index);

      conf->next_create_msg = igmp_create_report_v2;
      conf->interval = 2;

      hash_set_mem (im->igmp_config_context_by_key, conf->key, conf);

      igmp_enq_config (im, conf);

      vlib_process_signal_event (vm, igmp_process_node.index, IGMP_PROCESS_EVENT_START, 0);
    }
  else
    {
      conf = igmp_config_lookup (im, &key, sw_if_index, &saddr, &gaddr);
      if (conf)
	{
	  conf->next_create_msg = igmp_create_leave_v2;
	  conf->pending_del = 1;

	  igmp_deq_config (im, conf, /* free pointer */ 0);
	  igmp_enq_config (im, conf);
	}
      else
	  goto error;

      vlib_process_signal_event (vm, igmp_process_node.index, IGMP_PROCESS_EVENT_START, 0);
    }

  return 0;

error:
  return -1;
}

static clib_error_t *
igmp_init (vlib_main_t * vm)
{
  igmp_main_t *im = &igmp_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();

  memset (im, 0, sizeof (igmp_main_t));

  /* initialize binary API */
  igmp_plugin_api_hookup (vm);

  im->igmp_config_context_by_key = hash_create_mem (0, sizeof (igmp_config_key_t), sizeof (uword));

  /* initialize the linked-list */
  im->configs = NULL;

  vec_validate_aligned (im->buffers, tm->n_vlib_mains - 1,
			CLIB_CACHE_LINE_BYTES);
  return 0;
}

VLIB_INIT_FUNCTION (igmp_init);

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
    .version = VPP_BUILD_VER,
    .description = "IGMP messaging",
};
/* *INDENT-ON* */
