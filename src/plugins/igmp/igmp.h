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

#ifndef _IGMP_H_
#define _IGMP_H_

#include <vlib/vlib.h>
#include <vnet/ip/ip.h>
#include <vnet/ip/igmp_packet.h>
#include <vnet/adj/adj_mcast.h>
#include <igmp/igmp_format.h>

#define IGMP_QUERY_TIMER			(60)
#define IGMP_SG_TIMER				(3 * IGMP_QUERY_TIMER)
#define IGMP_DEFAULT_ROBUSTNESS_VARIABLE	(2)

#define IGMP_DBG 1

#if IGMP_DBG
#define DBG(...) clib_warning(__VA_ARGS__)
#else
#define DBG(...)
#endif /* IGMP_DBG */

#define group_ptr(p, l) ((igmp_membership_group_v3_t *)((char*)p + l))

enum
{
  IGMP_PROCESS_EVENT_UPDATE_TIMER = 1,
} igmp_process_event_t;

typedef enum
{
  IGMP_V1,
  IGMP_V2,
  IGMP_V3,
} igmp_ver_t;

struct igmp_config_t_;

typedef struct igmp_config_t_ igmp_config_t;

/* populate supplied bufefr with IGMP message */
typedef void (create_msg_t) (vlib_buffer_t * b, igmp_config_t * config);

typedef struct igmp_index_t_
{
  u32 config_index;
  u32 sg_index;
} igmp_index_t;

typedef struct igmp_sg_key_t_
{
  ip46_address_t gaddr;
  ip46_address_t saddr;
} igmp_sg_key_t;

typedef struct igmp_sg_t_
{
  ip46_address_t gaddr;
  ip46_address_t saddr;

  igmp_membership_group_v3_type_t group_type;

  /* check if expired (S,G) timer is valid */
  f64 exp_time;

  igmp_sg_key_t *key;
} igmp_sg_t;

typedef struct igmp_config_t_
{
  u32 sw_if_index;

  adj_index_t adj_index;

  u8 cli_api_configured;

  create_msg_t *next_create_msg;

  igmp_ver_t igmp_ver;

  u8 robustness_var;

  u8 flags;
#define IGMP_CONFIG_FLAG_QUERY_RESP_RECVED 	(1 << 0)
#define IGMP_CONFIG_FLAG_CAN_SEND_REPORT 	(1 << 1)

  uword *igmp_sg_by_key;

  /* pool of (S,G)s per interface */
  igmp_sg_t *sg;
} igmp_config_t;

struct igmp_timer_t_;

typedef struct igmp_timer_t_ igmp_timer_t;

typedef struct igmp_api_client_t_
{
  u32 client_index;
  u32 pid;
} igmp_api_client_t;

typedef struct
{
  u8 *name;
  igmp_type_t type;
} igmp_type_info_t;

typedef struct
{
  u8 *name;
  igmp_membership_group_v3_type_t type;
} igmp_report_type_info_t;

typedef struct igmp_main_t_
{
  /** API message ID base */
  u16 msg_id_base;

  /* get api client by client_index */
  uword *igmp_api_client_by_client_index;

  /** pool of api clients registered for join/leave notifications */
  igmp_api_client_t *api_clients;

  /* get config index by config key */
  uword *igmp_config_by_sw_if_index;

  /** pool of igmp configurations */
  igmp_config_t *configs;

  /** buffer cache */
  u32 **buffers;

  /* next report/deletion */
  igmp_index_t next_index;

  /** pool of igmp timers */
  igmp_timer_t *timers;

  igmp_type_info_t *type_infos;
  igmp_report_type_info_t *report_type_infos;

  uword *type_info_by_type;
  uword *report_type_info_by_report_type;

} igmp_main_t;

extern igmp_main_t igmp_main;

typedef void (igmp_timer_function_t) (vlib_main_t * vm,
				      vlib_node_runtime_t * rt,
				      igmp_main_t * im, igmp_timer_t * timer);

typedef struct igmp_timer_t_
{
  f64 exp_time;
  igmp_timer_function_t *func;

  u32 sw_if_index;
  void *data;
} igmp_timer_t;

extern vlib_node_registration_t igmp_timer_process_node;
extern vlib_node_registration_t igmp_input_node;
extern vlib_node_registration_t igmp_parse_query_node;
extern vlib_node_registration_t igmp_parse_report_node;

int igmp_listen (vlib_main_t * vm, u8 enable, u32 sw_if_index,
		 ip46_address_t saddr, ip46_address_t gaddr,
		 u8 cli_api_configured);

void igmp_clear_config (igmp_config_t * config);

void igmp_sort_timers (igmp_timer_t * timers);

void igmp_create_int_timer (f64 time, u32 sw_if_index,
			    igmp_timer_function_t * func);
void igmp_create_sg_timer (f64 time, u32 sw_if_index, igmp_sg_key_t * key,
			   igmp_timer_function_t * func);

void igmp_send_query (vlib_main_t * vm, vlib_node_runtime_t * rt,
		      igmp_main_t * im, igmp_timer_t * timer);
void igmp_query_resp_exp (vlib_main_t * vm, vlib_node_runtime_t * rt,
			  igmp_main_t * im, igmp_timer_t * timer);
void igmp_send_report (vlib_main_t * vm, vlib_node_runtime_t * rt,
		       igmp_main_t * im, igmp_timer_t * timer);
void igmp_send_state_changed (vlib_main_t * vm, vlib_node_runtime_t * rt,
			      igmp_main_t * im, igmp_timer_t * timer);
void igmp_sg_exp (vlib_main_t * vm, vlib_node_runtime_t * rt,
		  igmp_main_t * im, igmp_timer_t * timer);

static inline igmp_type_info_t *
igmp_get_type_info (igmp_main_t * im, u32 type)
{
  uword *p;

  p = hash_get (im->type_info_by_type, type);
  return p ? vec_elt_at_index (im->type_infos, p[0]) : 0;
}

static inline igmp_report_type_info_t *
igmp_get_report_type_info (igmp_main_t * im, u8 report_type)
{
  uword *p;

  p = hash_get (im->report_type_info_by_report_type, report_type);
  return p ? vec_elt_at_index (im->report_type_infos, p[0]) : 0;
}

void igmp_event (igmp_main_t * im, igmp_config_t * config, igmp_sg_t * sg);

typedef enum
{
  IGMP_NEXT_IP4_REWRITE_MCAST_NODE,
  IGMP_NEXT_IP6_REWRITE_MCAST_NODE,
  IGMP_N_NEXT,
} igmp_next_t;


always_inline igmp_config_t *
igmp_config_lookup (igmp_main_t * im, u32 sw_if_index)
{
  uword *p;
  igmp_config_t *config = NULL;

  p = hash_get_mem (im->igmp_config_by_sw_if_index, &sw_if_index);
  if (p)
    config = vec_elt_at_index (im->configs, p[0]);

  return config;
}

always_inline igmp_sg_t *
igmp_sg_lookup (igmp_config_t * config, igmp_sg_key_t * key)
{
  uword *p;
  igmp_sg_t *sg = NULL;
  if (!config)
    return NULL;

  p = hash_get_mem (config->igmp_sg_by_key, key);
  if (p)
    sg = vec_elt_at_index (config->sg, p[0]);

  return sg;
}

always_inline igmp_api_client_t *
igmp_api_client_lookup (igmp_main_t * im, u32 client_index)
{
  uword *p;
  igmp_api_client_t *api_client = NULL;

  p = hash_get_mem (im->igmp_api_client_by_client_index, &client_index);
  if (p)
    api_client = vec_elt_at_index (im->api_clients, p[0]);

  return api_client;
}

#endif /* _IGMP_H_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
