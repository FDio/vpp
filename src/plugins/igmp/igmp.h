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
#include <vlibapi/api_helper_macros.h>
#include <vnet/ip/igmp_packet.h>
#include <vnet/adj/adj_mcast.h>
#include <igmp/igmp_format.h>

#define IGMP_QUERY_TIMER			(60)
#define IGMP_SRC_TIMER				(3 * IGMP_QUERY_TIMER)
#define IGMP_DEFAULT_ROBUSTNESS_VARIABLE	(2)

#define ENABLE_IGMP_DBG 0

#if ENABLE_IGMP_DBG == 1
#define IGMP_DBG(...) clib_warning(__VA_ARGS__)
#else
#define IGMP_DBG(...)
#endif /* ENABLE_IGMP_DBG */

/** General Query address - 224.0.0.1 */
#define IGMP_GENERAL_QUERY_ADDRESS		(0xE0000001)
/** Membership Report address - 224.0.0.22 */
#define IGMP_MEMBERSHIP_REPORT_ADDRESS	(0xE0000016)

/** helper macro to get igmp mebership group from pointer plus offset */
#define group_ptr(p, l) ((igmp_membership_group_v3_t *)((char*)p + l))

enum
{
  IGMP_PROCESS_EVENT_UPDATE_TIMER = 1,
} igmp_process_event_t;

/*! Igmp versions */
typedef enum
{
  IGMP_V1,
  IGMP_V2,
  IGMP_V3,
} igmp_ver_t;

struct igmp_config_t_;

typedef struct igmp_config_t_ igmp_config_t;

struct igmp_group_t_;

typedef struct igmp_group_t_ igmp_group_t;

/** \brief create message
    @param b - vlib buffer
    @param config - igmp configuration
    @param group - igmp group

    Populate supplied bufefr with IGMP message.
*/
typedef void (create_msg_t) (vlib_buffer_t * b, igmp_config_t * config,
			     igmp_group_t * group);

/** \brief igmp key
    @param data - key data
    @param group_type - membership group type
*/
typedef struct
{
  u64 data[2];			/*!< ip46_address_t.as_u64 */
  u64 group_type;		/*!< zero in case of source key */
} igmp_key_t;

/** \brief igmp source
    @param addr - ip4/6 source address
    @param exp_time - expiration time
    @param key - pointer to key
*/
typedef struct
{
  ip46_address_t addr;

  f64 exp_time;

  igmp_key_t *key;
} igmp_src_t;

/** \brief igmp group
    @param addr - ip4/6 group address
    @param exp_time - expiration time
    @param key - pointer to key
    @param type - membership group type
    @param n_srcs - number of sources
    @param flags - igmp group flags
    @param igmp_src_by_key - source by key hash
    @param srcs - pool of sources
*/
typedef struct igmp_group_t_
{
  ip46_address_t addr;

  f64 exp_time;

  igmp_key_t *key;

  igmp_membership_group_v3_type_t type;

  u16 n_srcs;

  u8 flags;
/** reponse to query was received */
#define IGMP_GROUP_FLAG_QUERY_RESP_RECVED	(1 << 0)

  uword *igmp_src_by_key;
  igmp_src_t *srcs;
} igmp_group_t;

/** \brief igmp configuration
    @param sw_if_index - interface sw_if_index
    @param adj_index - adjacency index
    @param cli_api_configured - if zero, an igmp report was received
    @param next_create_msg - specify next igmp message
    @param igmp_ver - igmp version
    @param robustness_var - robustness variable
    @param flags - igmp configuration falgs
    @param igmp_group_by_key - group by key hash
    @param groups - pool of groups
*/
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

  uword *igmp_group_by_key;

  igmp_group_t *groups;
} igmp_config_t;

struct igmp_timer_t_;

typedef struct igmp_timer_t_ igmp_timer_t;

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

/** \brief igmp main
    @param msg_id_base - API message ID base
    @param igmp_api_client_by_client_index - get api client by client_index
    @param api_clients -  pool of api clients registered for join/leave notifications
    @param igmp_config_by_sw_if_index - get config index by config key
    @param configs - pool of igmp configurations
    @param buffers - buffer cache
    @param timers - pool of igmp timers
    @param type_infos - igmp type info
    @param report_type_infos - igmp report type info
    @param type_info_by_type -
    @param report_type_info_by_report_type -
    @param general_query_address - 224.0.0.1
    @param membership_report_address - 224.0.0.22
*/
typedef struct igmp_main_t_
{
  u16 msg_id_base;

  uword *igmp_api_client_by_client_index;

  vpe_client_registration_t *api_clients;

  uword *igmp_config_by_sw_if_index;

  igmp_config_t *configs;

  u32 **buffers;

  igmp_timer_t *timers;

  igmp_type_info_t *type_infos;
  igmp_report_type_info_t *report_type_infos;

  uword *type_info_by_type;
  uword *report_type_info_by_report_type;
} igmp_main_t;

extern igmp_main_t igmp_main;

/** \brief igmp timer function
    @param vm - vlib main
    @param rt - vlib runtime node
    @param im - igmp main
    @param timer - igmp timer
*/
typedef void (igmp_timer_function_t) (vlib_main_t * vm,
				      vlib_node_runtime_t * rt,
				      igmp_main_t * im, igmp_timer_t * timer);

/** \brief igmp timer
    @param exp_time - expiration time
    @param func - function to call on timer expiration
    @param sw_if_index - interface sw_if_index
    @param data - custom data
*/
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

/** \brief igmp listen
    @param vm - vlib main
    @param enable - 0 == remove (S,G), else add (S,G)
    @param sw_if_index - interface sw_if_index
    @param saddr - source address
    @param gaddr - group address
    @param cli_api_configured - if zero, an igmp report has been received on interface

    Add/del (S,G) on an interface. If user configured,
    send a status change report from the interface.
    If a report was received on interface notify registered api clients.
*/
int igmp_listen (vlib_main_t * vm, u8 enable, u32 sw_if_index,
		 ip46_address_t saddr, ip46_address_t gaddr,
		 u8 cli_api_configured);

/** \brief igmp clear config
    @param config - igmp configuration

    Clear all (S,G)s on specified config and remove this config from pool.
*/
void igmp_clear_config (igmp_config_t * config);

/** \brief igmp clear group
    @param config - igmp configuration
    @param group - the group to be removed

    Remove this group from interface (specified by configuration).
*/
void igmp_clear_group (igmp_config_t * config, igmp_group_t * group);

/** \brief igmp sort timers
    @param timers - pool of igmp timers

    Sort igmp timers, so that the first to expire is at end.
*/
void igmp_sort_timers (igmp_timer_t * timers);

/** \brief igmp create int timer
    @param time - expiration time (at this time the timer will expire)
    @param sw_if_index - interface sw_if_index
    @param func - function to all after timer expiration


    Creates new interface timer. Delayed reports, query msg, query resp.
*/
void igmp_create_int_timer (f64 time, u32 sw_if_index,
			    igmp_timer_function_t * func);

/** \brief igmp create group timer
    @param time - expiration time (at this time the timer will expire)
    @param sw_if_index - interface sw_if_index
    @param gkey - key to find the group by
    @param func - function to all after timer expiration

    Creates new group timer.
*/
void igmp_create_group_timer (f64 time, u32 sw_if_index, igmp_key_t * gkey,
			      igmp_timer_function_t * func);

/** \brief igmp create group timer
    @param time - expiration time (at this time the timer will expire)
    @param sw_if_index - interface sw_if_index
    @param gkey - key to find the group by
    @param skey - key to find the source by
    @param func - function to all after timer expiration

    Creates new source timer.
*/
void igmp_create_src_timer (f64 time, u32 sw_if_index, igmp_key_t * gkey,
			    igmp_key_t * skey, igmp_timer_function_t * func);

/** \brief igmp send query (igmp_timer_function_t)

    Send an igmp query.
    If the timer holds group key, send Group-Specific query,
    else send General query.
*/
void igmp_send_query (vlib_main_t * vm, vlib_node_runtime_t * rt,
		      igmp_main_t * im, igmp_timer_t * timer);

/** \brief igmp query response expiration (igmp_timer_function_t)

    If a response to a query didn't come in time, remove (S,G)s.
*/
void igmp_query_resp_exp (vlib_main_t * vm, vlib_node_runtime_t * rt,
			  igmp_main_t * im, igmp_timer_t * timer);

/** \brief igmp send report (igmp_timer_function_t)

    Send igmp membership report.
*/
void igmp_send_report (vlib_main_t * vm, vlib_node_runtime_t * rt,
		       igmp_main_t * im, igmp_timer_t * timer);

/** \brief igmp send state changed (igmp_timer_function_t)

    Send report if an (S,G) filter has changed.
*/
void igmp_send_state_changed (vlib_main_t * vm, vlib_node_runtime_t * rt,
			      igmp_main_t * im, igmp_timer_t * timer);

/** \brief igmp source expiration (igmp_timer_function_t)

    Remove expired (S,G) from group.
*/
void igmp_src_exp (vlib_main_t * vm, vlib_node_runtime_t * rt,
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

/** \brief igmp event
    @param im - igmp main
    @param config - igmp configuration
    @param group - igmp group
    @param src - source

    Notify registered api clients of (S,G) filter update.
*/
void igmp_event (igmp_main_t * im, igmp_config_t * config,
		 igmp_group_t * group, igmp_src_t * src);

typedef enum
{
  IGMP_NEXT_IP4_REWRITE_MCAST_NODE,
  IGMP_NEXT_IP6_REWRITE_MCAST_NODE,
  IGMP_N_NEXT,
} igmp_next_t;

/** \brief igmp config lookup
    @param im - igmp main
    @param sw_if_index - interface sw_if_index
*/
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

/** \brief igmp group lookup
    @param config - igmp configuration
    @param key - igmp key
*/
always_inline igmp_group_t *
igmp_group_lookup (igmp_config_t * config, igmp_key_t * key)
{
  uword *p;
  igmp_group_t *group = NULL;
  if (!config)
    return NULL;

  p = hash_get_mem (config->igmp_group_by_key, key);
  if (p)
    group = vec_elt_at_index (config->groups, p[0]);

  return group;
}

/** \brief igmp group lookup
    @param group - igmp group
    @param key - igmp key
*/
always_inline igmp_src_t *
igmp_src_lookup (igmp_group_t * group, igmp_key_t * key)
{
  uword *p;
  igmp_src_t *src = NULL;
  if (!group)
    return NULL;

  p = hash_get_mem (group->igmp_src_by_key, key);
  if (p)
    src = vec_elt_at_index (group->srcs, p[0]);

  return src;
}

#endif /* _IGMP_H_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
