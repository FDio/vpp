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
#include <igmp/igmp_timer.h>

#define IGMP_QUERY_TIMER			(60)
#define IGMP_SRC_TIMER				(3 * IGMP_QUERY_TIMER)
#define IGMP_DEFAULT_ROBUSTNESS_VARIABLE	(2)

#define IGMP_DBG(...) \
    vlib_log_notice (igmp_main.logger, __VA_ARGS__);

/**
 * General Query address - 224.0.0.1
 * Membership Report address - 224.0.0.22
 */
#if CLIB_ARCH_IS_BIG_ENDIAN
#define IGMP_GENERAL_QUERY_ADDRESS	(0xE0000001)
#define IGMP_MEMBERSHIP_REPORT_ADDRESS	(0xE0000016)
#else
#define IGMP_GENERAL_QUERY_ADDRESS	(0x010000E0)
#define IGMP_MEMBERSHIP_REPORT_ADDRESS	(0x160000E0)
#endif

/** helper macro to get igmp mebership group from pointer plus offset */
#define group_ptr(p, l) ((igmp_membership_group_v3_t *)((char*)p + l))

/** \brief IGMP filter mode
 * Exclude all source address except this one
 * Include only this source address
 */
#define foreach_igmp_filter_mode	\
  _ (1, INCLUDE)			\
  _ (0, EXCLUDE)			\

typedef enum igmp_filter_mode_t_
{
#define _(n,f) IGMP_FILTER_MODE_##f = n,
  foreach_igmp_filter_mode
#undef _
} igmp_filter_mode_t;

#define IGMP_N_FILTER_MODES 2

/** \brief IGMP source - where to the request for state arrive from
 *  host - from an API/CLI command to add the state
 *  network - from a received report
 * Each source could be mode from both modes, so these are flags.
 */
#define foreach_igmp_mode	\
  _ (1, HOST)			\
  _ (2, ROUTER)                 \

typedef enum igmp_mode_t_
{
#define _(n,f) IGMP_MODE_##f = n,
  foreach_igmp_mode
#undef _
} igmp_mode_t;

/*! Igmp versions */
typedef enum
{
  /**
   * This implementation supports only IGMPv3. It does not support
   * systems on the link of other versions (RFC 3367, Section 7)
   */
  IGMP_V3 = 3,
} igmp_ver_t;

typedef enum igmp_msg_type_t_
{
  IGMP_MSG_REPORT,
  IGMP_MSG_QUERY,
} igmp_msg_type_t;

/**
 * @brief IGMP Key
 *  Used to index groups within an interface config and sources within a list
 */
typedef ip46_address_t igmp_key_t;

extern u8 *format_igmp_key (u8 * s, va_list * args);

/**
 *  @brief IGMP source
 *  The representation of a specified source address with in multicast group.
 */
typedef struct
{
  /**
   * The source's key
   */
  igmp_key_t *key;

  /**
   * The liveness timer. Reset with each recieved report. on expiry
   * the source is removed from the group.
   */
  u32 exp_timer;

  /**
   * the mode that provided this source
   */
  igmp_mode_t mode;
} igmp_src_t;

/**
 * @brief A list of sources maintain for a multicast group
 */
typedef struct imgp_src_list_t_
{
  /** stored as a hasd table against the source's address */
  uword *srcs;
} igmp_src_list_t;

/* typedef enum igmp_group_flags_t_ */
/* { */
/*   /\** reponse to query was received *\/ */
/*   IGMP_GROUP_FLAG_QUERY_RESP_RECVED = (1 << 0), */
/* } __attribute__ ((packed)) igmp_group_flags_t; */

/**
 * Types of timers maintained for each group
 */
typedef enum igmp_group_timer_type_t_
{
  /**
   * Timer running to reply to a G/SG specific query
   */
  IGMP_GROUP_TIMER_QUERY_REPLY,
  /**
   * wait for response from a sent G/SG specfic query.
   * Sent when a host leaves a group
   */
  IGMP_GROUP_TIMER_QUERY_SENT,
  /**
   * filter-mode change timer, to check if the group can swap to
   * INCLUDE mode (section 6.2.2)
   */
  IGMP_GROUP_TIMER_FILTER_MODE_CHANGE,
} igmp_group_timer_type_t;

#define IGMP_GROUP_N_TIMERS (IGMP_GROUP_TIMER_FILTER_MODE_CHANGE + 1)

/**
 * @brief IGMP group
 *  A multicast group address for which reception has been requested.
 */
typedef struct igmp_group_t_
{
  /** The group's key within the per-interface config */
  igmp_key_t *key;

  /**
   * A vector of running timers for the group. this can include:
   *  - group-specific query, sent on reception of a host 'leave'
   *  - filter-mode change timer, to check if the group can swap to
   *      INCLUDE mode (section 6.2.2)
   */
  u32 timers[IGMP_GROUP_N_TIMERS];

  /**
   * The current filter mode of the group (see 6.2.1)
   */
  igmp_filter_mode_t router_filter_mode;

  /**
   * Source list per-filter mode
   */
  uword *igmp_src_by_key[IGMP_N_FILTER_MODES];
} igmp_group_t;

#define FOR_EACH_SRC(_src, _group, _filter, _body)                       \
do {                                                                    \
  igmp_key_t *__key__;                                                  \
  u32 __sid__;                                                          \
  hash_foreach(__key__, __sid__, ((igmp_group_t*)_group)->igmp_src_by_key[(_filter)], \
  ({                                                                    \
    _src = pool_elt_at_index(igmp_main.srcs, __sid__);                  \
    do { _body; } while (0);                                            \
  }));                                                                  \
 } while (0);

typedef enum igmp_config_timer_type_t_
{
  IGMP_CONFIG_TIMER_GENERAL_QUERY,
} igmp_config_timer_type_t;

#define IGMP_CONFIG_N_TIMERS (IGMP_CONFIG_TIMER_GENERAL_QUERY + 1)

/** \brief igmp configuration
    @param sw_if_index - interface sw_if_index
    @param adj_index - adjacency index
    @param mode - VPP IGMP mode
    @param igmp_ver - igmp version
    @param robustness_var - robustness variable
    @param flags - igmp configuration falgs
    @param igmp_group_by_key - group by key hash
*/
typedef struct igmp_config_t_
{
  u32 sw_if_index;

  adj_index_t adj_index;

  igmp_ver_t igmp_ver;
  igmp_mode_t mode;

  u8 robustness_var;

  u8 flags;
#define IGMP_CONFIG_FLAG_QUERY_RESP_RECVED 	(1 << 0)
#define IGMP_CONFIG_FLAG_CAN_SEND_REPORT 	(1 << 1)

  uword *igmp_group_by_key;

  /**
   * A vector of scheduled query-respone timers
   */
  igmp_timer_id_t timers[IGMP_CONFIG_N_TIMERS];
} igmp_config_t;

#define FOR_EACH_GROUP(_group, _config, _body)                          \
do {                                                                    \
  igmp_key_t *__key__;                                                  \
  u32 __gid__;                                                          \
  hash_foreach(__key__, __gid__, _config->igmp_group_by_key,            \
  ({                                                                    \
    _group = pool_elt_at_index(igmp_main.groups, __gid__);              \
    do { _body; } while (0);                                            \
  }));                                                                  \
 } while (0);

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
    @param general_query_address - 224.0.0.1
    @param membership_report_address - 224.0.0.22
    @param n_configs_per_mfib_index - the number of igmp configs
                                      for each mfib_index (VRF)
    @param groups - pool of groups
    @param srcs - pool of sources
    @param logger - VLIB log class
*/
typedef struct igmp_main_t_
{
  u16 msg_id_base;

  clib_spinlock_t lock;

  uword *igmp_api_client_by_client_index;

  vpe_client_registration_t *api_clients;

  u32 *igmp_config_by_sw_if_index;

  igmp_config_t *configs;

  u32 **buffers;

  u32 *n_configs_per_mfib_index;
  igmp_group_t *groups;
  igmp_src_t *srcs;
  vlib_log_class_t logger;
} igmp_main_t;

extern igmp_main_t igmp_main;


extern vlib_node_registration_t igmp_timer_process_node;
extern vlib_node_registration_t igmp_input_node;

/** \brief IGMP interface enable/disable
 *  Called by a router to enable/disable the reception of IGMP messages
 *  @param sw_if_index - Interface
 *  @param enable - enable/disable
 *  @param mode - Host (1) or router (0)
 */
int igmp_enable_disable (u32 sw_if_index, u8 enable, igmp_mode_t mode);

/** \brief igmp listen
    @param vm - vlib main
    @param filter - Filter mode
    @param sw_if_index - interface sw_if_index
    @param saddr - source address
    @param gaddr - group address

    Add/del (S,G) on an interface.
    send a status change report from the interface.
*/
int igmp_listen (vlib_main_t * vm,
		 igmp_filter_mode_t filter,
		 u32 sw_if_index,
		 const ip46_address_t * saddr, const ip46_address_t * gaddr);

int igmp_update (vlib_main_t * vm,
		 u32 sw_if_index,
		 const ip46_address_t * saddr,
		 const ip46_address_t * gaddr,
		 igmp_mode_t mode, igmp_membership_group_v3_type_t type);

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

/** \brief igmp create int timer
    @param time - expiration time (at this time the timer will expire)
    @param sw_if_index - interface sw_if_index
    @param func - function to all after timer expiration


    Creates new interface timer. Delayed reports, query msg, query resp.
*/
/* void igmp_create_int_timer (f64 time, u32 sw_if_index, */
/* 			    igmp_timer_function_t * func); */

/** \brief igmp event
    @param im - igmp main
    @param config - igmp configuration
    @param group - igmp group
    @param src - source

    Notify registered api clients of (S,G) filter update.
*/
void igmp_event (igmp_main_t * im, igmp_config_t * config,
		 igmp_group_t * group, igmp_src_t * src);

/** \brief igmp send report (igmp_timer_function_t)

    Send igmp membership report.
*/
/* void igmp_send_report (vlib_main_t * vm, vlib_node_runtime_t * rt, */
/* 		       igmp_main_t * im, igmp_timer_t * timer); */

/** \brief igmp config lookup
    @param im - igmp main
    @param sw_if_index - interface sw_if_index
*/
always_inline igmp_config_t *
igmp_config_lookup (u32 sw_if_index)
{
  igmp_main_t *im;

  im = &igmp_main;

  if (vec_len (im->igmp_config_by_sw_if_index) > sw_if_index)
    {
      u32 index;

      index = im->igmp_config_by_sw_if_index[sw_if_index];

      if (~0 != index)
	return (vec_elt_at_index (im->configs, index));
    }
  return NULL;
}

always_inline u32
igmp_config_index (const igmp_config_t * c)
{
  return (c - igmp_main.configs);
}

/** \brief igmp group lookup
    @param config - igmp configuration
    @param key - igmp key
*/
always_inline igmp_group_t *
igmp_group_lookup (igmp_config_t * config, const igmp_key_t * key)
{
  uword *p;
  igmp_group_t *group = NULL;
  if (!config)
    return NULL;

  p = hash_get_mem (config->igmp_group_by_key, key);
  if (p)
    group = pool_elt_at_index (igmp_main.groups, p[0]);

  return group;
}

always_inline u32
igmp_group_index (const igmp_group_t * c)
{
  return (c - igmp_main.groups);
}

/** \brief igmp group lookup
    @param group - igmp group
    @param key - igmp key
*/
always_inline igmp_src_t *
igmp_src_lookup (igmp_group_t * group, const igmp_key_t * key)
{
  uword *p;
  igmp_src_t *src = NULL;
  if (!group)
    return NULL;

  p = hash_get_mem (group->igmp_src_by_key[IGMP_FILTER_MODE_INCLUDE], key);
  if (p)
    src = vec_elt_at_index (igmp_main.srcs, p[0]);

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
