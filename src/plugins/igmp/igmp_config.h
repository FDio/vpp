/*
 *------------------------------------------------------------------
 * Copyright (c) 2018 Cisco and/or its affiliates.
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

#ifndef __IGMP_CONFIG_H__
#define __IGMP_CONFIG_H__

#include <igmp/igmp_types.h>
#include <igmp/igmp_timer.h>
#include <igmp/igmp_group.h>

/**
 * GENERAL_REPORT = On expiry send a general report
 * GENERAL_QUERY  = On expiry send a general query
 */
#define foreach_igmp_config_timer_type  \
  _(GENERAL_REPORT, "general-report")   \
  _(GENERAL_QUERY, "general-query")

typedef enum igmp_config_timer_type_t_
{
#define _(v,s) IGMP_CONFIG_TIMER_##v,
  foreach_igmp_config_timer_type
#undef _
} igmp_config_timer_type_t;

#define IGMP_CONFIG_N_TIMERS (IGMP_CONFIG_TIMER_GENERAL_QUERY + 1)

extern u8 *format_igmp_config_timer_type (u8 * s, va_list * args);

/**
 * @brief IGMP interface configuration
*/
typedef struct igmp_config_t_
{
  /**
   * @param sw_if_index - interface sw_if_index
   */
  u32 sw_if_index;

  /**
   * @param adj_index - multicast adjacency index on the link
   */
  adj_index_t adj_index;

  /**
   * @param mode - host or router
   */
  igmp_mode_t mode;

  /**
   * Robustness variable (section 5.1)
   */
  u8 robustness_var;

  /**
   * Database of groups joined on the link
   */
  uword *igmp_group_by_key;

  /**
   * A vector of scheduled query-response timers
   */
  igmp_timer_id_t timers[IGMP_CONFIG_N_TIMERS];

  /**
   * ID of a proxy device this configuration is on
   */
  u32 proxy_device_id;
} igmp_config_t;

#define FOR_EACH_GROUP(_group, _config, _body)                          \
do {                                                                    \
  igmp_key_t *__key__;                                                  \
  u32 __gid__;                                                          \
  hash_foreach_mem(__key__, __gid__, _config->igmp_group_by_key,        \
  ({                                                                    \
    _group = pool_elt_at_index(igmp_main.groups, __gid__);              \
    do { _body; } while (0);                                            \
  }));                                                                  \
 } while (0);

/**
 * @brief igmp clear config
 *  @param config - igmp configuration
 *
 *   Clear all (S,G)s on specified config and remove this config from pool.
 */
extern void igmp_clear_config (igmp_config_t * config);

/**
 * @brief igmp config lookup
 *  @param im - igmp main
 *  @param sw_if_index - interface sw_if_index
 */
extern igmp_config_t *igmp_config_lookup (u32 sw_if_index);

/**
 * Get the pool index for a config
 */
extern u32 igmp_config_index (const igmp_config_t * c);

/**
 * Get the config from the pool index
 */
extern igmp_config_t *igmp_config_get (u32 index);

/**
 * @brief igmp group lookup
 *  @param config - igmp configuration
 *  @param key - igmp key
*/
extern igmp_group_t *igmp_group_lookup (igmp_config_t * config,
					const igmp_key_t * key);

extern u8 *format_igmp_config (u8 * s, va_list * args);

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
