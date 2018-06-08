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

typedef enum igmp_config_timer_type_t_
{
  /**
   * On expiry send a general report
   */
  IGMP_CONFIG_TIMER_GENERAL_REPORT,

  /**
   * On expiry send a general query
   */
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

extern u32 igmp_config_index (const igmp_config_t * c);

extern igmp_config_t *igmp_config_get (u32 index);

/**
 * @brief igmp group lookup
 *  @param config - igmp configuration
 *  @param key - igmp key
*/
extern igmp_group_t *igmp_group_lookup (igmp_config_t * config,
					const igmp_key_t * key);

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
