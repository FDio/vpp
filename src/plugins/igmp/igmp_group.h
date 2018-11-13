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

#ifndef __IGMP_GROUP_H__
#define __IGMP_GROUP_H__

#include <igmp/igmp_types.h>
#include <igmp/igmp_src.h>

/**
 * QUERY_REPLY = Timer running to reply to a G/SG specific query
 * QUERY_SENT  = wait for response from a sent G/SG specific query.
 *               Sent when a host leaves a group
 * RESEND_REPORT = Timer running to resend report
 * FILTER_MODE_CHANGE = to check if the group can swap to
 *                      INCLUDE mode (section 6.2.2)
 */
#define foreach_igmp_group_timer                \
  _(QUERY_REPLY, "query-reply")                 \
  _(QUERY_SENT,  "query-sent")                  \
  _(RESEND_REPORT, "resend-report")             \
  _(FILTER_MODE_CHANGE, "filter-mode-change")

/**
 * Types of timers maintained for each group
 */
typedef enum igmp_group_timer_type_t_
{
#define _(v,s) IGMP_GROUP_TIMER_##v,
  foreach_igmp_group_timer
#undef _
} igmp_group_timer_type_t;

#define IGMP_GROUP_N_TIMERS (IGMP_GROUP_TIMER_FILTER_MODE_CHANGE + 1)

extern u8 *format_igmp_group_timer_type (u8 * s, va_list * args);

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
   * The pool index of the config object this group is in
   */
  u32 config;

  /**
   * The number of times the last report has been sent
   */
  u32 n_reports_sent;

  /**
   * Source list per-filter mode
   */
  uword *igmp_src_by_key[IGMP_N_FILTER_MODES];
} igmp_group_t;

#define FOR_EACH_SRC(_src, _group, _filter, _body)                       \
do {                                                                    \
  igmp_key_t *__key__;                                                  \
  u32 __sid__;                                                          \
  hash_foreach_mem(__key__, __sid__, ((igmp_group_t*)_group)->igmp_src_by_key[(_filter)], \
  ({                                                                    \
    _src = pool_elt_at_index(igmp_main.srcs, __sid__);                  \
    do { _body; } while (0);                                            \
  }));                                                                  \
 } while (0);

/**
 * Forward declarations
 */
struct igmp_config_t_;

extern void igmp_group_clear (igmp_group_t * group);
extern void igmp_group_free_all_srcs (igmp_group_t * group);

extern igmp_group_t *igmp_group_alloc (struct igmp_config_t_ *config,
				       const igmp_key_t * gkey,
				       igmp_filter_mode_t mode);

extern igmp_src_t *igmp_group_src_update (igmp_group_t * group,
					  const igmp_key_t * skey,
					  igmp_mode_t mode);

extern void igmp_group_src_remove (igmp_group_t * group, igmp_src_t * src);
extern u8 *format_igmp_group (u8 * s, va_list * args);


extern ip46_address_t *igmp_group_present_minus_new (igmp_group_t * group,
						     igmp_filter_mode_t mode,
						     const ip46_address_t *
						     saddrs);

extern ip46_address_t *igmp_group_new_minus_present (igmp_group_t * group,
						     igmp_filter_mode_t mode,
						     const ip46_address_t *
						     saddrs);

extern ip46_address_t *igmp_group_new_intersect_present (igmp_group_t * group,
							 igmp_filter_mode_t
							 mode,
							 const ip46_address_t
							 * saddrs);

extern u32 igmp_group_n_srcs (const igmp_group_t * group,
			      igmp_filter_mode_t mode);


/** \brief igmp group lookup
    @param group - igmp group
    @param key - igmp key
*/
extern igmp_src_t *igmp_src_lookup (igmp_group_t * group,
				    const igmp_key_t * key);

extern u32 igmp_group_index (const igmp_group_t * g);
extern igmp_group_t *igmp_group_get (u32 index);

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
