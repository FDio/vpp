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
#include <igmp/igmp_types.h>
#include <igmp/igmp_format.h>
#include <igmp/igmp_timer.h>
#include <igmp/igmp_group.h>
#include <igmp/igmp_config.h>

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



#endif /* _IGMP_H_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
