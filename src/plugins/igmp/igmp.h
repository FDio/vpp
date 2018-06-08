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

/**
 * RFC 3376 Section 8.1
 */
#define IGMP_DEFAULT_ROBUSTNESS_VARIABLE	(2)

#define IGMP_DBG(...) \
    vlib_log_debug (igmp_main.logger, __VA_ARGS__);

/**
 * General Query address - 224.0.0.1
 * Membership Report address - 224.0.0.22
 * SSM default range 232/8
 */
#if CLIB_ARCH_IS_BIG_ENDIAN
#define IGMP_GENERAL_QUERY_ADDRESS	(0xE0000001)
#define IGMP_MEMBERSHIP_REPORT_ADDRESS	(0xE0000016)
#define IGMP_SSM_DEFAULT        	(0xE8000000)
#else
#define IGMP_GENERAL_QUERY_ADDRESS	(0x010000E0)
#define IGMP_MEMBERSHIP_REPORT_ADDRESS	(0x160000E0)
#define IGMP_SSM_DEFAULT        	(0x000000E8)
#endif

/** helper macro to get igmp mebership group from pointer plus offset */
#define group_ptr(p, l) ((igmp_membership_group_v3_t *)((u8*)(p) + (l)))
#define group_cptr(p, l) ((const igmp_membership_group_v3_t *)((u8*)(p) + (l)))

/**
 * collection of data related to IGMP
 */
typedef struct igmp_main_t_
{
  /**
   * API base message ID
   */
  u16 msg_id_base;

  uword *igmp_api_client_by_client_index;

  /**
   * API client registered for events
   */
  vpe_client_registration_t *api_clients;

  /**
   * per-interface DB of configs
   */
  u32 *igmp_config_by_sw_if_index;

  /**
   * the number of igmp configs for each mfib_index (VRF)
   */
  u32 *n_configs_per_mfib_index;

  /**
   * logger - VLIB log class
   */
  vlib_log_class_t logger;

  /**
   * pool of configs
   */
  igmp_config_t *configs;

  /**
   * pool of groups
   */
  igmp_group_t *groups;
  /**
   * pool of sources
   */
  igmp_src_t *srcs;
} igmp_main_t;

extern igmp_main_t igmp_main;

/**
 * @brief IGMP interface enable/disable
 *  @param sw_if_index - Interface
 *  @param enable - enable/disable
 *  @param mode - Host or router
 */
int igmp_enable_disable (u32 sw_if_index, u8 enable, igmp_mode_t mode);

/**
 * @brief igmp listen
 *  Called by a host to request reception of multicast packets
 * @param vm - vlib main
 * @param filter - Filter mode
 * @param sw_if_index - interface sw_if_index
 * @param saddr - source address
 * @param gaddr - group address
 *
 *    Add/del (S,G) on an interface.
 *   send a status change report from the interface.
 */
int igmp_listen (vlib_main_t * vm,
		 igmp_filter_mode_t filter,
		 u32 sw_if_index,
		 const ip46_address_t * saddr, const ip46_address_t * gaddr);

/**
 * @brief Send an IGMP event to listening parties
 * @param filter mode
 * @param sw_if_index
 * @param saddr
 * @param gaddr
 */
void igmp_event (igmp_filter_mode_t filter,
		 u32 sw_if_index,
		 const ip46_address_t * saddr, const ip46_address_t * gaddr);

#endif /* _IGMP_H_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
