/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2018 Cisco and/or its affiliates.
 */

#ifndef _IGMP_PROXY_H_
#define _IGMP_PROXY_H_

#include <igmp/igmp_types.h>
#include <igmp/igmp_config.h>

typedef struct
{
  /* VRF index */
  u32 vrf_id;

  /* upstream interface */
  u32 upstream_if;

  /* downstream interfaces */
  u32 *downstream_ifs;
} igmp_proxy_device_t;

/**
 * @brief IGMP proxy device add/del
 *  @param vrf_id - VRF id
 *  @param sw_if_index - upstream interface
 *  @param add - add/del
 *
 * Add/del IGMP proxy device. Interface must be IGMP enabled in HOST mode.
 */
int igmp_proxy_device_add_del (u32 vrf_id, u32 sw_if_index, u8 add);

/**
 * @brief IGMP proxy device add/del interface
 *  @param vrf_id - VRF id
 *  @param sw_if_index - downstream interface
 *  @param add - add/del
 *
 * Add/del IGMP enabled interface in ROUTER mode to proxy device.
 */
int igmp_proxy_device_add_del_interface (u32 vrf_id, u32 sw_if_index, u8 add);

void igmp_proxy_device_merge_config (igmp_config_t *config, u8 block);

void igmp_proxy_device_block_src (igmp_config_t *config, igmp_group_t *group, igmp_src_t *src);

void igmp_proxy_device_mfib_path_add_del (igmp_group_t *group, u8 add);

#endif /* IGMP_PROXY_H */
