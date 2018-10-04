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

#ifndef _IGMP_PROXY_H_
#define _IGMP_PROXY_H_

#include <igmp/igmp_types.h>
#include <igmp/igmp_config.h>

typedef struct
{
  /* VRF index */
  u32 vrf_id;

  /* upstrema interface */
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
int igmp_proxy_device_add_del (u32 vfr_id, u32 sw_if_index, u8 add);

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
