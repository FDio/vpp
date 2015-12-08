/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
 */
#ifndef __CNAT_CONFIG_API_H__
#define __CNAT_CONFIG_API_H__

typedef struct _spp_api_cnat_v4_add_vrf_map {
    u16 _spp_msg_id;
    u8 rc;
    u8 pad;
    u32 i_vrf_id;
    u32 o_vrf_id;
    u16 i_vrf;
    u16 o_vrf;
    u32 start_addr[8];
    u32 end_addr[8];
} spp_api_cnat_v4_add_vrf_map_t;

typedef struct _spp_api_cnat_v4_config_nfv9_logging {
    u16 _spp_msg_id;
    u8 rc;
    u8 enable;
    u32 ipv4_address;
    u32 i_vrf_id;
    u16 i_vrf;
    u16 port;
    u16 refresh_rate;
    u16 timeout_rate;
    u16 path_mtu;
    u8 nfv9_global_collector;
    u8 session_logging;
} spp_api_cnat_v4_config_nfv9_logging_t;


#endif
