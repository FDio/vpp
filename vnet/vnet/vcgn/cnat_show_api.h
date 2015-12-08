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
#ifndef __CNAT_SHOW_API_H__
#define __CNAT_SHOW_API_H__

typedef struct _spp_api_cnat_v4_show_inside_entry_req {
    u16 _spp_msg_id;
    u16 vrf_id;
    u32 ipv4_addr;
    u16 start_port;
    u16 end_port;
    u8 flags;
    u8 all_entries;
    u8 protocol;
} spp_api_cnat_v4_show_inside_entry_req_t;

typedef struct _spp_api_cnat_v4_show_outside_entry_req {
    u16 _spp_msg_id;
    u16 vrf_id;
    u32 ipv4_addr;
    u16 start_port;
    u16 end_port;
    u8 flags;
    u8 protocol;
} spp_api_cnat_v4_show_outside_entry_req_t;


#endif
