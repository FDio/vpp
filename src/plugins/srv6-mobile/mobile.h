/*
 * srv6_end.h
 *
 * Copyright (c) 2016 Cisco and/or its affiliates.
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

#ifndef __included_srv6_end_h__
#define __included_srv6_end_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/srv6/sr.h>
#include <vnet/srv6/sr_packet.h>

#include <vppinfra/error.h>
#include <vppinfra/elog.h>

#define SRV6_GTP_UDP_DST_PORT 2152


typedef struct srv6_end_main_v4_s
{

  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;

  u32 end_m_gtp4_e_node_index;
  u32 error_node_index;

  u32 dst_p_len; // dst prefix len
  u32 src_p_len; // src prefix len

  ip4_gtpu_header_t cache_hdr;

} srv6_end_main_v4_t;

extern srv6_end_main_v4_t srv6_end_main_v4;
extern vlib_node_registration_t srv6_end_m_gtp4_e;

typedef struct srv6_end_main_v6_s
{
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;

  u32 end_m_gtp6_e_node_index;
  u32 error_node_index;

  u32 dst_p_len;
  u32 src_p_len;

  ip6_gtpu_header_t cache_hdr;
} srv6_end_main_v6_t;

extern srv6_end_main_v6_t srv6_end_main_v6;
extern vlib_node_registration_t srv6_end_m_gtp6_e;

typedef struct srv6_end_main_v6_decap_s
{
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;

  u32 end_m_gtp6_d_node_index;
  u32 error_node_index;

} srv6_end_main_v6_decap_t;

extern srv6_end_main_v6_decap_t srv6_end_main_v6_decap;
extern vlib_node_registration_t srv6_end_m_gtp6_d;

#endif /* __included_srv6_end_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
