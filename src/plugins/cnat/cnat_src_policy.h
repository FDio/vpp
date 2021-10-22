/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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

#ifndef __CNAT_SRC_POLICY_H__
#define __CNAT_SRC_POLICY_H__

#include <cnat/cnat_types.h>
#include <cnat/cnat_session.h>
#include <cnat/cnat_translation.h>

typedef enum
{
  CNAT_SPORT_PROTO_TCP,
  CNAT_SPORT_PROTO_UDP,
  CNAT_SPORT_PROTO_ICMP,
  CNAT_SPORT_PROTO_ICMP6,
  CNAT_N_SPORT_PROTO
} cnat_sport_proto_t;

typedef enum cnat_source_policy_errors_
{
  CNAT_SOURCE_ERROR_EXHAUSTED_PORTS = 1,
  CNAT_SOURCE_ERROR_USE_DEFAULT = 2,
} cnat_source_policy_errors_t;

typedef struct cnat_src_port_allocator_
{
  /* Source ports bitmap for snat */
  clib_bitmap_t *bmap;

  /* Lock for src_ports access */
  clib_spinlock_t lock;
} cnat_src_port_allocator_t;

/* function to use to compute source (IP, port) for a new session to a vip */
typedef cnat_source_policy_errors_t (*cnat_vip_source_policy_t) (
  ip_protocol_t iproto, u16 *sport);

typedef struct cnat_src_policy_main_
{
  cnat_vip_source_policy_t vip_policy;
  cnat_vip_source_policy_t default_policy;

  /* Per proto source ports allocator for snat */
  cnat_src_port_allocator_t *src_ports;
} cnat_src_policy_main_t;

extern cnat_src_policy_main_t cnat_src_policy_main;

void cnat_register_vip_src_policy (cnat_vip_source_policy_t fp);
int cnat_allocate_port (u16 * port, ip_protocol_t iproto);
void cnat_free_port (u16 port, ip_protocol_t iproto);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

#endif
