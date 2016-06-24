/*
 *-----------------------------------------------------------------------------
 *
 * Filename: cnat_ipv4_udp.h
 *
 * Description: common functions for udp node
 *
 * Assumptions and Constraints:
 *
 * Copyright (c) 2000-2009 Cisco and/or its affiliates.
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
 *-----------------------------------------------------------------------------
 */

#ifndef __CNAT_IPV4_UDP_H__
#define __CNAT_IPV4_UDP_H__

#include "tcp_header_definitions.h"
#include "cnat_db.h"
#include "cnat_v4_functions.h"
#include "cnat_global.h"
#include "cnat_config.h"

extern void swap_ip_src_udp_port(ipv4_header *ip,
                                 udp_hdr_type_t *udp,
                                 cnat_main_db_entry_t *db);
extern void swap_ip_dst_udp_port(ipv4_header *ip,
                                 udp_hdr_type_t *udp,
                                 cnat_main_db_entry_t *db,
                                 u16 vrf);
#endif /* __CNAT_IPV4_UDP_H__ */
