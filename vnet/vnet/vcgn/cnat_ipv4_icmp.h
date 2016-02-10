/*
 *-----------------------------------------------------------------------------
 *
 * Filename: cnat_ipv4_icmp.h
 *
 * Description: common functions for icmp node
 *
 * Assumptions and Constraints:
 *
 * Copyright (c) 2000-2009, 2014 Cisco and/or its affiliates.
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

#ifndef __CNAT_IPV4_ICMP_H__
#define __CNAT_IPV4_ICMP_H__

#include "tcp_header_definitions.h"
#include "cnat_db.h"
#include "cnat_v4_functions.h"
#include "cnat_global.h"
#include "cnat_config.h"

typedef struct {
    icmp_v4_t   *icmp;
    ipv4_header *em_ip;
    u16         *em_port;
    u16         *em_l4_checksum;
} icmp_em_ip_info;

extern void swap_ip_src_icmp_id(ipv4_header *ip,
                                icmp_v4_t *icmp,
                                cnat_main_db_entry_t *db, 
				                u16 vrf);

extern void swap_ip_dst_icmp_id(ipv4_header *ip,
                                icmp_v4_t *icmp,
                                cnat_main_db_entry_t *db, 
				                u16 vrf);

extern void swap_ip_src_emip_dst(ipv4_header *ip,
                                 icmp_em_ip_info *icmp_info,
                                 cnat_main_db_entry_t *db, u16 vrf);

extern void swap_ip_dst_emip_src(ipv4_header *ip,
                                 icmp_em_ip_info *icmp_info,
                                 cnat_main_db_entry_t *db, u16 vrf);


#endif /* __CNAT_IPV4_ICMP_H__ */
