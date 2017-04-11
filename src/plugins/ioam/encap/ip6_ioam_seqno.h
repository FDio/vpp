/*
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

#ifndef __included_ip6_ioam_seqno_h__
#define __included_ip6_ioam_seqno_h__

#include "vnet/ip/ip6_packet.h"
#include "vnet/ip/ip6_hop_by_hop.h"
#include "ioam/lib-e2e/e2e_util.h"

int ioam_seqno_encap_handler(vlib_buffer_t *b, ip6_header_t *ip,
                             ip6_hop_by_hop_option_t *opt);

int
ioam_seqno_decap_handler(vlib_buffer_t *b, ip6_header_t *ip,
                         ip6_hop_by_hop_option_t *opt);

#endif
