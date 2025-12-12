/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2016 Cisco and/or its affiliates.
 */

#ifndef __included_ip6_ioam_seqno_h__
#define __included_ip6_ioam_seqno_h__

#include <vnet/ip/ip6_packet.h>
#include <vnet/ip/ip6_hop_by_hop.h>
#include <ioam/lib-e2e/e2e_util.h>

int ioam_seqno_encap_handler(vlib_buffer_t *b, ip6_header_t *ip,
                             ip6_hop_by_hop_option_t *opt);

int
ioam_seqno_decap_handler(vlib_buffer_t *b, ip6_header_t *ip,
                         ip6_hop_by_hop_option_t *opt);

#endif
