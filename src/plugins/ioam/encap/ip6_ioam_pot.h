/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2017 Cisco and/or its affiliates.
 */

#ifndef PLUGINS_IOAM_PLUGIN_IOAM_ENCAP_IP6_IOAM_POT_H_
#define PLUGINS_IOAM_PLUGIN_IOAM_ENCAP_IP6_IOAM_POT_H_

#include <vnet/ip/ip6_hop_by_hop_packet.h>

typedef CLIB_PACKED (struct {
  ip6_hop_by_hop_option_t hdr;
  u8 pot_type;
  #define PROFILE_ID_MASK 0xF
  u8 reserved_profile_id;	/* 4 bits reserved, 4 bits to carry profile id */
  u64 random;
  u64 cumulative;
}) ioam_pot_option_t;

#endif /* PLUGINS_IOAM_PLUGIN_IOAM_ENCAP_IP6_IOAM_POT_H_ */
