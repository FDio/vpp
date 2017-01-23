/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
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

#ifndef PLUGINS_IOAM_PLUGIN_IOAM_ENCAP_IP6_IOAM_POT_H_
#define PLUGINS_IOAM_PLUGIN_IOAM_ENCAP_IP6_IOAM_POT_H_

#include <vnet/ip/ip6_hop_by_hop_packet.h>

/* *INDENT-OFF* */
typedef CLIB_PACKED (struct {
  ip6_hop_by_hop_option_t hdr;
  u8 pot_type;
  #define PROFILE_ID_MASK 0xF
  u8 reserved_profile_id;	/* 4 bits reserved, 4 bits to carry profile id */
  u64 random;
  u64 cumulative;
}) ioam_pot_option_t;
/* *INDENT-ON* */

#endif /* PLUGINS_IOAM_PLUGIN_IOAM_ENCAP_IP6_IOAM_POT_H_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
