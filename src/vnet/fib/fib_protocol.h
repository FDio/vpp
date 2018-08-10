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

#ifndef __FIB_PROTOCOL_H__
#define __FIB_PROTOCOL_H__

#include <stdbool.h>
#include <vlib/vlib.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/dpo/dpo.h>

/**
 * Protocol Type. packed so it consumes a u8 only
 */
typedef enum fib_protocol_t_ {
    FIB_PROTOCOL_IP4 = DPO_PROTO_IP4,
    FIB_PROTOCOL_IP6 = DPO_PROTO_IP6,
    FIB_PROTOCOL_MPLS = DPO_PROTO_MPLS,
}  __attribute__ ((packed)) fib_protocol_t;

#define FIB_PROTOCOLS {			\
    [FIB_PROTOCOL_IP4] = "ipv4",	\
    [FIB_PROTOCOL_IP6] = "ipv6",        \
    [FIB_PROTOCOL_MPLS] = "MPLS",       \
}

/**
 * Definition outside of enum so it does not need to be included in non-defaulted
 * switch statements
 */
#define FIB_PROTOCOL_MAX (FIB_PROTOCOL_MPLS + 1)

/**
 * Definition outside of enum so it does not need to be included in non-defaulted
 * switch statements
 */
#define FIB_PROTOCOL_IP_MAX (FIB_PROTOCOL_IP6 + 1)

/**
 * Not part of the enum so it does not have to be handled in switch statements
 */
#define FIB_PROTOCOL_NONE (FIB_PROTOCOL_MAX+1)

#define FOR_EACH_FIB_PROTOCOL(_item)    \
    for (_item = FIB_PROTOCOL_IP4;      \
	 _item <= FIB_PROTOCOL_MPLS;    \
	 _item++)

#define FOR_EACH_FIB_IP_PROTOCOL(_item)    \
    for (_item = FIB_PROTOCOL_IP4;         \
	 _item <= FIB_PROTOCOL_IP6;        \
	 _item++)

/**
 * @brief Convert from boolean is_ip6 to FIB protocol.
 * Drop MPLS on the floor in favor of IPv4.
 */
extern fib_protocol_t fib_ip_proto(bool is_ip6);

/**
 * @brief Convert from fib_protocol to ip46_type
 */
extern ip46_type_t fib_proto_to_ip46(fib_protocol_t fproto);

/**
 * @brief Convert from ip46_type to fib_protocol
 */
extern fib_protocol_t fib_proto_from_ip46(ip46_type_t iproto);

/**
 * @brief Convert from a protocol to a link type
 */
vnet_link_t fib_proto_to_link (fib_protocol_t proto);


#endif
