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

#ifndef __FIB_TYPES_H__
#define __FIB_TYPES_H__

#include <vlib/vlib.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/mpls/packet.h>
#include <vnet/dpo/dpo.h>

/**
 * A typedef of a node index.
 * we make this typedef so the code becomes easier for a human to parse.
 */
typedef u32 fib_node_index_t;
#define FIB_NODE_INDEX_INVALID ((fib_node_index_t)(~0))

/**
 * Protocol Type. packed so it consumes a u8 only
 */
typedef enum fib_protocol_t_ {
    FIB_PROTOCOL_IP4 = 1,
    FIB_PROTOCOL_IP6,
}  __attribute__ ((packed)) fib_protocol_t;

/**
 * Not part of the enum so it does not have to be handled in switch statements
 */
#define FIB_PROTOCOL_NONE ((fib_protocol_t)(0))

#define FIB_PROTOCOLS {			\
    [FIB_PROTOCOL_IP4] = "ipv4",	\
    [FIB_PROTOCOL_IP6] = "ipv6",       \
}

/**
 * Definition outside of enum so it does not need to be included in non-defaulted
 * switch statements
 */
#define FIB_PROTOCOL_MAX (FIB_PROTOCOL_IP6 + 1)

/**
 * Link Type. This maps directly into the ethertype.
 */
typedef enum fib_link_t_ {
    FIB_LINK_IP4 = 1,
    FIB_LINK_IP6,
    FIB_LINK_MPLS,
}  __attribute__ ((packed)) fib_link_t;

/**
 * Definition outside of enum so it does not need to be included in non-defaulted
 * switch statements
 */
#define FIB_LINK_NUM (FIB_LINK_MPLS+1)

#define FIB_LINKS {		\
    [FIB_LINK_IP4] = "ipv4",	\
    [FIB_LINK_IP6] = "ipv6",   \
    [FIB_LINK_MPLS] = "mpls",   \
}

#define FOR_EACH_FIB_LINK(_item)  \
    for (_item = FIB_LINK_IP4;	  \
	 _item <= FIB_LINK_MPLS;  \
	 _item++)

/**
 * @brief Convert from a protocol to a link type
 */
fib_link_t fib_proto_to_link (fib_protocol_t proto);

/**
 * FIB output chain type. When a child object requests a forwarding contribution
 * from a parent, it does so for a particular scenario. This enumererates those
 * sceanrios
 */
typedef enum fib_forward_chain_type_t_ {
    /**
     * Contribute an object that is to be used to forward IP packets
     */
    FIB_FORW_CHAIN_TYPE_UNICAST_IP,
    /**
     * Contribute an object that is to be used to forward non-end-of-stack
     * MPLS packets
     */
    FIB_FORW_CHAIN_TYPE_MPLS_NON_EOS,
    /**
     * Contribute an object that is to be used to forward end-of-stack
     * MPLS packets
     */
    FIB_FORW_CHAIN_TYPE_MPLS_EOS,
}  __attribute__ ((packed)) fib_forward_chain_type_t;

#define FIB_FORW_CHAINS {		\
    [FIB_FORW_CHAIN_TYPE_UNICAST_IP]   = "unicast-ip",	\
    [FIB_FORW_CHAIN_TYPE_MPLS_NON_EOS] = "mpls-neos",	\
    [FIB_FORW_CHAIN_TYPE_MPLS_EOS]     = "mpls-eos",	\
}

#define FIB_FORW_CHAIN_NUM (FIB_FORW_CHAIN_TYPE_MPLS_EOS+1)

#define FOR_EACH_FIB_FORW_CHAIN(_item)			  \
    for (_item = FIB_FORW_CHAIN_TYPE_UNICAST_IP;	  \
	 _item <= FIB_FORW_CHAIN_TYPE_MPLS_EOS;		  \
	 _item++)

/**
 * Aggregrate type for a prefix
 */
typedef struct fib_prefix_t_ {
    /**
     * The mask length
     */
    u16 fp_len;

    /**
     * protocol type
     */
    fib_protocol_t fp_proto;

    /**
     * Pad to keep the address 4 byte aligned
     */
    u8 ___fp___pad;

    /**
     * The address type is not deriveable from the fp_addr member.
     * If it's v4, then the first 3 u32s of the address will be 0.
     * v6 addresses (even v4 mapped ones) have at least 2 u32s assigned
     * to non-zero values. true. but when it's all zero, one cannot decide.
     */
    ip46_address_t fp_addr;
} fib_prefix_t;

_Static_assert(STRUCT_OFFSET_OF(fib_prefix_t, fp_addr) == 4,
	       "FIB Prefix's address is 4 byte aligned.");

/**
 * \brief Compare two prefixes for equality
 */
extern int fib_prefix_cmp(const fib_prefix_t *p1,
			  const fib_prefix_t *p2);

/**
 * \brief Compare two prefixes for covering relationship
 *
 * \return non-zero if the first prefix is a cover for the second
 */
extern int fib_prefix_is_cover(const fib_prefix_t *p1,
			       const fib_prefix_t *p2);

/**
 * \brief Return true is the prefix is a host prefix
 */
extern int fib_prefix_is_host(const fib_prefix_t *p);

extern u8 * format_fib_prefix(u8 * s, va_list * args);
extern u8 * format_fib_forw_chain_type(u8 * s, va_list * args);

extern dpo_proto_t fib_proto_to_dpo(fib_protocol_t fib_proto);
extern fib_protocol_t dpo_proto_to_fib(dpo_proto_t dpo_proto);

/**
 * Enurmeration of special path/entry types
 */
typedef enum fib_special_type_t_ {
    /**
     * Marker. Add new types after this one.
     */
    FIB_SPECIAL_TYPE_FIRST = 0,
    /**
     * Local/for-us paths
     */
    FIB_SPECIAL_TYPE_LOCAL = FIB_SPECIAL_TYPE_FIRST,
    /**
     * drop paths
     */
    FIB_SPECIAL_TYPE_DROP,
    /**
     * Marker. Add new types before this one, then update it.
     */
    FIB_SPECIAL_TYPE_LAST = FIB_SPECIAL_TYPE_DROP,
} __attribute__ ((packed)) fib_special_type_t;

/**
 * The maximum number of types
 */
#define FIB_SPEICAL_TYPE_MAX (FIB_SPEICAL_TYPE_LAST + 1)

#define FIB_SPEICAL_TYPES {				\
    [FIB_SPEICAL_TYPE_ATTACHED_NEXT_HOP] = "local",	\
    [FIB_SPEICAL_TYPE_ATTACHED]          = "drop",	\
}

#define FOR_EACH_FIB_SPEICAL_TYPE(_item)		\
    for (_item = FIB_TYPE_SPEICAL_FIRST;		\
	 _item <= FIB_SPEICAL_TYPE_LAST; _item++)

extern u8 * format_fib_protocol(u8 * s, va_list ap);
extern u8 * format_fib_link(u8 *s, va_list ap);

/**
 * Path flags from the control plane
 */
typedef enum fib_route_path_flags_t_
{
    FIB_ROUTE_PATH_FLAG_NONE = 0,
    /**
     * Recursion constraint of via a host prefix
     */
    FIB_ROUTE_PATH_RESOLVE_VIA_HOST = (1 << 0),
    /**
     * Recursion constraint of via an attahced prefix
     */
    FIB_ROUTE_PATH_RESOLVE_VIA_ATTACHED = (1 << 1),
} fib_route_path_flags_t;

/**
 * A representation of a path as described by a route producer
 */
typedef struct fib_route_path_t_ {
    /**
     * The protocol of the address below. We need this since the all
     * zeros address is ambiguous.
     */
    fib_protocol_t frp_proto;
    /**
     * The next-hop address. Can be NULL or all zeros (for attached)
     */
    ip46_address_t frp_addr;
    /**
     * The interface. Can be invalid (for recursives)
     */
    u32 frp_sw_if_index;
    /**
     * The FIB index to lookup the nexthop (only for recursives)
     */
    u32 frp_fib_index;
    /**
     * UCMP weight
     */
    u32 frp_weight;
    /**
     * flags on the path
     */
    fib_route_path_flags_t frp_flags;
    /**
     * The outgoing MPLS label
     */
    mpls_label_t frp_label;
} fib_route_path_t;

#endif
