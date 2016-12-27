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
    FIB_PROTOCOL_IP4 = 0,
    FIB_PROTOCOL_IP6,
    FIB_PROTOCOL_MPLS,
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
 * @brief Convert from a protocol to a link type
 */
vnet_link_t fib_proto_to_link (fib_protocol_t proto);

/**
 * FIB output chain type. When a child object requests a forwarding contribution
 * from a parent, it does so for a particular scenario. This enumererates those
 * sceanrios
 */
typedef enum fib_forward_chain_type_t_ {
    /**
     * Contribute an object that is to be used to forward IP4 packets
     */
    FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
    /**
     * Contribute an object that is to be used to forward IP6 packets
     */
    FIB_FORW_CHAIN_TYPE_UNICAST_IP6,
    /**
     * Contribute an object that is to be used to forward non-end-of-stack
     * MPLS packets
     */
    FIB_FORW_CHAIN_TYPE_MPLS_NON_EOS,
    /**
     * Contribute an object that is to be used to forward end-of-stack
     * MPLS packets. This is a convenient ID for clients. A real EOS chain
     * must be pay-load protocol specific. This
     * option is converted into one of the other three internally.
     */
    FIB_FORW_CHAIN_TYPE_MPLS_EOS,
    /**
     * Contribute an object that is to be used to forward Ethernet packets.
     * This is last in the list since it is not valid for many FIB objects,
     * and thus their array of per-chain-type DPOs can be sized smaller.
     */
    FIB_FORW_CHAIN_TYPE_ETHERNET,
}  __attribute__ ((packed)) fib_forward_chain_type_t;

#define FIB_FORW_CHAINS {					\
    [FIB_FORW_CHAIN_TYPE_ETHERNET]      = "ethernet",     	\
    [FIB_FORW_CHAIN_TYPE_UNICAST_IP4]   = "unicast-ip4",	\
    [FIB_FORW_CHAIN_TYPE_UNICAST_IP6]   = "unicast-ip6",	\
    [FIB_FORW_CHAIN_TYPE_MPLS_NON_EOS]  = "mpls-neos",	        \
    [FIB_FORW_CHAIN_TYPE_MPLS_EOS]      = "mpls-eos",	        \
}

#define FIB_FORW_CHAIN_NUM (FIB_FORW_CHAIN_TYPE_MPLS_ETHERNET+1)
#define FIB_FORW_CHAIN_MPLS_NUM (FIB_FORW_CHAIN_TYPE_MPLS_EOS+1)

#define FOR_EACH_FIB_FORW_CHAIN(_item)			  \
    for (_item = FIB_FORW_CHAIN_TYPE_UNICAST_IP4;   	  \
	 _item <= FIB_FORW_CHAIN_TYPE_ETHERNET;		  \
	 _item++)

#define FOR_EACH_FIB_FORW_MPLS_CHAIN(_item)		  \
    for (_item = FIB_FORW_CHAIN_TYPE_UNICAST_IP4;   	  \
	 _item <= FIB_FORW_CHAIN_TYPE_MPLS_EOS;		  \
	 _item++)

/**
 * @brief Convert from a chain type to the adjacencies link type
 */
extern vnet_link_t fib_forw_chain_type_to_link_type(fib_forward_chain_type_t fct);

/**
 * @brief Convert from a payload-protocol to a chain type.
 */
extern fib_forward_chain_type_t fib_forw_chain_type_from_dpo_proto(dpo_proto_t proto);

/**
 * @brief Convert from a chain type to the DPO proto it will install
 */
extern dpo_proto_t fib_forw_chain_type_to_dpo_proto(fib_forward_chain_type_t fct);

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

    union {
	/**
	 * The address type is not deriveable from the fp_addr member.
	 * If it's v4, then the first 3 u32s of the address will be 0.
	 * v6 addresses (even v4 mapped ones) have at least 2 u32s assigned
	 * to non-zero values. true. but when it's all zero, one cannot decide.
	 */
	ip46_address_t fp_addr;

	struct {
	    mpls_label_t fp_label;
	    mpls_eos_bit_t fp_eos;
	    /**
	     * This protocol determines the payload protocol of packets
	     * that will be forwarded by this entry once the label is popped.
	     * For a non-eos entry it will be MPLS.
	     */
	    dpo_proto_t fp_payload_proto;
	};
    };
} fib_prefix_t;

STATIC_ASSERT(STRUCT_OFFSET_OF(fib_prefix_t, fp_addr) == 4,
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


/**
 * \brief Host prefix from ip
 */
extern void fib_prefix_from_ip46_addr (const ip46_address_t *addr,
			   fib_prefix_t *pfx);

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

#define FOR_EACH_FIB_SPEICAL_TYPE(_item)		\
    for (_item = FIB_TYPE_SPEICAL_FIRST;		\
	 _item <= FIB_SPEICAL_TYPE_LAST; _item++)

extern u8 * format_fib_protocol(u8 * s, va_list ap);
extern u8 * format_vnet_link(u8 *s, va_list ap);

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
 * @brief 
 * A representation of a path as described by a route producer.
 * These paramenters will determine the path 'type', of which there are:
 * 1) Attached-next-hop:
 *   a single peer on a link.
 *   It is 'attached' because it is in the same sub-net as the router, on a link
 *   directly connected to the route.
 *   It is 'next=hop' since the next-hop address of the peer is known.
 * 2) Attached:
 *  the next-hop is not known. but we can ARP for it.
 * 3) Recursive.
 *  The next-hop is known but the interface is not. So to find the adj to use
 *  we must recursively resolve the next-hop.
 * 3) deaggregate (deag)
 *  A further lookup is required.
 */
typedef struct fib_route_path_t_ {
    /**
     * The protocol of the address below. We need this since the all
     * zeros address is ambiguous.
     */
    fib_protocol_t frp_proto;

    union {
	/**
	 * The next-hop address.
	 * Will be NULL for attached paths.
	 * Will be all zeros for attached-next-hop paths on a p2p interface
	 * Will be all zeros for a deag path.
	 */
	ip46_address_t frp_addr;

	/**
	 * The MPLS local Label to reursively resolve through.
	 * This is valid when the path type is MPLS.
	 */
	mpls_label_t frp_local_label;
    };
    /**
     * The interface.
     * Will be invalid for recursive paths.
     */
    u32 frp_sw_if_index;
    /**
     * The FIB index to lookup the nexthop
     * Only valid for recursive paths.
     */
    u32 frp_fib_index;
    /**
     * [un]equal cost path weight
     */
    u32 frp_weight;
    /**
     * flags on the path
     */
    fib_route_path_flags_t frp_flags;
    /**
     * The outgoing MPLS label Stack. NULL implies no label.
     */
    mpls_label_t *frp_label_stack;
} fib_route_path_t;

/**
 * @brief 
 * A representation of a fib path for fib_path_encode to convey the information to the caller
 */
typedef struct fib_route_path_encode_t_ {
    fib_route_path_t rpath;
    dpo_id_t dpo;
} fib_route_path_encode_t;

#endif
