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

#include <stdbool.h>
#include <vnet/ip/ip46_address.h>
#include <vnet/mpls/packet.h>
#include <vnet/dpo/dpo.h>
#include <vnet/bier/bier_types.h>

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
static inline fib_protocol_t
fib_ip_proto(bool is_ip6)
{
  return (is_ip6) ? FIB_PROTOCOL_IP6 : FIB_PROTOCOL_IP4;
}

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
     * Contribute an object that is to be used to forward BIER packets.
     */
    FIB_FORW_CHAIN_TYPE_BIER,
    /**
     * Contribute an object that is to be used to forward end-of-stack
     * MPLS packets. This is a convenient ID for clients. A real EOS chain
     * must be pay-load protocol specific. This
     * option is converted into one of the other three internally.
     */
    FIB_FORW_CHAIN_TYPE_MPLS_EOS,
    /**
     * Contribute an object that is to be used to forward IP4 packets
     */
    FIB_FORW_CHAIN_TYPE_MCAST_IP4,
    /**
     * Contribute an object that is to be used to forward IP6 packets
     */
    FIB_FORW_CHAIN_TYPE_MCAST_IP6,
    /**
     * Contribute an object that is to be used to forward Ethernet packets.
     */
    FIB_FORW_CHAIN_TYPE_ETHERNET,
    /**
     * Contribute an object that is to be used to forward NSH packets.
     * This is last in the list since it is not valid for many FIB objects,
     * and thus their array of per-chain-type DPOs can be sized smaller.
     */
    FIB_FORW_CHAIN_TYPE_NSH,
}  __attribute__ ((packed)) fib_forward_chain_type_t;

#define FIB_FORW_CHAINS {					\
    [FIB_FORW_CHAIN_TYPE_ETHERNET]      = "ethernet",     	\
    [FIB_FORW_CHAIN_TYPE_BIER]          = "bier",     	        \
    [FIB_FORW_CHAIN_TYPE_UNICAST_IP4]   = "unicast-ip4",	\
    [FIB_FORW_CHAIN_TYPE_UNICAST_IP6]   = "unicast-ip6",	\
    [FIB_FORW_CHAIN_TYPE_MCAST_IP4]     = "multicast-ip4",	\
    [FIB_FORW_CHAIN_TYPE_MCAST_IP6]     = "multicast-ip6",	\
    [FIB_FORW_CHAIN_TYPE_MPLS_NON_EOS]  = "mpls-neos",	        \
    [FIB_FORW_CHAIN_TYPE_MPLS_EOS]      = "mpls-eos",	        \
    [FIB_FORW_CHAIN_TYPE_NSH]           = "nsh",                \
}

#define FIB_FORW_CHAIN_NUM (FIB_FORW_CHAIN_TYPE_NSH+1)
#define FIB_FORW_CHAIN_MPLS_NUM (FIB_FORW_CHAIN_TYPE_MPLS_EOS+1)

#define FOR_EACH_FIB_FORW_CHAIN(_item)			  \
    for (_item = FIB_FORW_CHAIN_TYPE_UNICAST_IP4;   	  \
	 _item <= FIB_FORW_CHAIN_TYPE_NSH;		  \
	 _item++)

#define FOR_EACH_FIB_FORW_MPLS_CHAIN(_item)		  \
    for (_item = FIB_FORW_CHAIN_TYPE_UNICAST_IP4;   	  \
	 _item <= FIB_FORW_CHAIN_TYPE_MPLS_EOS;		  \
	 _item++)

/**
 * @brief Convert from a chain type to the adjacency's link type
 */
extern vnet_link_t fib_forw_chain_type_to_link_type(fib_forward_chain_type_t fct);

/**
 * @brief Convert from a adjacency's link type to chain type
 */
extern fib_forward_chain_type_t fib_forw_chain_type_from_link_type(vnet_link_t lt);

/**
 * @brief Convert from a payload-protocol to a chain type.
 */
extern fib_forward_chain_type_t fib_forw_chain_type_from_dpo_proto(dpo_proto_t proto);

/**
 * @brief Convert from a fib-protocol to a chain type.
 */
extern fib_forward_chain_type_t fib_forw_chain_type_from_fib_proto(fib_protocol_t proto);

/**
 * @brief Convert from a chain type to the DPO proto it will install
 */
extern dpo_proto_t fib_forw_chain_type_to_dpo_proto(fib_forward_chain_type_t fct);

/**
 * Aggregate type for a prefix
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
 * \brief Copy a prefix
 */
extern void fib_prefix_copy(fib_prefix_t *dst,
                            const fib_prefix_t *src);

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
extern u8 fib_prefix_get_host_length (fib_protocol_t proto);

/**
 * normalise a prefix (i.e. mask the host bits according to the
 * prefix length)
 */
extern void fib_prefix_normalize(const fib_prefix_t *p,
                                 fib_prefix_t *out);

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
 * Convert from BIER next-hop proto to FIB proto
 */
extern fib_protocol_t bier_hdr_proto_to_fib(bier_hdr_proto_id_t bproto);

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

extern u8 * format_fib_protocol(u8 * s, va_list *ap);
extern u8 * format_vnet_link(u8 *s, va_list *ap);

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
    /**
     * A for-us/local path
     */
    FIB_ROUTE_PATH_LOCAL = (1 << 2),
    /**
     * Attached path
     */
    FIB_ROUTE_PATH_ATTACHED = (1 << 3),
    /**
     * A Drop path - resolve the path on the drop DPO
     */
    FIB_ROUTE_PATH_DROP = (1 << 4),
    /**
     * Don't resolve the path, use the DPO the client provides
     */
    FIB_ROUTE_PATH_EXCLUSIVE = (1 << 5),
    /**
     * A path that result in received traffic being recieved/recirculated
     * so that it appears to have arrived on the new interface
     */
    FIB_ROUTE_PATH_INTF_RX = (1 << 6),
    /**
     * A local path with a RPF-ID => multicast traffic
     */
    FIB_ROUTE_PATH_RPF_ID = (1 << 7),
    /**
     * A deag path using the packet's source not destination address.
     */
    FIB_ROUTE_PATH_SOURCE_LOOKUP = (1 << 8),
    /**
     * A path via a UDP encap object.
     */
    FIB_ROUTE_PATH_UDP_ENCAP = (1 << 9),
    /**
     * A path that resolves via a BIER F-Mask
     */
    FIB_ROUTE_PATH_BIER_FMASK = (1 << 10),
    /**
     * A path that resolves via a BIER [ECMP] Table
     */
    FIB_ROUTE_PATH_BIER_TABLE = (1 << 11),
    /**
     * A path that resolves via a BIER impostion object
     */
    FIB_ROUTE_PATH_BIER_IMP = (1 << 12),
    /**
     * A path that resolves via another table
     */
    FIB_ROUTE_PATH_DEAG = (1 << 13),
    /**
     * A path that resolves via a DVR DPO
     */
    FIB_ROUTE_PATH_DVR = (1 << 14),

    FIB_ROUTE_PATH_ICMP_UNREACH = (1 << 15),
    FIB_ROUTE_PATH_ICMP_PROHIBIT = (1 << 16),
    FIB_ROUTE_PATH_CLASSIFY = (1 << 17),

    /**
     * Pop a Psuedo Wire Control Word
     */
    FIB_ROUTE_PATH_POP_PW_CW = (1 << 18),
    /**
     * A path that resolves via a glean adjacency
     */
    FIB_ROUTE_PATH_GLEAN = (1 << 19),
} fib_route_path_flags_t;

/**
 * Format route path flags
 */
extern u8 * format_fib_route_path_flags(u8 *s, va_list *ap);

/**
 * An RPF-ID is numerical value that is used RPF validate. An entry
 * has-a RPF-ID, when a packet egress from (e.g. an LSP) it gains an
 * RPF-ID, these two are compared for the RPF check.
 * This replaces the interfce based chack (since the LSP has no associated
 * interface.
 */
typedef u32 fib_rpf_id_t;

#define MFIB_RPF_ID_NONE (0)

/**
 * MPLS LSP mode - only valid at the head and tail
 */
typedef enum fib_mpls_lsp_mode_t_
{
    /**
     * Pipe Mode - the default.
     *  TTL and DSCP markings are not carried between the layers
     */
    FIB_MPLS_LSP_MODE_PIPE,
    /**
     * Uniform mode.
     *  TTL and DSCP are copied between the layers
     */
    FIB_MPLS_LSP_MODE_UNIFORM,
} __attribute__((packed)) fib_mpls_lsp_mode_t;

#define FIB_MPLS_LSP_MODES {			\
    [FIB_MPLS_LSP_MODE_PIPE]     = "pipe",     	\
    [FIB_MPLS_LSP_MODE_UNIFORM]  = "uniform",   \
}

/**
 * Format an LSP mode type
 */
extern u8 * format_fib_mpls_lsp_mode(u8 *s, va_list *ap);

/**
 * Configuration for each label value in the output-stack
 */
typedef struct fib_mpls_label_t_
{
    /**
     * The label value
     */
    mpls_label_t fml_value;

    /**
     * The LSP mode
     */
    fib_mpls_lsp_mode_t fml_mode;

    /**
     * TTL. valid only at imposition.
     */
    u8 fml_ttl;

    /**
     * EXP bits; valid only at imposition.
     */
    u8 fml_exp;
} fib_mpls_label_t;

/**
 * Format an MPLS label
 */
extern u8 * format_fib_mpls_label(u8 *s, va_list *ap);

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
    dpo_proto_t frp_proto;

    union {
        struct {
            union {
                /**
                 * The next-hop address.
                 * Will be NULL for attached paths.
                 * Will be all zeros for attached-next-hop paths on a p2p interface
                 * Will be all zeros for a deag path.
                 */
                ip46_address_t frp_addr;

                struct {
                    /**
                     * The MPLS local Label to reursively resolve through.
                     * This is valid when the path type is MPLS.
                     */
                    mpls_label_t frp_local_label;
                    /**
                     * EOS bit for the resolving label
                     */
                    mpls_eos_bit_t frp_eos;
                };
                /**
                 * A path via a BIER imposition object.
                 * Present in an mfib path list
                 */
                index_t frp_bier_imp;

                /**
                 * Glean prefix on a glean path
                 */
                fib_prefix_t frp_connected;
            };

            /**
             * The interface.
             * Will be invalid for recursive paths.
             */
            u32 frp_sw_if_index;

            /**
             * The RPF-ID
             */
            fib_rpf_id_t frp_rpf_id;

            union {
                /**
                 * The FIB index to lookup the nexthop
                 * Only valid for recursive paths.
                 */
                u32 frp_fib_index;
                /**
                 * The BIER table to resolve the fmask in
                 */
                u32 frp_bier_fib_index;
            };
            /**
             * The outgoing MPLS label Stack. NULL implies no label.
             */
            fib_mpls_label_t *frp_label_stack;
            /**
	     * Exclusive DPO
	     */
	    dpo_id_t dpo;
            /**
             * MFIB interface flags
             */
            u32 frp_mitf_flags;
        };
        /**
         * A path that resolves via a BIER Table.
         * This would be for a MPLS label at a BIER midpoint or tail
         */
        bier_table_id_t frp_bier_tbl;

        /**
         * UDP encap ID
         */
        u32 frp_udp_encap_id;

        /**
         * Classify table ID
         */
        u32 frp_classify_table_id;

        /**
         * Resolving via a BIER Fmask
         */
        index_t frp_bier_fmask;

        /**
         * The DPO for use with exclusive paths
         */
        dpo_id_t frp_dpo;
    };
    /**
     * [un]equal cost path weight
     */
    u8 frp_weight;
    /**
     * A path preference. 0 is the best.
     * Only paths of the best preference, that are 'up', are considered
     * for forwarding.
     */
    u8 frp_preference;
    /**
     * flags on the path
     */
    fib_route_path_flags_t frp_flags;
} fib_route_path_t;

/**
 * Unformat a fib_route_path_t from CLI input
 */
extern uword unformat_fib_route_path(unformat_input_t * input, va_list * args);

/**
 * Format route path flags
 */
extern u8 * format_fib_route_path(u8 *s, va_list *ap);

/**
 * A help string to list the FIB path options
 */
#define FIB_ROUTE_PATH_HELP "[next-hop-address] [next-hop-interface] [next-hop-table <value>] [weight <value>] [preference <value>] [udp-encap-id <value>] [ip4-lookup-in-table <value>] [ip6-lookup-in-table <value>] [mpls-lookup-in-table <value>] [resolve-via-host] [resolve-via-connected] [rx-ip4 <interface>] [out-labels <value value value>]"

/**
 * return code to control pat-hlist walk
 */
typedef enum fib_path_list_walk_rc_t_
{
    FIB_PATH_LIST_WALK_STOP,
    FIB_PATH_LIST_WALK_CONTINUE,
} fib_path_list_walk_rc_t;

/**
 * A list of path-extensions
 */
typedef struct fib_path_ext_list_t_
{
    struct fib_path_ext_t_ *fpel_exts;
} fib_path_ext_list_t;

#endif
