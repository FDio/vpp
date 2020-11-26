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

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ip/format.h>
#include <vnet/ip/ip.h>
#include <vnet/dpo/drop_dpo.h>
#include <vnet/dpo/receive_dpo.h>
#include <vnet/dpo/load_balance_map.h>
#include <vnet/dpo/lookup_dpo.h>
#include <vnet/dpo/interface_rx_dpo.h>
#include <vnet/dpo/mpls_disposition.h>
#include <vnet/dpo/dvr_dpo.h>
#include <vnet/dpo/ip_null_dpo.h>
#include <vnet/dpo/classify_dpo.h>
#include <vnet/dpo/pw_cw.h>

#include <vnet/adj/adj.h>
#include <vnet/adj/adj_mcast.h>

#include <vnet/fib/fib_path.h>
#include <vnet/fib/fib_node.h>
#include <vnet/fib/fib_table.h>
#include <vnet/fib/fib_entry.h>
#include <vnet/fib/fib_path_list.h>
#include <vnet/fib/fib_internal.h>
#include <vnet/fib/fib_urpf_list.h>
#include <vnet/fib/mpls_fib.h>
#include <vnet/fib/fib_path_ext.h>
#include <vnet/udp/udp_encap.h>
#include <vnet/bier/bier_fmask.h>
#include <vnet/bier/bier_table.h>
#include <vnet/bier/bier_imp.h>
#include <vnet/bier/bier_disp_table.h>

/**
 * Enurmeration of path types
 */
typedef enum fib_path_type_t_ {
    /**
     * Marker. Add new types after this one.
     */
    FIB_PATH_TYPE_FIRST = 0,
    /**
     * Attached-nexthop. An interface and a nexthop are known.
     */
    FIB_PATH_TYPE_ATTACHED_NEXT_HOP = FIB_PATH_TYPE_FIRST,
    /**
     * attached. Only the interface is known.
     */
    FIB_PATH_TYPE_ATTACHED,
    /**
     * recursive. Only the next-hop is known.
     */
    FIB_PATH_TYPE_RECURSIVE,
    /**
     * special. nothing is known. so we drop.
     */
    FIB_PATH_TYPE_SPECIAL,
    /**
     * exclusive. user provided adj.
     */
    FIB_PATH_TYPE_EXCLUSIVE,
    /**
     * deag. Link to a lookup adj in the next table
     */
    FIB_PATH_TYPE_DEAG,
    /**
     * interface receive.
     */
    FIB_PATH_TYPE_INTF_RX,
    /**
     * Path resolves via a UDP encap object.
     */
    FIB_PATH_TYPE_UDP_ENCAP,
    /**
     * receive. it's for-us.
     */
    FIB_PATH_TYPE_RECEIVE,
    /**
     * bier-imp. it's via a BIER imposition.
     */
    FIB_PATH_TYPE_BIER_IMP,
    /**
     * bier-fmask. it's via a BIER ECMP-table.
     */
    FIB_PATH_TYPE_BIER_TABLE,
    /**
     * bier-fmask. it's via a BIER f-mask.
     */
    FIB_PATH_TYPE_BIER_FMASK,
    /**
     * via a DVR.
     */
    FIB_PATH_TYPE_DVR,
} __attribute__ ((packed)) fib_path_type_t;

#define FIB_PATH_TYPES {					\
    [FIB_PATH_TYPE_ATTACHED_NEXT_HOP] = "attached-nexthop",	\
    [FIB_PATH_TYPE_ATTACHED]          = "attached",		\
    [FIB_PATH_TYPE_RECURSIVE]         = "recursive",	        \
    [FIB_PATH_TYPE_SPECIAL]           = "special",	        \
    [FIB_PATH_TYPE_EXCLUSIVE]         = "exclusive",	        \
    [FIB_PATH_TYPE_DEAG]              = "deag",	                \
    [FIB_PATH_TYPE_INTF_RX]           = "intf-rx",	        \
    [FIB_PATH_TYPE_UDP_ENCAP]         = "udp-encap",	        \
    [FIB_PATH_TYPE_RECEIVE]           = "receive",	        \
    [FIB_PATH_TYPE_BIER_IMP]          = "bier-imp",	        \
    [FIB_PATH_TYPE_BIER_TABLE]        = "bier-table",	        \
    [FIB_PATH_TYPE_BIER_FMASK]        = "bier-fmask",	        \
    [FIB_PATH_TYPE_DVR]               = "dvr",   	        \
}

/**
 * Enurmeration of path operational (i.e. derived) attributes
 */
typedef enum fib_path_oper_attribute_t_ {
    /**
     * Marker. Add new types after this one.
     */
    FIB_PATH_OPER_ATTRIBUTE_FIRST = 0,
    /**
     * The path forms part of a recursive loop.
     */
    FIB_PATH_OPER_ATTRIBUTE_RECURSIVE_LOOP = FIB_PATH_OPER_ATTRIBUTE_FIRST,
    /**
     * The path is resolved
     */
    FIB_PATH_OPER_ATTRIBUTE_RESOLVED,
    /**
     * The path is attached, despite what the next-hop may say.
     */
    FIB_PATH_OPER_ATTRIBUTE_ATTACHED,
    /**
     * The path has become a permanent drop.
     */
    FIB_PATH_OPER_ATTRIBUTE_DROP,
    /**
     * Marker. Add new types before this one, then update it.
     */
    FIB_PATH_OPER_ATTRIBUTE_LAST = FIB_PATH_OPER_ATTRIBUTE_DROP,
} __attribute__ ((packed)) fib_path_oper_attribute_t;

/**
 * The maximum number of path operational attributes
 */
#define FIB_PATH_OPER_ATTRIBUTE_MAX (FIB_PATH_OPER_ATTRIBUTE_LAST + 1)

#define FIB_PATH_OPER_ATTRIBUTES {					\
    [FIB_PATH_OPER_ATTRIBUTE_RECURSIVE_LOOP] = "recursive-loop",	\
    [FIB_PATH_OPER_ATTRIBUTE_RESOLVED]       = "resolved",	        \
    [FIB_PATH_OPER_ATTRIBUTE_DROP]           = "drop",		        \
}

#define FOR_EACH_FIB_PATH_OPER_ATTRIBUTE(_item) \
    for (_item = FIB_PATH_OPER_ATTRIBUTE_FIRST; \
	 _item <= FIB_PATH_OPER_ATTRIBUTE_LAST; \
	 _item++)

/**
 * Path flags from the attributes
 */
typedef enum fib_path_oper_flags_t_ {
    FIB_PATH_OPER_FLAG_NONE = 0,
    FIB_PATH_OPER_FLAG_RECURSIVE_LOOP = (1 << FIB_PATH_OPER_ATTRIBUTE_RECURSIVE_LOOP),
    FIB_PATH_OPER_FLAG_DROP = (1 << FIB_PATH_OPER_ATTRIBUTE_DROP),
    FIB_PATH_OPER_FLAG_RESOLVED = (1 << FIB_PATH_OPER_ATTRIBUTE_RESOLVED),
    FIB_PATH_OPER_FLAG_ATTACHED = (1 << FIB_PATH_OPER_ATTRIBUTE_ATTACHED),
} __attribute__ ((packed)) fib_path_oper_flags_t;

/**
 * A FIB path
 */
typedef struct fib_path_t_ {
    /**
     * A path is a node in the FIB graph.
     */
    fib_node_t fp_node;

    /**
     * The index of the path-list to which this path belongs
     */
    u32 fp_pl_index;

    /**
     * This marks the start of the memory area used to hash
     * the path
     */
    STRUCT_MARK(path_hash_start);

    /**
     * Configuration Flags
     */
    fib_path_cfg_flags_t fp_cfg_flags;

    /**
     * The type of the path. This is the selector for the union
     */
    fib_path_type_t fp_type;

    /**
     * The protocol of the next-hop, i.e. the address family of the
     * next-hop's address. We can't derive this from the address itself
     * since the address can be all zeros
     */
    dpo_proto_t fp_nh_proto;

    /**
     * UCMP [unnormalised] weigth
     */
    u8 fp_weight;

    /**
     * A path preference. 0 is the best.
     * Only paths of the best preference, that are 'up', are considered
     * for forwarding.
     */
    u8 fp_preference;

    /**
     * per-type union of the data required to resolve the path
     */
    union {
	struct {
	    /**
	     * The next-hop
	     */
	    ip46_address_t fp_nh;
	    /**
	     * The interface
	     */
	    u32 fp_interface;
	} attached_next_hop;
	struct {
	    /**
	     * The Connected local address
	     */
	    fib_prefix_t fp_connected;
	    /**
	     * The interface
	     */
	    u32 fp_interface;
	} attached;
	struct {
	    union
	    {
		/**
		 * The next-hop
		 */
		ip46_address_t fp_ip;
		struct {
                    /**
                     * The local label to resolve through.
                     */
                    mpls_label_t fp_local_label;
                    /**
                     * The EOS bit of the resolving label
                     */
                    mpls_eos_bit_t fp_eos;
                };
	    } fp_nh;
            union {
                /**
                 * The FIB table index in which to find the next-hop.
                 */
                fib_node_index_t fp_tbl_id;
                /**
                 * The BIER FIB the fmask is in
                 */
                index_t fp_bier_fib;
            };
	} recursive;
	struct {
            /**
             * BIER FMask ID
             */
            index_t fp_bier_fmask;
	} bier_fmask;
	struct {
            /**
             * The BIER table's ID
             */
            bier_table_id_t fp_bier_tbl;
	} bier_table;
	struct {
            /**
             * The BIER imposition object
             * this is part of the path's key, since the index_t
             * of an imposition object is the object's key.
             */
            index_t fp_bier_imp;
	} bier_imp;
	struct {
	    /**
	     * The FIB index in which to perfom the next lookup
	     */
	    fib_node_index_t fp_tbl_id;
            /**
             * The RPF-ID to tag the packets with
             */
            fib_rpf_id_t fp_rpf_id;
	} deag;
	struct {
	} special;
	struct {
	    /**
	     * The user provided 'exclusive' DPO
	     */
	    dpo_id_t fp_ex_dpo;
	} exclusive;
	struct {
	    /**
	     * The interface on which the local address is configured
	     */
	    u32 fp_interface;
	    /**
	     * The next-hop
	     */
	    ip46_address_t fp_addr;
	} receive;
	struct {
	    /**
	     * The interface on which the packets will be input.
	     */
	    u32 fp_interface;
	} intf_rx;
	struct {
	    /**
	     * The UDP Encap object this path resolves through
	     */
	    u32 fp_udp_encap_id;
	} udp_encap;
	struct {
	    /**
	     * The UDP Encap object this path resolves through
	     */
	    u32 fp_classify_table_id;
	} classify;
	struct {
	    /**
	     * The interface
	     */
	    u32 fp_interface;
	} dvr;
    };
    STRUCT_MARK(path_hash_end);

    /**
     * Memebers in this last section represent information that is
     * dervied during resolution. It should not be copied to new paths
     * nor compared.
     */

    /**
     * Operational Flags
     */
    fib_path_oper_flags_t fp_oper_flags;

    union {
        /**
         * the resolving via fib. not part of the union, since it it not part
         * of the path's hash.
         */
        fib_node_index_t fp_via_fib;
        /**
         * the resolving bier-table
         */
        index_t fp_via_bier_tbl;
        /**
         * the resolving bier-fmask
         */
        index_t fp_via_bier_fmask;
    };

    /**
     * The Data-path objects through which this path resolves for IP.
     */
    dpo_id_t fp_dpo;

    /**
     * the index of this path in the parent's child list.
     */
    u32 fp_sibling;
} fib_path_t;

/*
 * Array of strings/names for the path types and attributes
 */
static const char *fib_path_type_names[] = FIB_PATH_TYPES;
static const char *fib_path_oper_attribute_names[] = FIB_PATH_OPER_ATTRIBUTES;
static const char *fib_path_cfg_attribute_names[]  = FIB_PATH_CFG_ATTRIBUTES;

/*
 * The memory pool from which we allocate all the paths
 */
static fib_path_t *fib_path_pool;

/**
 * the logger
 */
vlib_log_class_t fib_path_logger;

/*
 * Debug macro
 */
#define FIB_PATH_DBG(_p, _fmt, _args...)                                \
{                                                                       \
    vlib_log_debug (fib_path_logger,                                    \
                    "[%U]: " _fmt,                                      \
                    format_fib_path, fib_path_get_index(_p), 0,         \
                    FIB_PATH_FORMAT_FLAGS_ONE_LINE,                     \
                    ##_args);                                           \
}

static fib_path_t *
fib_path_get (fib_node_index_t index)
{
    return (pool_elt_at_index(fib_path_pool, index));
}

static fib_node_index_t 
fib_path_get_index (fib_path_t *path)
{
    return (path - fib_path_pool);
}

static fib_node_t *
fib_path_get_node (fib_node_index_t index)
{
    return ((fib_node_t*)fib_path_get(index));
}

static fib_path_t*
fib_path_from_fib_node (fib_node_t *node)
{
    ASSERT(FIB_NODE_TYPE_PATH == node->fn_type);
    return ((fib_path_t*)node);
}

u8 *
format_fib_path (u8 * s, va_list * args)
{
    fib_node_index_t path_index = va_arg (*args, fib_node_index_t);
    u32 indent = va_arg (*args, u32);
    fib_format_path_flags_t flags =  va_arg (*args, fib_format_path_flags_t);
    vnet_main_t * vnm = vnet_get_main();
    fib_path_oper_attribute_t oattr;
    fib_path_cfg_attribute_t cattr;
    fib_path_t *path;
    const char *eol;

    if (flags & FIB_PATH_FORMAT_FLAGS_ONE_LINE)
    {
        eol = "";
    }
    else
    {
        eol = "\n";
    }

    path = fib_path_get(path_index);

    s = format (s, "%Upath:[%d] ", format_white_space, indent,
                fib_path_get_index(path));
    s = format (s, "pl-index:%d ", path->fp_pl_index);
    s = format (s, "%U ", format_dpo_proto, path->fp_nh_proto);
    s = format (s, "weight=%d ", path->fp_weight);
    s = format (s, "pref=%d ", path->fp_preference);
    s = format (s, "%s: ", fib_path_type_names[path->fp_type]);
    if (FIB_PATH_OPER_FLAG_NONE != path->fp_oper_flags) {
	s = format(s, " oper-flags:");
	FOR_EACH_FIB_PATH_OPER_ATTRIBUTE(oattr) {
	    if ((1<<oattr) & path->fp_oper_flags) {
		s = format (s, "%s,", fib_path_oper_attribute_names[oattr]);
	    }
	}
    }
    if (FIB_PATH_CFG_FLAG_NONE != path->fp_cfg_flags) {
	s = format(s, " cfg-flags:");
	FOR_EACH_FIB_PATH_CFG_ATTRIBUTE(cattr) {
	    if ((1<<cattr) & path->fp_cfg_flags) {
		s = format (s, "%s,", fib_path_cfg_attribute_names[cattr]);
	    }
	}
    }
    if (!(flags & FIB_PATH_FORMAT_FLAGS_ONE_LINE))
        s = format(s, "\n%U", format_white_space, indent+2);

    switch (path->fp_type)
    {
    case FIB_PATH_TYPE_ATTACHED_NEXT_HOP:
	s = format (s, "%U", format_ip46_address,
		    &path->attached_next_hop.fp_nh,
		    IP46_TYPE_ANY);
	if (path->fp_oper_flags & FIB_PATH_OPER_FLAG_DROP)
	{
	    s = format (s, " if_index:%d", path->attached_next_hop.fp_interface);
	}
	else
	{
	    s = format (s, " %U",
			format_vnet_sw_interface_name,
			vnm,
			vnet_get_sw_interface(
			    vnm,
			    path->attached_next_hop.fp_interface));
	    if (vnet_sw_interface_is_p2p(vnet_get_main(),
					 path->attached_next_hop.fp_interface))
	    {
		s = format (s, " (p2p)");
	    }
	}
	if (!dpo_id_is_valid(&path->fp_dpo))
	{
	    s = format(s, "%s%Uunresolved", eol, format_white_space, indent+2);
	}
	else
	{
	    s = format(s, "%s%U%U", eol,
		       format_white_space, indent,
                       format_dpo_id,
		       &path->fp_dpo, 13);
	}
	break;
    case FIB_PATH_TYPE_ATTACHED:
	if (path->fp_oper_flags & FIB_PATH_OPER_FLAG_DROP)
	{
	    s = format (s, "if_index:%d", path->attached_next_hop.fp_interface);
	}
	else
	{
	    s = format (s, " %U",
			format_vnet_sw_interface_name,
			vnm,
			vnet_get_sw_interface(
			    vnm,
			    path->attached.fp_interface));
	}
	break;
    case FIB_PATH_TYPE_RECURSIVE:
	if (DPO_PROTO_MPLS == path->fp_nh_proto)
	{
	    s = format (s, "via %U %U",
			format_mpls_unicast_label,
			path->recursive.fp_nh.fp_local_label,
			format_mpls_eos_bit,
			path->recursive.fp_nh.fp_eos);
	}
	else
	{
	    s = format (s, "via %U",
			format_ip46_address,
			&path->recursive.fp_nh.fp_ip,
			IP46_TYPE_ANY);
	}
	s = format (s, " in fib:%d",
		    path->recursive.fp_tbl_id,
		    path->fp_via_fib); 
	s = format (s, " via-fib:%d", path->fp_via_fib); 
	s = format (s, " via-dpo:[%U:%d]",
		    format_dpo_type, path->fp_dpo.dpoi_type, 
		    path->fp_dpo.dpoi_index);

	break;
    case FIB_PATH_TYPE_UDP_ENCAP:
        s = format (s, "UDP-encap ID:%d", path->udp_encap.fp_udp_encap_id);
        break;
    case FIB_PATH_TYPE_BIER_TABLE:
        s = format (s, "via bier-table:[%U}",
                    format_bier_table_id,
                    &path->bier_table.fp_bier_tbl);
        s = format (s, " via-dpo:[%U:%d]",
                    format_dpo_type, path->fp_dpo.dpoi_type,
                    path->fp_dpo.dpoi_index);
        break;
    case FIB_PATH_TYPE_BIER_FMASK:
	s = format (s, "via-fmask:%d", path->bier_fmask.fp_bier_fmask); 
	s = format (s, " via-dpo:[%U:%d]",
		    format_dpo_type, path->fp_dpo.dpoi_type, 
		    path->fp_dpo.dpoi_index);
	break;
    case FIB_PATH_TYPE_BIER_IMP:
        s = format (s, "via %U", format_bier_imp,
                    path->bier_imp.fp_bier_imp, 0, BIER_SHOW_BRIEF);
        break;
    case FIB_PATH_TYPE_DVR:
        s = format (s, " %U",
                    format_vnet_sw_interface_name,
                    vnm,
                    vnet_get_sw_interface(
                        vnm,
                        path->dvr.fp_interface));
        break;
    case FIB_PATH_TYPE_DEAG:
        s = format (s, " %sfib-index:%d",
                    (path->fp_cfg_flags & FIB_PATH_CFG_FLAG_RPF_ID ?  "m" : ""),
                    path->deag.fp_tbl_id);
        break;
    case FIB_PATH_TYPE_RECEIVE:
    case FIB_PATH_TYPE_INTF_RX:
    case FIB_PATH_TYPE_SPECIAL:
    case FIB_PATH_TYPE_EXCLUSIVE:
	if (dpo_id_is_valid(&path->fp_dpo))
	{
	    s = format(s, "%U", format_dpo_id,
		       &path->fp_dpo, indent+2);
	}
	break;
    }
    return (s);
}

/*
 * fib_path_last_lock_gone
 *
 * We don't share paths, we share path lists, so the [un]lock functions
 * are no-ops
 */
static void
fib_path_last_lock_gone (fib_node_t *node)
{
    ASSERT(0);
}

static fib_path_t*
fib_path_attached_next_hop_get_adj (fib_path_t *path,
				    vnet_link_t link,
                                    dpo_id_t *dpo)
{
    fib_node_index_t fib_path_index;
    fib_protocol_t nh_proto;
    adj_index_t ai;

    fib_path_index = fib_path_get_index(path);
    nh_proto = dpo_proto_to_fib(path->fp_nh_proto);

    if (vnet_sw_interface_is_p2p(vnet_get_main(),
				 path->attached_next_hop.fp_interface))
    {
	/*
	 * if the interface is p2p then the adj for the specific
	 * neighbour on that link will never exist. on p2p links
	 * the subnet address (the attached route) links to the
	 * auto-adj (see below), we want that adj here too.
	 */
	ai = adj_nbr_add_or_lock(nh_proto, link, &zero_addr,
                                 path->attached_next_hop.fp_interface);
    }
    else
    {
	ai = adj_nbr_add_or_lock(nh_proto, link,
                                 &path->attached_next_hop.fp_nh,
                                 path->attached_next_hop.fp_interface);
    }

    dpo_set(dpo, DPO_ADJACENCY, vnet_link_to_dpo_proto(link), ai);
    adj_unlock(ai);

    return (fib_path_get(fib_path_index));
}

static void
fib_path_attached_next_hop_set (fib_path_t *path)
{
    /*
     * resolve directly via the adjacency discribed by the
     * interface and next-hop
     */
    path = fib_path_attached_next_hop_get_adj(path,
                                              dpo_proto_to_link(path->fp_nh_proto),
                                              &path->fp_dpo);

    ASSERT(dpo_is_adj(&path->fp_dpo));

    /*
     * become a child of the adjacency so we receive updates
     * when its rewrite changes
     */
    path->fp_sibling = adj_child_add(path->fp_dpo.dpoi_index,
				     FIB_NODE_TYPE_PATH,
				     fib_path_get_index(path));

    if (!vnet_sw_interface_is_up(vnet_get_main(),
                                 path->attached_next_hop.fp_interface) ||
        !adj_is_up(path->fp_dpo.dpoi_index))
    {
	path->fp_oper_flags &= ~FIB_PATH_OPER_FLAG_RESOLVED;
    }
}

static void
fib_path_attached_get_adj (fib_path_t *path,
                           vnet_link_t link,
                           dpo_id_t *dpo)
{
    fib_protocol_t nh_proto;

    nh_proto = dpo_proto_to_fib(path->fp_nh_proto);

    if (vnet_sw_interface_is_p2p(vnet_get_main(),
                                 path->attached.fp_interface))
    {
        /*
         * point-2-point interfaces do not require a glean, since
         * there is nothing to ARP. Install a rewrite/nbr adj instead
         */
        adj_index_t ai;

        ai = adj_nbr_add_or_lock(nh_proto, link, &zero_addr,
                                 path->attached.fp_interface);

        dpo_set(dpo, DPO_ADJACENCY, vnet_link_to_dpo_proto(link), ai);
        adj_unlock(ai);
    }
    else if (vnet_sw_interface_is_nbma(vnet_get_main(),
                                       path->attached.fp_interface))
    {
        dpo_copy(dpo, drop_dpo_get(path->fp_nh_proto));
    }
    else
    {
        adj_index_t ai;

        ai = adj_glean_add_or_lock(nh_proto, link,
                                   path->attached.fp_interface,
                                   &path->attached.fp_connected);
        dpo_set(dpo, DPO_ADJACENCY_GLEAN, vnet_link_to_dpo_proto(link), ai);
        adj_unlock(ai);
    }
}

/*
 * create of update the paths recursive adj
 */
static void
fib_path_recursive_adj_update (fib_path_t *path,
			       fib_forward_chain_type_t fct,
			       dpo_id_t *dpo)
{
    dpo_id_t via_dpo = DPO_INVALID;

    /*
     * get the DPO to resolve through from the via-entry
     */
    fib_entry_contribute_forwarding(path->fp_via_fib,
				    fct,
				    &via_dpo);


    /*
     * hope for the best - clear if restrictions apply.
     */
    path->fp_oper_flags |= FIB_PATH_OPER_FLAG_RESOLVED;

    /*
     * Validate any recursion constraints and over-ride the via
     * adj if not met
     */
    if (path->fp_oper_flags & FIB_PATH_OPER_FLAG_RECURSIVE_LOOP)
    {
	path->fp_oper_flags &= ~FIB_PATH_OPER_FLAG_RESOLVED;
	dpo_copy(&via_dpo, drop_dpo_get(path->fp_nh_proto));
    }
    else if (path->fp_cfg_flags & FIB_PATH_CFG_FLAG_RESOLVE_HOST)
    {
	/*
	 * the via FIB must be a host route.
	 * note the via FIB just added will always be a host route
	 * since it is an RR source added host route. So what we need to
	 * check is whether the route has other sources. If it does then
	 * some other source has added it as a host route. If it doesn't
	 * then it was added only here and inherits forwarding from a cover.
	 * the cover is not a host route.
	 * The RR source is the lowest priority source, so we check if it
	 * is the best. if it is there are no other sources.
	 */
	if (fib_entry_get_best_source(path->fp_via_fib) >= FIB_SOURCE_RR)
	{
	    path->fp_oper_flags &= ~FIB_PATH_OPER_FLAG_RESOLVED;
            dpo_copy(&via_dpo, drop_dpo_get(path->fp_nh_proto));

            /*
             * PIC edge trigger. let the load-balance maps know
             */
            load_balance_map_path_state_change(fib_path_get_index(path));
	}
    }
    else if (path->fp_cfg_flags & FIB_PATH_CFG_FLAG_RESOLVE_ATTACHED)
    {
	/*
	 * RR source entries inherit the flags from the cover, so
	 * we can check the via directly
	 */
	if (!(FIB_ENTRY_FLAG_ATTACHED & fib_entry_get_flags(path->fp_via_fib)))
	{
	    path->fp_oper_flags &= ~FIB_PATH_OPER_FLAG_RESOLVED;
            dpo_copy(&via_dpo, drop_dpo_get(path->fp_nh_proto));

            /*
             * PIC edge trigger. let the load-balance maps know
             */
            load_balance_map_path_state_change(fib_path_get_index(path));
	}
    }
    /*
     * check for over-riding factors on the FIB entry itself
     */
    if (!fib_entry_is_resolved(path->fp_via_fib))
    {
        path->fp_oper_flags &= ~FIB_PATH_OPER_FLAG_RESOLVED;
        dpo_copy(&via_dpo, drop_dpo_get(path->fp_nh_proto));

        /*
         * PIC edge trigger. let the load-balance maps know
         */
        load_balance_map_path_state_change(fib_path_get_index(path));
    }

    /*
     * If this path is contributing a drop, then it's not resolved
     */
    if (dpo_is_drop(&via_dpo) || load_balance_is_drop(&via_dpo))
    {
        path->fp_oper_flags &= ~FIB_PATH_OPER_FLAG_RESOLVED;
    }

    /*
     * update the path's contributed DPO
     */
    dpo_copy(dpo, &via_dpo);

    FIB_PATH_DBG(path, "recursive update:");

    dpo_reset(&via_dpo);
}

/*
 * re-evaulate the forwarding state for a via fmask path
 */
static void
fib_path_bier_fmask_update (fib_path_t *path,
                            dpo_id_t *dpo)
{
    bier_fmask_contribute_forwarding(path->bier_fmask.fp_bier_fmask, dpo);

    /*
     * if we are stakcing on the drop, then the path is not resolved
     */
    if (dpo_is_drop(dpo))
    {
        path->fp_oper_flags &= ~FIB_PATH_OPER_FLAG_RESOLVED;
    }
    else
    {
        path->fp_oper_flags |= FIB_PATH_OPER_FLAG_RESOLVED;
    }
}

/*
 * fib_path_is_permanent_drop
 *
 * Return !0 if the path is configured to permanently drop,
 * despite other attributes.
 */
static int
fib_path_is_permanent_drop (fib_path_t *path)
{
    return ((path->fp_cfg_flags & FIB_PATH_CFG_FLAG_DROP) ||
	    (path->fp_oper_flags & FIB_PATH_OPER_FLAG_DROP));
}

/*
 * fib_path_unresolve
 *
 * Remove our dependency on the resolution target
 */
static void
fib_path_unresolve (fib_path_t *path)
{
    /*
     * the forced drop path does not need unresolving
     */
    if (fib_path_is_permanent_drop(path))
    {
	return;
    }

    switch (path->fp_type)
    {
    case FIB_PATH_TYPE_RECURSIVE:
	if (FIB_NODE_INDEX_INVALID != path->fp_via_fib)
	{
	    fib_entry_child_remove(path->fp_via_fib,
				   path->fp_sibling);
            fib_table_entry_special_remove(path->recursive.fp_tbl_id,
                                           fib_entry_get_prefix(path->fp_via_fib),
					   FIB_SOURCE_RR);
            fib_table_unlock(path->recursive.fp_tbl_id,
                             dpo_proto_to_fib(path->fp_nh_proto),
                             FIB_SOURCE_RR);
	    path->fp_via_fib = FIB_NODE_INDEX_INVALID;
	}
	break;
    case FIB_PATH_TYPE_BIER_FMASK:
        bier_fmask_child_remove(path->fp_via_bier_fmask,
                                path->fp_sibling);
	break;
    case FIB_PATH_TYPE_BIER_IMP:
        bier_imp_unlock(path->fp_dpo.dpoi_index);
	break;
    case FIB_PATH_TYPE_BIER_TABLE:
        bier_table_ecmp_unlock(path->fp_via_bier_tbl);
        break;
    case FIB_PATH_TYPE_ATTACHED_NEXT_HOP:
    case FIB_PATH_TYPE_ATTACHED:
	if (dpo_is_adj(&path->fp_dpo))
            adj_child_remove(path->fp_dpo.dpoi_index,
                             path->fp_sibling);
        break;
    case FIB_PATH_TYPE_UDP_ENCAP:
	udp_encap_unlock(path->fp_dpo.dpoi_index);
        break;
    case FIB_PATH_TYPE_EXCLUSIVE:
	dpo_reset(&path->exclusive.fp_ex_dpo);
        break;
    case FIB_PATH_TYPE_SPECIAL:
    case FIB_PATH_TYPE_RECEIVE:
    case FIB_PATH_TYPE_INTF_RX:
    case FIB_PATH_TYPE_DEAG:
    case FIB_PATH_TYPE_DVR:
        /*
         * these hold only the path's DPO, which is reset below.
         */
	break;
    }

    /*
     * release the adj we were holding and pick up the
     * drop just in case.
     */
    dpo_reset(&path->fp_dpo);
    path->fp_oper_flags &= ~FIB_PATH_OPER_FLAG_RESOLVED;

    return;
}

static fib_forward_chain_type_t
fib_path_to_chain_type (const fib_path_t *path)
{
    if (DPO_PROTO_MPLS == path->fp_nh_proto)
    {
        if (FIB_PATH_TYPE_RECURSIVE == path->fp_type &&
            MPLS_EOS == path->recursive.fp_nh.fp_eos)
        {
            return (FIB_FORW_CHAIN_TYPE_MPLS_EOS);
        }
        else
        {
            return (FIB_FORW_CHAIN_TYPE_MPLS_NON_EOS);
        }
    }
    else
    {
        return (fib_forw_chain_type_from_dpo_proto(path->fp_nh_proto));
    }
}

/*
 * fib_path_back_walk_notify
 *
 * A back walk has reach this path.
 */
static fib_node_back_walk_rc_t
fib_path_back_walk_notify (fib_node_t *node,
			   fib_node_back_walk_ctx_t *ctx)
{
    fib_path_t *path;

    path = fib_path_from_fib_node(node);

    FIB_PATH_DBG(path, "bw:%U",
                 format_fib_node_bw_reason, ctx->fnbw_reason);

    switch (path->fp_type)
    {
    case FIB_PATH_TYPE_RECURSIVE:
	if (FIB_NODE_BW_REASON_FLAG_EVALUATE & ctx->fnbw_reason)
	{
	    /*
	     * modify the recursive adjacency to use the new forwarding
	     * of the via-fib.
	     * this update is visible to packets in flight in the DP.
	     */
	    fib_path_recursive_adj_update(
		path,
		fib_path_to_chain_type(path),
		&path->fp_dpo);
	}
	if ((FIB_NODE_BW_REASON_FLAG_ADJ_UPDATE & ctx->fnbw_reason) ||
            (FIB_NODE_BW_REASON_FLAG_ADJ_DOWN   & ctx->fnbw_reason))
	{
	    /*
	     * ADJ updates (complete<->incomplete) do not need to propagate to
	     * recursive entries.
	     * The only reason its needed as far back as here, is that the adj
	     * and the incomplete adj are a different DPO type, so the LBs need
	     * to re-stack.
	     * If this walk was quashed in the fib_entry, then any non-fib_path
	     * children (like tunnels that collapse out the LB when they stack)
	     * would not see the update.
	     */
	    return (FIB_NODE_BACK_WALK_CONTINUE);
	}
	break;
    case FIB_PATH_TYPE_BIER_FMASK:
	if (FIB_NODE_BW_REASON_FLAG_EVALUATE & ctx->fnbw_reason)
	{
	    /*
	     * update to use the BIER fmask's new forwading
	     */
	    fib_path_bier_fmask_update(path, &path->fp_dpo);
	}
	if ((FIB_NODE_BW_REASON_FLAG_ADJ_UPDATE & ctx->fnbw_reason) ||
            (FIB_NODE_BW_REASON_FLAG_ADJ_DOWN   & ctx->fnbw_reason))
	{
	    /*
	     * ADJ updates (complete<->incomplete) do not need to propagate to
	     * recursive entries.
	     * The only reason its needed as far back as here, is that the adj
	     * and the incomplete adj are a different DPO type, so the LBs need
	     * to re-stack.
	     * If this walk was quashed in the fib_entry, then any non-fib_path
	     * children (like tunnels that collapse out the LB when they stack)
	     * would not see the update.
	     */
	    return (FIB_NODE_BACK_WALK_CONTINUE);
	}
	break;
    case FIB_PATH_TYPE_ATTACHED_NEXT_HOP:
	/*
FIXME comment
	 * ADJ_UPDATE backwalk pass silently through here and up to
	 * the path-list when the multipath adj collapse occurs.
	 * The reason we do this is that the assumtption is that VPP
	 * runs in an environment where the Control-Plane is remote
	 * and hence reacts slowly to link up down. In order to remove
	 * this down link from the ECMP set quickly, we back-walk.
	 * VPP also has dedicated CPUs, so we are not stealing resources
	 * from the CP to do so.
	 */
	if (FIB_NODE_BW_REASON_FLAG_INTERFACE_UP & ctx->fnbw_reason)
	{
            if (path->fp_oper_flags & FIB_PATH_OPER_FLAG_RESOLVED)
            {
                /*
                 * alreday resolved. no need to walk back again
                 */
                return (FIB_NODE_BACK_WALK_CONTINUE);
            }
	    path->fp_oper_flags |= FIB_PATH_OPER_FLAG_RESOLVED;
	}
	if (FIB_NODE_BW_REASON_FLAG_INTERFACE_DOWN & ctx->fnbw_reason)
	{
            if (!(path->fp_oper_flags & FIB_PATH_OPER_FLAG_RESOLVED))
            {
                /*
                 * alreday unresolved. no need to walk back again
                 */
                return (FIB_NODE_BACK_WALK_CONTINUE);
            }
	    path->fp_oper_flags &= ~FIB_PATH_OPER_FLAG_RESOLVED;
	}
	if (FIB_NODE_BW_REASON_FLAG_INTERFACE_DELETE & ctx->fnbw_reason)
	{
	    /*
	     * The interface this path resolves through has been deleted.
	     * This will leave the path in a permanent drop state. The route
	     * needs to be removed and readded (and hence the path-list deleted)
	     * before it can forward again.
	     */
	    fib_path_unresolve(path);
	    path->fp_oper_flags |= FIB_PATH_OPER_FLAG_DROP;
	}
        if (FIB_NODE_BW_REASON_FLAG_ADJ_UPDATE & ctx->fnbw_reason)
	{
            /*
             * restack the DPO to pick up the correct DPO sub-type
             */
            uword if_is_up;

            if_is_up = vnet_sw_interface_is_up(
                           vnet_get_main(),
                           path->attached_next_hop.fp_interface);

            path = fib_path_attached_next_hop_get_adj(
                path,
                dpo_proto_to_link(path->fp_nh_proto),
                &path->fp_dpo);

            path->fp_oper_flags &= ~FIB_PATH_OPER_FLAG_RESOLVED;
            if (if_is_up && adj_is_up(path->fp_dpo.dpoi_index))
            {
                path->fp_oper_flags |= FIB_PATH_OPER_FLAG_RESOLVED;
            }

            if (!if_is_up)
            {
                /*
                 * If the interface is not up there is no reason to walk
                 * back to children. if we did they would only evalute
                 * that this path is unresolved and hence it would
                 * not contribute the adjacency - so it would be wasted
                 * CPU time.
                 */
                return (FIB_NODE_BACK_WALK_CONTINUE);
            }
        }
        if (FIB_NODE_BW_REASON_FLAG_ADJ_DOWN & ctx->fnbw_reason)
	{
            if (!(path->fp_oper_flags & FIB_PATH_OPER_FLAG_RESOLVED))
            {
                /*
                 * alreday unresolved. no need to walk back again
                 */
                return (FIB_NODE_BACK_WALK_CONTINUE);
            }
            /*
             * the adj has gone down. the path is no longer resolved.
             */
	    path->fp_oper_flags &= ~FIB_PATH_OPER_FLAG_RESOLVED;
        }
	break;
    case FIB_PATH_TYPE_ATTACHED:
    case FIB_PATH_TYPE_DVR:
	/*
	 * FIXME; this could schedule a lower priority walk, since attached
	 * routes are not usually in ECMP configurations so the backwalk to
	 * the FIB entry does not need to be high priority
	 */
	if (FIB_NODE_BW_REASON_FLAG_INTERFACE_UP & ctx->fnbw_reason)
	{
	    path->fp_oper_flags |= FIB_PATH_OPER_FLAG_RESOLVED;
	}
	if (FIB_NODE_BW_REASON_FLAG_INTERFACE_DOWN & ctx->fnbw_reason)
	{
	    path->fp_oper_flags &= ~FIB_PATH_OPER_FLAG_RESOLVED;
	}
	if (FIB_NODE_BW_REASON_FLAG_INTERFACE_DELETE & ctx->fnbw_reason)
	{
	    fib_path_unresolve(path);
	    path->fp_oper_flags |= FIB_PATH_OPER_FLAG_DROP;
	}
	break;
    case FIB_PATH_TYPE_UDP_ENCAP:
    {
        dpo_id_t via_dpo = DPO_INVALID;

        /*
         * hope for the best - clear if restrictions apply.
         */
        path->fp_oper_flags |= FIB_PATH_OPER_FLAG_RESOLVED;

        udp_encap_contribute_forwarding(path->udp_encap.fp_udp_encap_id,
                                        path->fp_nh_proto,
                                        &via_dpo);
        /*
         * If this path is contributing a drop, then it's not resolved
         */
        if (dpo_is_drop(&via_dpo) || load_balance_is_drop(&via_dpo))
        {
            path->fp_oper_flags &= ~FIB_PATH_OPER_FLAG_RESOLVED;
        }

        /*
         * update the path's contributed DPO
         */
        dpo_copy(&path->fp_dpo, &via_dpo);
        dpo_reset(&via_dpo);
        break;
    }
    case FIB_PATH_TYPE_INTF_RX:
        ASSERT(0);
    case FIB_PATH_TYPE_DEAG:
	/*
	 * FIXME When VRF delete is allowed this will need a poke.
	 */
    case FIB_PATH_TYPE_SPECIAL:
    case FIB_PATH_TYPE_RECEIVE:
    case FIB_PATH_TYPE_EXCLUSIVE:
    case FIB_PATH_TYPE_BIER_TABLE:
    case FIB_PATH_TYPE_BIER_IMP:
	/*
	 * these path types have no parents. so to be
	 * walked from one is unexpected.
	 */
	ASSERT(0);
	break;
    }

    /*
     * propagate the backwalk further to the path-list
     */
    fib_path_list_back_walk(path->fp_pl_index, ctx);

    return (FIB_NODE_BACK_WALK_CONTINUE);
}

static void
fib_path_memory_show (void)
{
    fib_show_memory_usage("Path",
			  pool_elts(fib_path_pool),
			  pool_len(fib_path_pool),
			  sizeof(fib_path_t));
}

/*
 * The FIB path's graph node virtual function table
 */
static const fib_node_vft_t fib_path_vft = {
    .fnv_get = fib_path_get_node,
    .fnv_last_lock = fib_path_last_lock_gone,
    .fnv_back_walk = fib_path_back_walk_notify,
    .fnv_mem_show = fib_path_memory_show,
};

static fib_path_cfg_flags_t
fib_path_route_flags_to_cfg_flags (const fib_route_path_t *rpath)
{
    fib_path_cfg_flags_t cfg_flags = FIB_PATH_CFG_FLAG_NONE;

    if (rpath->frp_flags & FIB_ROUTE_PATH_POP_PW_CW)
	cfg_flags |= FIB_PATH_CFG_FLAG_POP_PW_CW;
    if (rpath->frp_flags & FIB_ROUTE_PATH_RESOLVE_VIA_HOST)
	cfg_flags |= FIB_PATH_CFG_FLAG_RESOLVE_HOST;
    if (rpath->frp_flags & FIB_ROUTE_PATH_RESOLVE_VIA_ATTACHED)
	cfg_flags |= FIB_PATH_CFG_FLAG_RESOLVE_ATTACHED;
    if (rpath->frp_flags & FIB_ROUTE_PATH_LOCAL)
	cfg_flags |= FIB_PATH_CFG_FLAG_LOCAL;
    if (rpath->frp_flags & FIB_ROUTE_PATH_ATTACHED)
	cfg_flags |= FIB_PATH_CFG_FLAG_ATTACHED;
    if (rpath->frp_flags & FIB_ROUTE_PATH_INTF_RX)
	cfg_flags |= FIB_PATH_CFG_FLAG_INTF_RX;
    if (rpath->frp_flags & FIB_ROUTE_PATH_RPF_ID)
	cfg_flags |= FIB_PATH_CFG_FLAG_RPF_ID;
    if (rpath->frp_flags & FIB_ROUTE_PATH_EXCLUSIVE)
	cfg_flags |= FIB_PATH_CFG_FLAG_EXCLUSIVE;
    if (rpath->frp_flags & FIB_ROUTE_PATH_DROP)
	cfg_flags |= FIB_PATH_CFG_FLAG_DROP;
    if (rpath->frp_flags & FIB_ROUTE_PATH_SOURCE_LOOKUP)
	cfg_flags |= FIB_PATH_CFG_FLAG_DEAG_SRC;
    if (rpath->frp_flags & FIB_ROUTE_PATH_ICMP_UNREACH)
	cfg_flags |= FIB_PATH_CFG_FLAG_ICMP_UNREACH;
    if (rpath->frp_flags & FIB_ROUTE_PATH_ICMP_PROHIBIT)
	cfg_flags |= FIB_PATH_CFG_FLAG_ICMP_PROHIBIT;
    if (rpath->frp_flags & FIB_ROUTE_PATH_GLEAN)
	cfg_flags |= FIB_PATH_CFG_FLAG_GLEAN;

    return (cfg_flags);
}

/*
 * fib_path_create
 *
 * Create and initialise a new path object.
 * return the index of the path.
 */
fib_node_index_t
fib_path_create (fib_node_index_t pl_index,
		 const fib_route_path_t *rpath)
{
    fib_path_t *path;

    pool_get(fib_path_pool, path);
    clib_memset(path, 0, sizeof(*path));

    fib_node_init(&path->fp_node,
		  FIB_NODE_TYPE_PATH);

    dpo_reset(&path->fp_dpo);
    path->fp_pl_index = pl_index;
    path->fp_nh_proto = rpath->frp_proto;
    path->fp_via_fib = FIB_NODE_INDEX_INVALID;
    path->fp_weight = rpath->frp_weight;
    if (0 == path->fp_weight)
    {
        /*
         * a weight of 0 is a meaningless value. We could either reject it, and thus force
         * clients to always use 1, or we can accept it and fixup approrpiately.
         */
        path->fp_weight = 1;
    }
    path->fp_preference = rpath->frp_preference;
    path->fp_cfg_flags = fib_path_route_flags_to_cfg_flags(rpath);

    /*
     * deduce the path's tpye from the parementers and save what is needed.
     */
    if (path->fp_cfg_flags & FIB_PATH_CFG_FLAG_LOCAL)
    {
        path->fp_type = FIB_PATH_TYPE_RECEIVE;
        path->receive.fp_interface = rpath->frp_sw_if_index;
        path->receive.fp_addr = rpath->frp_addr;
    }
    else if (rpath->frp_flags & FIB_ROUTE_PATH_UDP_ENCAP)
    {
        path->fp_type = FIB_PATH_TYPE_UDP_ENCAP;
        path->udp_encap.fp_udp_encap_id = rpath->frp_udp_encap_id;
    }
    else if (path->fp_cfg_flags & FIB_PATH_CFG_FLAG_INTF_RX)
    {
        path->fp_type = FIB_PATH_TYPE_INTF_RX;
        path->intf_rx.fp_interface = rpath->frp_sw_if_index;
    }
    else if (path->fp_cfg_flags & FIB_PATH_CFG_FLAG_RPF_ID)
    {
        path->fp_type = FIB_PATH_TYPE_DEAG;
        path->deag.fp_tbl_id = rpath->frp_fib_index;
        path->deag.fp_rpf_id = rpath->frp_rpf_id;
    }
    else if (rpath->frp_flags & FIB_ROUTE_PATH_BIER_FMASK)
    {
        path->fp_type = FIB_PATH_TYPE_BIER_FMASK;
        path->bier_fmask.fp_bier_fmask = rpath->frp_bier_fmask;
    }
    else if (rpath->frp_flags & FIB_ROUTE_PATH_BIER_IMP)
    {
        path->fp_type = FIB_PATH_TYPE_BIER_IMP;
        path->bier_imp.fp_bier_imp = rpath->frp_bier_imp;
    }
    else if (rpath->frp_flags & FIB_ROUTE_PATH_BIER_TABLE)
    {
        path->fp_type = FIB_PATH_TYPE_BIER_TABLE;
        path->bier_table.fp_bier_tbl = rpath->frp_bier_tbl;
    }
    else if (rpath->frp_flags & FIB_ROUTE_PATH_DEAG)
    {
	path->fp_type = FIB_PATH_TYPE_DEAG;
	path->deag.fp_tbl_id = rpath->frp_fib_index;
    }
    else if (rpath->frp_flags & FIB_ROUTE_PATH_DVR)
    {
	path->fp_type = FIB_PATH_TYPE_DVR;
	path->dvr.fp_interface = rpath->frp_sw_if_index;
    }
    else if (rpath->frp_flags & FIB_ROUTE_PATH_EXCLUSIVE)
    {
	path->fp_type = FIB_PATH_TYPE_EXCLUSIVE;
	dpo_copy(&path->exclusive.fp_ex_dpo, &rpath->dpo);
    }
    else if ((path->fp_cfg_flags & FIB_PATH_CFG_FLAG_ICMP_PROHIBIT) ||
        (path->fp_cfg_flags & FIB_PATH_CFG_FLAG_ICMP_UNREACH))
    {
        path->fp_type = FIB_PATH_TYPE_SPECIAL;
    }
    else if ((path->fp_cfg_flags & FIB_PATH_CFG_FLAG_CLASSIFY))
    {
        path->fp_type = FIB_PATH_TYPE_SPECIAL;
        path->classify.fp_classify_table_id = rpath->frp_classify_table_id;
    }
    else if (path->fp_cfg_flags & FIB_PATH_CFG_FLAG_GLEAN)
    {
        path->fp_type = FIB_PATH_TYPE_ATTACHED;
        path->attached.fp_interface = rpath->frp_sw_if_index;
        path->attached.fp_connected = rpath->frp_connected;
    }
    else if (~0 != rpath->frp_sw_if_index)
    {
        if (ip46_address_is_zero(&rpath->frp_addr))
        {
            path->fp_type = FIB_PATH_TYPE_ATTACHED;
            path->attached.fp_interface = rpath->frp_sw_if_index;
        }
        else
        {
            path->fp_type = FIB_PATH_TYPE_ATTACHED_NEXT_HOP;
            path->attached_next_hop.fp_interface = rpath->frp_sw_if_index;
            path->attached_next_hop.fp_nh = rpath->frp_addr;
        }
    }
    else
    {
	if (ip46_address_is_zero(&rpath->frp_addr))
	{
	    if (~0 == rpath->frp_fib_index)
	    {
		path->fp_type = FIB_PATH_TYPE_SPECIAL;
	    }
	    else
	    {
		path->fp_type = FIB_PATH_TYPE_DEAG;
		path->deag.fp_tbl_id = rpath->frp_fib_index;
                path->deag.fp_rpf_id = ~0;
	    }
	}
	else
	{
	    path->fp_type = FIB_PATH_TYPE_RECURSIVE;
	    if (DPO_PROTO_MPLS == path->fp_nh_proto)
	    {
		path->recursive.fp_nh.fp_local_label = rpath->frp_local_label;
                path->recursive.fp_nh.fp_eos = rpath->frp_eos;
	    }
	    else
	    {
		path->recursive.fp_nh.fp_ip = rpath->frp_addr;
	    }
            path->recursive.fp_tbl_id = rpath->frp_fib_index;
	}
    }

    FIB_PATH_DBG(path, "create");

    return (fib_path_get_index(path));
}

/*
 * fib_path_create_special
 *
 * Create and initialise a new path object.
 * return the index of the path.
 */
fib_node_index_t
fib_path_create_special (fib_node_index_t pl_index,
			 dpo_proto_t nh_proto,
			 fib_path_cfg_flags_t flags,
			 const dpo_id_t *dpo)
{
    fib_path_t *path;

    pool_get(fib_path_pool, path);
    clib_memset(path, 0, sizeof(*path));

    fib_node_init(&path->fp_node,
		  FIB_NODE_TYPE_PATH);
    dpo_reset(&path->fp_dpo);

    path->fp_pl_index = pl_index;
    path->fp_weight = 1;
    path->fp_preference = 0;
    path->fp_nh_proto = nh_proto;
    path->fp_via_fib = FIB_NODE_INDEX_INVALID;
    path->fp_cfg_flags = flags;

    if (FIB_PATH_CFG_FLAG_DROP & flags)
    {
	path->fp_type = FIB_PATH_TYPE_SPECIAL;
    }
    else if (FIB_PATH_CFG_FLAG_LOCAL & flags)
    {
	path->fp_type = FIB_PATH_TYPE_RECEIVE;
	path->attached.fp_interface = FIB_NODE_INDEX_INVALID;
    }
    else
    {
	path->fp_type = FIB_PATH_TYPE_EXCLUSIVE;
	ASSERT(NULL != dpo);
	dpo_copy(&path->exclusive.fp_ex_dpo, dpo);
    }

    return (fib_path_get_index(path));
}

/*
 * fib_path_copy
 *
 * Copy a path. return index of new path.
 */
fib_node_index_t
fib_path_copy (fib_node_index_t path_index,
	       fib_node_index_t path_list_index)
{
    fib_path_t *path, *orig_path;

    pool_get(fib_path_pool, path);

    orig_path = fib_path_get(path_index);
    ASSERT(NULL != orig_path);

    clib_memcpy(path, orig_path, sizeof(*path));

    FIB_PATH_DBG(path, "create-copy:%d", path_index);

    /*
     * reset the dynamic section
     */
    fib_node_init(&path->fp_node, FIB_NODE_TYPE_PATH);
    path->fp_oper_flags     = FIB_PATH_OPER_FLAG_NONE;
    path->fp_pl_index  = path_list_index;
    path->fp_via_fib   = FIB_NODE_INDEX_INVALID;
    clib_memset(&path->fp_dpo, 0, sizeof(path->fp_dpo));
    dpo_reset(&path->fp_dpo);

    return (fib_path_get_index(path));
}

/*
 * fib_path_destroy
 *
 * destroy a path that is no longer required
 */
void
fib_path_destroy (fib_node_index_t path_index)
{
    fib_path_t *path;

    path = fib_path_get(path_index);

    ASSERT(NULL != path);
    FIB_PATH_DBG(path, "destroy");

    fib_path_unresolve(path);

    fib_node_deinit(&path->fp_node);
    pool_put(fib_path_pool, path);
}

/*
 * fib_path_destroy
 *
 * destroy a path that is no longer required
 */
uword
fib_path_hash (fib_node_index_t path_index)
{
    fib_path_t *path;

    path = fib_path_get(path_index);

    return (hash_memory(STRUCT_MARK_PTR(path, path_hash_start),
			(STRUCT_OFFSET_OF(fib_path_t, path_hash_end) -
			 STRUCT_OFFSET_OF(fib_path_t, path_hash_start)),
			0));
}

/*
 * fib_path_cmp_i
 *
 * Compare two paths for equivalence.
 */
static int
fib_path_cmp_i (const fib_path_t *path1,
		const fib_path_t *path2)
{
    int res;

    res = 1;

    /*
     * paths of different types and protocol are not equal.
     * different weights and/or preference only are the same path.
     */
    if (path1->fp_type != path2->fp_type)
    {
	res = (path1->fp_type - path2->fp_type);
    }
    else if (path1->fp_nh_proto != path2->fp_nh_proto)
    {
	res = (path1->fp_nh_proto - path2->fp_nh_proto);
    }
    else
    {
	/*
	 * both paths are of the same type.
	 * consider each type and its attributes in turn.
	 */
	switch (path1->fp_type)
	{
	case FIB_PATH_TYPE_ATTACHED_NEXT_HOP:
	    res = ip46_address_cmp(&path1->attached_next_hop.fp_nh,
				   &path2->attached_next_hop.fp_nh);
	    if (0 == res) {
		res = (path1->attached_next_hop.fp_interface -
                       path2->attached_next_hop.fp_interface);
	    }
	    break;
	case FIB_PATH_TYPE_ATTACHED:
	    res = (path1->attached.fp_interface -
                   path2->attached.fp_interface);
	    break;
	case FIB_PATH_TYPE_RECURSIVE:
	    res = ip46_address_cmp(&path1->recursive.fp_nh.fp_ip,
				   &path2->recursive.fp_nh.fp_ip);
 
	    if (0 == res)
	    {
		res = (path1->recursive.fp_tbl_id - path2->recursive.fp_tbl_id);
	    }
	    break;
	case FIB_PATH_TYPE_BIER_FMASK:
            res = (path1->bier_fmask.fp_bier_fmask -
                   path2->bier_fmask.fp_bier_fmask);
	    break;
	case FIB_PATH_TYPE_BIER_IMP:
            res = (path1->bier_imp.fp_bier_imp -
                   path2->bier_imp.fp_bier_imp);
	    break;
        case FIB_PATH_TYPE_BIER_TABLE:
            res = bier_table_id_cmp(&path1->bier_table.fp_bier_tbl,
                                    &path2->bier_table.fp_bier_tbl);
            break;
	case FIB_PATH_TYPE_DEAG:
	    res = (path1->deag.fp_tbl_id - path2->deag.fp_tbl_id);
	    if (0 == res)
	    {
                res = (path1->deag.fp_rpf_id - path2->deag.fp_rpf_id);
            }
	    break;
	case FIB_PATH_TYPE_INTF_RX:
	    res = (path1->intf_rx.fp_interface - path2->intf_rx.fp_interface);
	    break;
	case FIB_PATH_TYPE_UDP_ENCAP:
	    res = (path1->udp_encap.fp_udp_encap_id - path2->udp_encap.fp_udp_encap_id);
	    break;
	case FIB_PATH_TYPE_DVR:
	    res = (path1->dvr.fp_interface - path2->dvr.fp_interface);
	    break;
	case FIB_PATH_TYPE_EXCLUSIVE:
	    res = dpo_cmp(&path1->exclusive.fp_ex_dpo, &path2->exclusive.fp_ex_dpo);
	    break;
	case FIB_PATH_TYPE_SPECIAL:
	case FIB_PATH_TYPE_RECEIVE:
	    res = 0;
	    break;
	}
    }
    return (res);
}

/*
 * fib_path_cmp_for_sort
 *
 * Compare two paths for equivalence. Used during path sorting.
 * As usual 0 means equal.
 */
int
fib_path_cmp_for_sort (void * v1,
		       void * v2)
{
    fib_node_index_t *pi1 = v1, *pi2 = v2;
    fib_path_t *path1, *path2;

    path1 = fib_path_get(*pi1);
    path2 = fib_path_get(*pi2);

    /*
     * when sorting paths we want the highest preference paths
     * first, so that the choices set built is in prefernce order
     */
    if (path1->fp_preference != path2->fp_preference)
    {
	return (path1->fp_preference - path2->fp_preference);
    }

    return (fib_path_cmp_i(path1, path2));
}

/*
 * fib_path_cmp
 *
 * Compare two paths for equivalence.
 */
int
fib_path_cmp (fib_node_index_t pi1,
	      fib_node_index_t pi2)
{
    fib_path_t *path1, *path2;

    path1 = fib_path_get(pi1);
    path2 = fib_path_get(pi2);

    return (fib_path_cmp_i(path1, path2));
}

int
fib_path_cmp_w_route_path (fib_node_index_t path_index,
			   const fib_route_path_t *rpath)
{
    fib_path_t *path;
    int res;

    path = fib_path_get(path_index);

    res = 1;

    if (path->fp_weight != rpath->frp_weight)
    {
	res = (path->fp_weight - rpath->frp_weight);
    }
    else
    {
	/*
	 * both paths are of the same type.
	 * consider each type and its attributes in turn.
	 */
	switch (path->fp_type)
	{
	case FIB_PATH_TYPE_ATTACHED_NEXT_HOP:
	    res = ip46_address_cmp(&path->attached_next_hop.fp_nh,
				   &rpath->frp_addr);
	    if (0 == res)
	    {
		res = (path->attached_next_hop.fp_interface -
                       rpath->frp_sw_if_index);
	    }
	    break;
	case FIB_PATH_TYPE_ATTACHED:
	    res = (path->attached.fp_interface - rpath->frp_sw_if_index);
	    break;
	case FIB_PATH_TYPE_RECURSIVE:
            if (DPO_PROTO_MPLS == path->fp_nh_proto)
            {
                res = path->recursive.fp_nh.fp_local_label - rpath->frp_local_label;

                if (res == 0)
                {
                    res = path->recursive.fp_nh.fp_eos - rpath->frp_eos;
                }
            }
            else
            {
                res = ip46_address_cmp(&path->recursive.fp_nh.fp_ip,
                                       &rpath->frp_addr);
            }

            if (0 == res)
            {
                res = (path->recursive.fp_tbl_id - rpath->frp_fib_index);
            }
	    break;
	case FIB_PATH_TYPE_BIER_FMASK:
            res = (path->bier_fmask.fp_bier_fmask - rpath->frp_bier_fmask);
	    break;
	case FIB_PATH_TYPE_BIER_IMP:
            res = (path->bier_imp.fp_bier_imp - rpath->frp_bier_imp);
	    break;
        case FIB_PATH_TYPE_BIER_TABLE:
            res = bier_table_id_cmp(&path->bier_table.fp_bier_tbl,
                                    &rpath->frp_bier_tbl);
            break;
	case FIB_PATH_TYPE_INTF_RX:
	    res = (path->intf_rx.fp_interface - rpath->frp_sw_if_index);
            break;
	case FIB_PATH_TYPE_UDP_ENCAP:
	    res = (path->udp_encap.fp_udp_encap_id - rpath->frp_udp_encap_id);
            break;
	case FIB_PATH_TYPE_DEAG:
	    res = (path->deag.fp_tbl_id - rpath->frp_fib_index);
	    if (0 == res)
            {
                res = (path->deag.fp_rpf_id - rpath->frp_rpf_id);
            }
            break;
	case FIB_PATH_TYPE_DVR:
	    res = (path->dvr.fp_interface - rpath->frp_sw_if_index);
	    break;
	case FIB_PATH_TYPE_EXCLUSIVE:
	    res = dpo_cmp(&path->exclusive.fp_ex_dpo, &rpath->dpo);
	    break;
	case FIB_PATH_TYPE_RECEIVE:
            if (rpath->frp_flags & FIB_ROUTE_PATH_LOCAL)
            {
                res = 0;
            }
            else
            {
                res = 1;
            }
            break;
	case FIB_PATH_TYPE_SPECIAL:
	    res = 0;
	    break;
	}
    }
    return (res);
}

/*
 * fib_path_recursive_loop_detect
 *
 * A forward walk of the FIB object graph to detect for a cycle/loop. This
 * walk is initiated when an entry is linking to a new path list or from an old.
 * The entry vector passed contains all the FIB entrys that are children of this
 * path (it is all the entries encountered on the walk so far). If this vector
 * contains the entry this path resolve via, then a loop is about to form.
 * The loop must be allowed to form, since we need the dependencies in place
 * so that we can track when the loop breaks.
 * However, we MUST not produce a loop in the forwarding graph (else packets
 * would loop around the switch path until the loop breaks), so we mark recursive
 * paths as looped so that they do not contribute forwarding information.
 * By marking the path as looped, an etry such as;
 *    X/Y
 *     via a.a.a.a (looped)
 *     via b.b.b.b (not looped)
 * can still forward using the info provided by b.b.b.b only
 */
int
fib_path_recursive_loop_detect (fib_node_index_t path_index,
				fib_node_index_t **entry_indicies)
{
    fib_path_t *path;

    path = fib_path_get(path_index);

    /*
     * the forced drop path is never looped, cos it is never resolved.
     */
    if (fib_path_is_permanent_drop(path))
    {
	return (0);
    }

    switch (path->fp_type)
    {
    case FIB_PATH_TYPE_RECURSIVE:
    {
	fib_node_index_t *entry_index, *entries;
	int looped = 0;
	entries = *entry_indicies;

	vec_foreach(entry_index, entries) {
	    if (*entry_index == path->fp_via_fib)
	    {
		/*
		 * the entry that is about to link to this path-list (or
		 * one of this path-list's children) is the same entry that
		 * this recursive path resolves through. this is a cycle.
		 * abort the walk.
		 */
		looped = 1;
		break;
	    }
	}

	if (looped)
	{
	    FIB_PATH_DBG(path, "recursive loop formed");
	    path->fp_oper_flags |= FIB_PATH_OPER_FLAG_RECURSIVE_LOOP;

	    dpo_copy(&path->fp_dpo, drop_dpo_get(path->fp_nh_proto));
	}
	else
	{
	    /*
	     * no loop here yet. keep forward walking the graph.
	     */
	    if (fib_entry_recursive_loop_detect(path->fp_via_fib, entry_indicies))
	    {
		FIB_PATH_DBG(path, "recursive loop formed");
		path->fp_oper_flags |= FIB_PATH_OPER_FLAG_RECURSIVE_LOOP;
	    }
	    else
	    {
		FIB_PATH_DBG(path, "recursive loop cleared");
		path->fp_oper_flags &= ~FIB_PATH_OPER_FLAG_RECURSIVE_LOOP;
	    }
	}
	break;
    }
    case FIB_PATH_TYPE_ATTACHED_NEXT_HOP:
    case FIB_PATH_TYPE_ATTACHED:
	if (dpo_is_adj(&path->fp_dpo) &&
            adj_recursive_loop_detect(path->fp_dpo.dpoi_index,
                                      entry_indicies))
	{
	    FIB_PATH_DBG(path, "recursive loop formed");
	    path->fp_oper_flags |= FIB_PATH_OPER_FLAG_RECURSIVE_LOOP;
	}
        else
        {
            FIB_PATH_DBG(path, "recursive loop cleared");
            path->fp_oper_flags &= ~FIB_PATH_OPER_FLAG_RECURSIVE_LOOP;
        }
        break;
    case FIB_PATH_TYPE_SPECIAL:
    case FIB_PATH_TYPE_DEAG:
    case FIB_PATH_TYPE_DVR:
    case FIB_PATH_TYPE_RECEIVE:
    case FIB_PATH_TYPE_INTF_RX:
    case FIB_PATH_TYPE_UDP_ENCAP:
    case FIB_PATH_TYPE_EXCLUSIVE:
    case FIB_PATH_TYPE_BIER_FMASK:
    case FIB_PATH_TYPE_BIER_TABLE:
    case FIB_PATH_TYPE_BIER_IMP:
	/*
	 * these path types cannot be part of a loop, since they are the leaves
	 * of the graph.
	 */
	break;
    }

    return (fib_path_is_looped(path_index));
}

int
fib_path_resolve (fib_node_index_t path_index)
{
    fib_path_t *path;

    path = fib_path_get(path_index);

    /*
     * hope for the best.
     */
    path->fp_oper_flags |= FIB_PATH_OPER_FLAG_RESOLVED;

    /*
     * the forced drop path resolves via the drop adj
     */
    if (fib_path_is_permanent_drop(path))
    {
	dpo_copy(&path->fp_dpo, drop_dpo_get(path->fp_nh_proto));
	path->fp_oper_flags &= ~FIB_PATH_OPER_FLAG_RESOLVED;
	return (fib_path_is_resolved(path_index));
    }

    switch (path->fp_type)
    {
    case FIB_PATH_TYPE_ATTACHED_NEXT_HOP:
	fib_path_attached_next_hop_set(path);
	break;
    case FIB_PATH_TYPE_ATTACHED:
    {
        dpo_id_t tmp = DPO_INVALID;

        /*
         * path->attached.fp_interface
         */
        if (!vnet_sw_interface_is_up(vnet_get_main(),
                                     path->attached.fp_interface))
        {
            path->fp_oper_flags &= ~FIB_PATH_OPER_FLAG_RESOLVED;
        }
        fib_path_attached_get_adj(path,
                                  dpo_proto_to_link(path->fp_nh_proto),
                                  &tmp);

        /*
         * re-fetch after possible mem realloc
         */
        path = fib_path_get(path_index);
        dpo_copy(&path->fp_dpo, &tmp);

        /*
         * become a child of the adjacency so we receive updates
         * when the interface state changes
         */
        if (dpo_is_adj(&path->fp_dpo))
        {
            path->fp_sibling = adj_child_add(path->fp_dpo.dpoi_index,
                                             FIB_NODE_TYPE_PATH,
                                             fib_path_get_index(path));
        }
        dpo_reset(&tmp);
	break;
    }
    case FIB_PATH_TYPE_RECURSIVE:
    {
	/*
	 * Create a RR source entry in the table for the address
	 * that this path recurses through.
	 * This resolve action is recursive, hence we may create
	 * more paths in the process. more creates mean maybe realloc
	 * of this path.
	 */
	fib_node_index_t fei;
	fib_prefix_t pfx;

	ASSERT(FIB_NODE_INDEX_INVALID == path->fp_via_fib);

	if (DPO_PROTO_MPLS == path->fp_nh_proto)
	{
	    fib_prefix_from_mpls_label(path->recursive.fp_nh.fp_local_label,
                                       path->recursive.fp_nh.fp_eos,
                                       &pfx);
	}
	else
	{
	    fib_prefix_from_ip46_addr(&path->recursive.fp_nh.fp_ip, &pfx);
	}

        fib_table_lock(path->recursive.fp_tbl_id,
                       dpo_proto_to_fib(path->fp_nh_proto),
                       FIB_SOURCE_RR);
	fei = fib_table_entry_special_add(path->recursive.fp_tbl_id,
					  &pfx,
					  FIB_SOURCE_RR,
					  FIB_ENTRY_FLAG_NONE);

	path = fib_path_get(path_index);
	path->fp_via_fib = fei;

	/*
	 * become a dependent child of the entry so the path is 
	 * informed when the forwarding for the entry changes.
	 */
	path->fp_sibling = fib_entry_child_add(path->fp_via_fib,
					       FIB_NODE_TYPE_PATH,
					       fib_path_get_index(path));

	/*
	 * create and configure the IP DPO
	 */
	fib_path_recursive_adj_update(
	    path,
	    fib_path_to_chain_type(path),
	    &path->fp_dpo);

	break;
    }
    case FIB_PATH_TYPE_BIER_FMASK:
    {
        /*
         * become a dependent child of the entry so the path is
         * informed when the forwarding for the entry changes.
         */
        path->fp_sibling = bier_fmask_child_add(path->bier_fmask.fp_bier_fmask,
                                                FIB_NODE_TYPE_PATH,
                                                fib_path_get_index(path));

        path->fp_via_bier_fmask = path->bier_fmask.fp_bier_fmask;
        fib_path_bier_fmask_update(path, &path->fp_dpo);

        break;
    }
    case FIB_PATH_TYPE_BIER_IMP:
        bier_imp_lock(path->bier_imp.fp_bier_imp);
        bier_imp_contribute_forwarding(path->bier_imp.fp_bier_imp,
                                       DPO_PROTO_IP4,
                                       &path->fp_dpo);
        break;
    case FIB_PATH_TYPE_BIER_TABLE:
    {
        /*
         * Find/create the BIER table to link to
         */
        ASSERT(FIB_NODE_INDEX_INVALID == path->fp_via_bier_tbl);

        path->fp_via_bier_tbl =
            bier_table_ecmp_create_and_lock(&path->bier_table.fp_bier_tbl);

        bier_table_contribute_forwarding(path->fp_via_bier_tbl,
                                         &path->fp_dpo);
        break;
    }
    case FIB_PATH_TYPE_SPECIAL:
        if (path->fp_cfg_flags & FIB_PATH_CFG_FLAG_ICMP_PROHIBIT)
        {
            ip_null_dpo_add_and_lock (path->fp_nh_proto,
                                      IP_NULL_ACTION_SEND_ICMP_PROHIBIT,
                                      &path->fp_dpo);
        }
        else if (path->fp_cfg_flags & FIB_PATH_CFG_FLAG_ICMP_UNREACH)
        {
            ip_null_dpo_add_and_lock (path->fp_nh_proto,
                                      IP_NULL_ACTION_SEND_ICMP_UNREACH,
                                      &path->fp_dpo);
        }
        else if (path->fp_cfg_flags & FIB_PATH_CFG_FLAG_CLASSIFY)
        {
            dpo_set (&path->fp_dpo, DPO_CLASSIFY,
                     path->fp_nh_proto,
                     classify_dpo_create (path->fp_nh_proto,
                                          path->classify.fp_classify_table_id));
        }
        else
        {
            /*
             * Resolve via the drop
             */
            dpo_copy(&path->fp_dpo, drop_dpo_get(path->fp_nh_proto));
        }
        break;
    case FIB_PATH_TYPE_DEAG:
    {
        if (DPO_PROTO_BIER == path->fp_nh_proto)
        {
            bier_disp_table_contribute_forwarding(path->deag.fp_tbl_id,
                                                  &path->fp_dpo);
        }
        else
        {
            /*
             * Resolve via a lookup DPO.
             * FIXME. control plane should add routes with a table ID
             */
            lookup_input_t input;
            lookup_cast_t cast;

            cast = (path->fp_cfg_flags & FIB_PATH_CFG_FLAG_RPF_ID ?
                    LOOKUP_MULTICAST :
                    LOOKUP_UNICAST);
            input = (path->fp_cfg_flags & FIB_PATH_CFG_FLAG_DEAG_SRC ?
                     LOOKUP_INPUT_SRC_ADDR :
                     LOOKUP_INPUT_DST_ADDR);

            lookup_dpo_add_or_lock_w_fib_index(path->deag.fp_tbl_id,
                                               path->fp_nh_proto,
                                               cast,
                                               input,
                                               LOOKUP_TABLE_FROM_CONFIG,
                                               &path->fp_dpo);
        }
        break;
    }
    case FIB_PATH_TYPE_DVR:
        dvr_dpo_add_or_lock(path->dvr.fp_interface,
                            path->fp_nh_proto,
                            &path->fp_dpo);
        break;
    case FIB_PATH_TYPE_RECEIVE:
	/*
	 * Resolve via a receive DPO.
	 */
	receive_dpo_add_or_lock(path->fp_nh_proto,
                                path->receive.fp_interface,
                                &path->receive.fp_addr,
                                &path->fp_dpo);
	break;
    case FIB_PATH_TYPE_UDP_ENCAP:
        udp_encap_lock(path->udp_encap.fp_udp_encap_id);
        udp_encap_contribute_forwarding(path->udp_encap.fp_udp_encap_id,
                                        path->fp_nh_proto,
                                        &path->fp_dpo);
        break;
    case FIB_PATH_TYPE_INTF_RX: {
	/*
	 * Resolve via a receive DPO.
	 */
	interface_rx_dpo_add_or_lock(path->fp_nh_proto,
                                     path->intf_rx.fp_interface,
                                     &path->fp_dpo);
	break;
    }
    case FIB_PATH_TYPE_EXCLUSIVE:
	/*
	 * Resolve via the user provided DPO
	 */
	dpo_copy(&path->fp_dpo, &path->exclusive.fp_ex_dpo);
	break;
    }

    return (fib_path_is_resolved(path_index));
}

u32
fib_path_get_resolving_interface (fib_node_index_t path_index)
{
    fib_path_t *path;

    path = fib_path_get(path_index);

    switch (path->fp_type)
    {
    case FIB_PATH_TYPE_ATTACHED_NEXT_HOP:
	return (path->attached_next_hop.fp_interface);
    case FIB_PATH_TYPE_ATTACHED:
	return (path->attached.fp_interface);
    case FIB_PATH_TYPE_RECEIVE:
	return (path->receive.fp_interface);
    case FIB_PATH_TYPE_RECURSIVE:
        if (fib_path_is_resolved(path_index))
        {
            return (fib_entry_get_resolving_interface(path->fp_via_fib));
        }
        break;
    case FIB_PATH_TYPE_DVR:
	return (path->dvr.fp_interface);
    case FIB_PATH_TYPE_INTF_RX:
    case FIB_PATH_TYPE_UDP_ENCAP:
    case FIB_PATH_TYPE_SPECIAL:
    case FIB_PATH_TYPE_DEAG:
    case FIB_PATH_TYPE_EXCLUSIVE:
    case FIB_PATH_TYPE_BIER_FMASK:
    case FIB_PATH_TYPE_BIER_TABLE:
    case FIB_PATH_TYPE_BIER_IMP:
	break;
    }
    return (dpo_get_urpf(&path->fp_dpo));
}

index_t
fib_path_get_resolving_index (fib_node_index_t path_index)
{
    fib_path_t *path;

    path = fib_path_get(path_index);

    switch (path->fp_type)
    {
    case FIB_PATH_TYPE_ATTACHED_NEXT_HOP:
    case FIB_PATH_TYPE_ATTACHED:
    case FIB_PATH_TYPE_RECEIVE:
    case FIB_PATH_TYPE_INTF_RX:
    case FIB_PATH_TYPE_SPECIAL:
    case FIB_PATH_TYPE_DEAG:
    case FIB_PATH_TYPE_DVR:
    case FIB_PATH_TYPE_EXCLUSIVE:
        break;
    case FIB_PATH_TYPE_UDP_ENCAP:
	return (path->udp_encap.fp_udp_encap_id);
    case FIB_PATH_TYPE_RECURSIVE:
	return (path->fp_via_fib);
    case FIB_PATH_TYPE_BIER_FMASK:
 	return (path->bier_fmask.fp_bier_fmask);
   case FIB_PATH_TYPE_BIER_TABLE:
       return (path->fp_via_bier_tbl);
   case FIB_PATH_TYPE_BIER_IMP:
       return (path->bier_imp.fp_bier_imp);
    }
    return (~0);
}

adj_index_t
fib_path_get_adj (fib_node_index_t path_index)
{
    fib_path_t *path;

    path = fib_path_get(path_index);

    if (dpo_is_adj(&path->fp_dpo))
    {
	return (path->fp_dpo.dpoi_index);
    }
    return (ADJ_INDEX_INVALID);
}

u16
fib_path_get_weight (fib_node_index_t path_index)
{
    fib_path_t *path;

    path = fib_path_get(path_index);

    ASSERT(path);

    return (path->fp_weight);
}

u16
fib_path_get_preference (fib_node_index_t path_index)
{
    fib_path_t *path;

    path = fib_path_get(path_index);

    ASSERT(path);

    return (path->fp_preference);
}

u32
fib_path_get_rpf_id (fib_node_index_t path_index)
{
    fib_path_t *path;

    path = fib_path_get(path_index);

    ASSERT(path);

    if (FIB_PATH_CFG_FLAG_RPF_ID & path->fp_cfg_flags)
    {
        return (path->deag.fp_rpf_id);
    }

    return (~0);
}

/**
 * @brief Contribute the path's adjacency to the list passed.
 * By calling this function over all paths, recursively, a child
 * can construct its full set of forwarding adjacencies, and hence its
 * uRPF list.
 */
void
fib_path_contribute_urpf (fib_node_index_t path_index,
			  index_t urpf)
{
    fib_path_t *path;

    path = fib_path_get(path_index);

    /*
     * resolved and unresolved paths contribute to the RPF list.
     */
    switch (path->fp_type)
    {
    case FIB_PATH_TYPE_ATTACHED_NEXT_HOP:
	fib_urpf_list_append(urpf, path->attached_next_hop.fp_interface);
	break;

    case FIB_PATH_TYPE_ATTACHED:
	fib_urpf_list_append(urpf, path->attached.fp_interface);
	break;

    case FIB_PATH_TYPE_RECURSIVE:
        if (FIB_NODE_INDEX_INVALID != path->fp_via_fib &&
	    !fib_path_is_looped(path_index))
        {
            /*
             * there's unresolved due to constraints, and there's unresolved
             * due to ain't got no via. can't do nowt w'out via.
             */
            fib_entry_contribute_urpf(path->fp_via_fib, urpf);
        }
	break;

    case FIB_PATH_TYPE_EXCLUSIVE:
    case FIB_PATH_TYPE_SPECIAL:
    {
        /*
	 * these path types may link to an adj, if that's what
	 * the clinet gave
	 */
        u32 rpf_sw_if_index;

        rpf_sw_if_index = dpo_get_urpf(&path->fp_dpo);

        if (~0 != rpf_sw_if_index)
	{
	    fib_urpf_list_append(urpf, rpf_sw_if_index);
	}
	break;
    }
    case FIB_PATH_TYPE_DVR:
	fib_urpf_list_append(urpf, path->dvr.fp_interface);
	break;
    case FIB_PATH_TYPE_DEAG:
    case FIB_PATH_TYPE_RECEIVE:
    case FIB_PATH_TYPE_INTF_RX:
    case FIB_PATH_TYPE_UDP_ENCAP:
    case FIB_PATH_TYPE_BIER_FMASK:
    case FIB_PATH_TYPE_BIER_TABLE:
    case FIB_PATH_TYPE_BIER_IMP:
	/*
	 * these path types don't link to an adj
	 */
	break;
    }
}

void
fib_path_stack_mpls_disp (fib_node_index_t path_index,
                          dpo_proto_t payload_proto,
                          fib_mpls_lsp_mode_t mode,
                          dpo_id_t *dpo)
{
    fib_path_t *path;

    path = fib_path_get(path_index);

    ASSERT(path);

    switch (path->fp_type)
    {
    case FIB_PATH_TYPE_ATTACHED_NEXT_HOP:
    {
        dpo_id_t tmp = DPO_INVALID;

        dpo_copy(&tmp, dpo);

        mpls_disp_dpo_create(payload_proto, ~0, mode, &tmp, dpo);
        dpo_reset(&tmp);
        break;
    }                
    case FIB_PATH_TYPE_DEAG:
    {
        dpo_id_t tmp = DPO_INVALID;

        dpo_copy(&tmp, dpo);

        mpls_disp_dpo_create(payload_proto,
                             path->deag.fp_rpf_id,
                             mode, &tmp, dpo);
        dpo_reset(&tmp);
        break;
    }
    case FIB_PATH_TYPE_RECEIVE:
    case FIB_PATH_TYPE_ATTACHED:
    case FIB_PATH_TYPE_RECURSIVE:
    case FIB_PATH_TYPE_INTF_RX:
    case FIB_PATH_TYPE_UDP_ENCAP:
    case FIB_PATH_TYPE_EXCLUSIVE:
    case FIB_PATH_TYPE_SPECIAL:
    case FIB_PATH_TYPE_BIER_FMASK:
    case FIB_PATH_TYPE_BIER_TABLE:
    case FIB_PATH_TYPE_BIER_IMP:
    case FIB_PATH_TYPE_DVR:
        break;
    }

    if (path->fp_cfg_flags & FIB_PATH_CFG_FLAG_POP_PW_CW)
    {
        dpo_id_t tmp = DPO_INVALID;

        dpo_copy(&tmp, dpo);

        pw_cw_dpo_create(&tmp, dpo);
        dpo_reset(&tmp);
    }
}

void
fib_path_contribute_forwarding (fib_node_index_t path_index,
				fib_forward_chain_type_t fct,
				dpo_id_t *dpo)
{
    fib_path_t *path;

    path = fib_path_get(path_index);

    ASSERT(path);
    ASSERT(FIB_FORW_CHAIN_TYPE_MPLS_EOS != fct);

    /*
     * The DPO stored in the path was created when the path was resolved.
     * This then represents the path's 'native' protocol; IP.
     * For all others will need to go find something else.
     */
    if (fib_path_to_chain_type(path) == fct)
    {
	dpo_copy(dpo, &path->fp_dpo);
    }
    else
    {
	switch (path->fp_type)
	{
	case FIB_PATH_TYPE_ATTACHED_NEXT_HOP:
	    switch (fct)
	    {
	    case FIB_FORW_CHAIN_TYPE_UNICAST_IP4:
	    case FIB_FORW_CHAIN_TYPE_UNICAST_IP6:
	    case FIB_FORW_CHAIN_TYPE_MPLS_EOS:
	    case FIB_FORW_CHAIN_TYPE_MPLS_NON_EOS:
	    case FIB_FORW_CHAIN_TYPE_ETHERNET:
	    case FIB_FORW_CHAIN_TYPE_NSH:
	    case FIB_FORW_CHAIN_TYPE_MCAST_IP4:
	    case FIB_FORW_CHAIN_TYPE_MCAST_IP6:
		path = fib_path_attached_next_hop_get_adj(
                    path,
                    fib_forw_chain_type_to_link_type(fct),
                    dpo);
		break;
	    case FIB_FORW_CHAIN_TYPE_BIER:
		break;
	    }
            break;
	case FIB_PATH_TYPE_RECURSIVE:
	    switch (fct)
	    {
	    case FIB_FORW_CHAIN_TYPE_MPLS_EOS:
	    case FIB_FORW_CHAIN_TYPE_UNICAST_IP4:
	    case FIB_FORW_CHAIN_TYPE_UNICAST_IP6:
	    case FIB_FORW_CHAIN_TYPE_MPLS_NON_EOS:
	    case FIB_FORW_CHAIN_TYPE_MCAST_IP4:
	    case FIB_FORW_CHAIN_TYPE_MCAST_IP6:
	    case FIB_FORW_CHAIN_TYPE_BIER:
		fib_path_recursive_adj_update(path, fct, dpo);
		break;
	    case FIB_FORW_CHAIN_TYPE_ETHERNET:
	    case FIB_FORW_CHAIN_TYPE_NSH:
		ASSERT(0);
		break;
	    }
	    break;
        case FIB_PATH_TYPE_BIER_TABLE:
            switch (fct)
            {
            case FIB_FORW_CHAIN_TYPE_BIER:
                bier_table_contribute_forwarding(path->fp_via_bier_tbl, dpo);
                break;
            case FIB_FORW_CHAIN_TYPE_MPLS_EOS:
            case FIB_FORW_CHAIN_TYPE_UNICAST_IP4:
            case FIB_FORW_CHAIN_TYPE_UNICAST_IP6:
            case FIB_FORW_CHAIN_TYPE_MPLS_NON_EOS:
            case FIB_FORW_CHAIN_TYPE_MCAST_IP4:
            case FIB_FORW_CHAIN_TYPE_MCAST_IP6:
            case FIB_FORW_CHAIN_TYPE_ETHERNET:
            case FIB_FORW_CHAIN_TYPE_NSH:
                ASSERT(0);
                break;
            }
            break;
	case FIB_PATH_TYPE_BIER_FMASK:
	    switch (fct)
	    {
	    case FIB_FORW_CHAIN_TYPE_BIER:
		fib_path_bier_fmask_update(path, dpo);
		break;
	    case FIB_FORW_CHAIN_TYPE_MPLS_EOS:
	    case FIB_FORW_CHAIN_TYPE_UNICAST_IP4:
	    case FIB_FORW_CHAIN_TYPE_UNICAST_IP6:
	    case FIB_FORW_CHAIN_TYPE_MPLS_NON_EOS:
	    case FIB_FORW_CHAIN_TYPE_MCAST_IP4:
	    case FIB_FORW_CHAIN_TYPE_MCAST_IP6:
	    case FIB_FORW_CHAIN_TYPE_ETHERNET:
	    case FIB_FORW_CHAIN_TYPE_NSH:
		ASSERT(0);
		break;
	    }
	    break;
	case FIB_PATH_TYPE_BIER_IMP:
            bier_imp_contribute_forwarding(path->bier_imp.fp_bier_imp,
                                           fib_forw_chain_type_to_dpo_proto(fct),
                                           dpo);
	    break;
	case FIB_PATH_TYPE_DEAG:
            switch (fct)
	    {
	    case FIB_FORW_CHAIN_TYPE_MPLS_NON_EOS:
                lookup_dpo_add_or_lock_w_table_id(MPLS_FIB_DEFAULT_TABLE_ID,
                                                  DPO_PROTO_MPLS,
                                                  LOOKUP_UNICAST,
                                                  LOOKUP_INPUT_DST_ADDR,
                                                  LOOKUP_TABLE_FROM_CONFIG,
                                                  dpo);
                break;
	    case FIB_FORW_CHAIN_TYPE_MPLS_EOS:
	    case FIB_FORW_CHAIN_TYPE_UNICAST_IP4:
	    case FIB_FORW_CHAIN_TYPE_UNICAST_IP6:
	    case FIB_FORW_CHAIN_TYPE_MCAST_IP4:
	    case FIB_FORW_CHAIN_TYPE_MCAST_IP6:
		dpo_copy(dpo, &path->fp_dpo);
		break;
	    case FIB_FORW_CHAIN_TYPE_BIER:
		break;
	    case FIB_FORW_CHAIN_TYPE_ETHERNET:
	    case FIB_FORW_CHAIN_TYPE_NSH:
		ASSERT(0);
		break;
            }
            break;
	case FIB_PATH_TYPE_EXCLUSIVE:
	    dpo_copy(dpo, &path->exclusive.fp_ex_dpo);
	    break;
        case FIB_PATH_TYPE_ATTACHED:
	    switch (fct)
	    {
	    case FIB_FORW_CHAIN_TYPE_MPLS_NON_EOS:
	    case FIB_FORW_CHAIN_TYPE_UNICAST_IP4:
	    case FIB_FORW_CHAIN_TYPE_UNICAST_IP6:
	    case FIB_FORW_CHAIN_TYPE_MPLS_EOS:
	    case FIB_FORW_CHAIN_TYPE_ETHERNET:
	    case FIB_FORW_CHAIN_TYPE_NSH:
            case FIB_FORW_CHAIN_TYPE_BIER:
                fib_path_attached_get_adj(path,
                                          fib_forw_chain_type_to_link_type(fct),
                                          dpo);
                break;
	    case FIB_FORW_CHAIN_TYPE_MCAST_IP4:
	    case FIB_FORW_CHAIN_TYPE_MCAST_IP6:
                {
                    adj_index_t ai;

                    /*
                     * Create the adj needed for sending IP multicast traffic
                     */
                    if (vnet_sw_interface_is_p2p(vnet_get_main(),
                                                 path->attached.fp_interface))
                    {
                        /*
                         * point-2-point interfaces do not require a glean, since
                         * there is nothing to ARP. Install a rewrite/nbr adj instead
                         */
                        ai = adj_nbr_add_or_lock(dpo_proto_to_fib(path->fp_nh_proto),
                                                 fib_forw_chain_type_to_link_type(fct),
                                                 &zero_addr,
                                                 path->attached.fp_interface);
                    }
                    else
                    {
                        ai = adj_mcast_add_or_lock(dpo_proto_to_fib(path->fp_nh_proto),
                                                   fib_forw_chain_type_to_link_type(fct),
                                                   path->attached.fp_interface);
                    }
                    dpo_set(dpo, DPO_ADJACENCY,
                            fib_forw_chain_type_to_dpo_proto(fct),
                            ai);
                    adj_unlock(ai);
                }
                break;
            }
            break;
        case FIB_PATH_TYPE_INTF_RX:
            /*
             * Create the adj needed for sending IP multicast traffic
             */
            interface_rx_dpo_add_or_lock(fib_forw_chain_type_to_dpo_proto(fct),
                                         path->attached.fp_interface,
                                         dpo);
            break;
        case FIB_PATH_TYPE_UDP_ENCAP:
            udp_encap_contribute_forwarding(path->udp_encap.fp_udp_encap_id,
                                            path->fp_nh_proto,
                                            dpo);
            break;
        case FIB_PATH_TYPE_RECEIVE:
        case FIB_PATH_TYPE_SPECIAL:
        case FIB_PATH_TYPE_DVR:
            dpo_copy(dpo, &path->fp_dpo);
            break;
	}
    }
}

load_balance_path_t *
fib_path_append_nh_for_multipath_hash (fib_node_index_t path_index,
				       fib_forward_chain_type_t fct,
				       load_balance_path_t *hash_key)
{
    load_balance_path_t *mnh;
    fib_path_t *path;

    path = fib_path_get(path_index);

    ASSERT(path);

    vec_add2(hash_key, mnh, 1);

    mnh->path_weight = path->fp_weight;
    mnh->path_index = path_index;

    if (fib_path_is_resolved(path_index))
    {
        fib_path_contribute_forwarding(path_index, fct, &mnh->path_dpo);
    }
    else
    {
        dpo_copy(&mnh->path_dpo,
                 drop_dpo_get(fib_forw_chain_type_to_dpo_proto(fct)));
    }
    return (hash_key);
}

int
fib_path_is_recursive_constrained (fib_node_index_t path_index)
{
    fib_path_t *path;

    path = fib_path_get(path_index);

    return ((FIB_PATH_TYPE_RECURSIVE == path->fp_type) &&
            ((path->fp_cfg_flags & FIB_PATH_CFG_FLAG_RESOLVE_ATTACHED) ||
             (path->fp_cfg_flags & FIB_PATH_CFG_FLAG_RESOLVE_HOST)));
}

int
fib_path_is_exclusive (fib_node_index_t path_index)
{
    fib_path_t *path;

    path = fib_path_get(path_index);

    return (FIB_PATH_TYPE_EXCLUSIVE == path->fp_type);
}

int
fib_path_is_deag (fib_node_index_t path_index)
{
    fib_path_t *path;

    path = fib_path_get(path_index);

    return (FIB_PATH_TYPE_DEAG == path->fp_type);
}

int
fib_path_is_resolved (fib_node_index_t path_index)
{
    fib_path_t *path;

    path = fib_path_get(path_index);

    return (dpo_id_is_valid(&path->fp_dpo) &&
	    (path->fp_oper_flags & FIB_PATH_OPER_FLAG_RESOLVED) &&
	    !fib_path_is_looped(path_index) &&
	    !fib_path_is_permanent_drop(path));
}

int
fib_path_is_looped (fib_node_index_t path_index)
{
    fib_path_t *path;

    path = fib_path_get(path_index);

    return (path->fp_oper_flags & FIB_PATH_OPER_FLAG_RECURSIVE_LOOP);
}

fib_path_list_walk_rc_t
fib_path_encode (fib_node_index_t path_list_index,
                 fib_node_index_t path_index,
                 const fib_path_ext_t *path_ext,
                 void *args)
{
    fib_path_encode_ctx_t *ctx = args;
    fib_route_path_t *rpath;
    fib_path_t *path;

    path = fib_path_get(path_index);
    if (!path)
      return (FIB_PATH_LIST_WALK_CONTINUE);

    vec_add2(ctx->rpaths, rpath, 1);
    rpath->frp_weight = path->fp_weight;
    rpath->frp_preference = path->fp_preference;
    rpath->frp_proto = path->fp_nh_proto;
    rpath->frp_sw_if_index = ~0;
    rpath->frp_fib_index = 0;

    switch (path->fp_type)
    {
      case FIB_PATH_TYPE_RECEIVE:
        rpath->frp_addr = path->receive.fp_addr;
        rpath->frp_sw_if_index = path->receive.fp_interface;
        rpath->frp_flags |= FIB_ROUTE_PATH_LOCAL;
        break;
      case FIB_PATH_TYPE_ATTACHED:
        rpath->frp_sw_if_index = path->attached.fp_interface;
        break;
      case FIB_PATH_TYPE_ATTACHED_NEXT_HOP:
        rpath->frp_sw_if_index = path->attached_next_hop.fp_interface;
        rpath->frp_addr = path->attached_next_hop.fp_nh;
        break;
      case FIB_PATH_TYPE_BIER_FMASK:
        rpath->frp_bier_fmask = path->bier_fmask.fp_bier_fmask;
        break;
      case FIB_PATH_TYPE_SPECIAL:
        break;
      case FIB_PATH_TYPE_DEAG:
        rpath->frp_fib_index = path->deag.fp_tbl_id;
        if (path->fp_cfg_flags & FIB_PATH_CFG_FLAG_RPF_ID)
        {
            rpath->frp_flags |= FIB_ROUTE_PATH_RPF_ID;
        }
        break;
      case FIB_PATH_TYPE_RECURSIVE:
        rpath->frp_addr = path->recursive.fp_nh.fp_ip;
        rpath->frp_fib_index = path->recursive.fp_tbl_id;
        break;
      case FIB_PATH_TYPE_DVR:
          rpath->frp_sw_if_index = path->dvr.fp_interface;
          rpath->frp_flags |= FIB_ROUTE_PATH_DVR;
          break;
      case FIB_PATH_TYPE_UDP_ENCAP:
          rpath->frp_udp_encap_id = path->udp_encap.fp_udp_encap_id;
          rpath->frp_flags |= FIB_ROUTE_PATH_UDP_ENCAP;
          break;
      case FIB_PATH_TYPE_INTF_RX:
	  rpath->frp_sw_if_index = path->receive.fp_interface;
	  rpath->frp_flags |= FIB_ROUTE_PATH_INTF_RX;
	  break;
      case FIB_PATH_TYPE_EXCLUSIVE:
        rpath->frp_flags |= FIB_ROUTE_PATH_EXCLUSIVE;
      default:
        break;
    }

    if (path_ext && path_ext->fpe_type == FIB_PATH_EXT_MPLS) 
    {
        rpath->frp_label_stack = path_ext->fpe_path.frp_label_stack;
    }

    if (path->fp_cfg_flags & FIB_PATH_CFG_FLAG_DROP)
        rpath->frp_flags |= FIB_ROUTE_PATH_DROP;
    if (path->fp_cfg_flags & FIB_PATH_CFG_FLAG_ICMP_UNREACH)
        rpath->frp_flags |= FIB_ROUTE_PATH_ICMP_UNREACH;
    if (path->fp_cfg_flags & FIB_PATH_CFG_FLAG_ICMP_PROHIBIT)
        rpath->frp_flags |= FIB_ROUTE_PATH_ICMP_PROHIBIT;

    return (FIB_PATH_LIST_WALK_CONTINUE);
}

dpo_proto_t
fib_path_get_proto (fib_node_index_t path_index)
{
    fib_path_t *path;

    path = fib_path_get(path_index);

    return (path->fp_nh_proto);
}

void
fib_path_module_init (void)
{
    fib_node_register_type (FIB_NODE_TYPE_PATH, &fib_path_vft);
    fib_path_logger = vlib_log_register_class ("fib", "path");
}

static clib_error_t *
show_fib_path_command (vlib_main_t * vm,
			unformat_input_t * input,
			vlib_cli_command_t * cmd)
{
    fib_node_index_t pi;
    fib_path_t *path;

    if (unformat (input, "%d", &pi))
    {
	/*
	 * show one in detail
	 */
	if (!pool_is_free_index(fib_path_pool, pi))
	{
	    path = fib_path_get(pi);
	    u8 *s = format(NULL, "%U", format_fib_path, pi, 1,
                           FIB_PATH_FORMAT_FLAGS_NONE);
	    s = format(s, "\n  children:");
	    s = fib_node_children_format(path->fp_node.fn_children, s);
	    vlib_cli_output (vm, "%v", s);
	    vec_free(s);
	}
	else
	{
	    vlib_cli_output (vm, "path %d invalid", pi);
	}
    }
    else
    {
	vlib_cli_output (vm, "FIB Paths");
	pool_foreach_index (pi, fib_path_pool,
	({
	    vlib_cli_output (vm, "%U", format_fib_path, pi, 0,
                             FIB_PATH_FORMAT_FLAGS_NONE);
	}));
    }

    return (NULL);
}

VLIB_CLI_COMMAND (show_fib_path, static) = {
  .path = "show fib paths",
  .function = show_fib_path_command,
  .short_help = "show fib paths",
};
