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

#ifndef __FIB_ENTRY_H__
#define __FIB_ENTRY_H__

#include <vnet/fib/fib_node.h>
#include <vnet/fib/fib_entry_delegate.h>
#include <vnet/adj/adj.h>
#include <vnet/ip/ip.h>
#include <vnet/dpo/dpo.h>

/**
 * The different sources that can create a route.
 * The sources are defined here the thier relative priority order.
 * The lower the value the higher the priority
 */
typedef enum fib_source_t_ {
    /**
     * Marker. Add new values after this one.
     */
    FIB_SOURCE_FIRST,
    /**
     * Special sources. These are for entries that are added to all
     * FIBs by default, and should never be over-ridden (hence they
     * are the highest priority)
     */
    FIB_SOURCE_SPECIAL = FIB_SOURCE_FIRST,
    /**
     * Classify. A route that links directly to a classify adj
     */
    FIB_SOURCE_CLASSIFY,
    /**
     * A route the is being 'proxied' on behalf of another device
     */
    FIB_SOURCE_PROXY,
    /**
     * Route added as a result of interface configuration.
     * this will also come from the API/CLI, but the distinction is
     * that is from confiiguration on an interface, not a 'ip route' command
     */
    FIB_SOURCE_INTERFACE,
    /**
     * SRv6 and SR-MPLS
     */
    FIB_SOURCE_SR,
    /**
     * A high priority source a plugin can use
     */
    FIB_SOURCE_PLUGIN_HI,
    /**
     * From the BIER subsystem
     */
    FIB_SOURCE_BIER,
    /**
     * From 6RD.
     */
    FIB_SOURCE_6RD,
    /**
     * From the control plane API
     */
    FIB_SOURCE_API,
    /**
     * From the CLI.
     */
    FIB_SOURCE_CLI,
    /**
     * A low (below routing) priority source a plugin can use
     */
    FIB_SOURCE_PLUGIN_LOW,
    /**
     * LISP
     */
    FIB_SOURCE_LISP,
    /**
     * IPv[46] Mapping
     */
    FIB_SOURCE_MAP,
    /**
     * DHCP
     */
    FIB_SOURCE_DHCP,
    /**
     * IPv6 Proxy ND
     */
    FIB_SOURCE_IP6_ND_PROXY,
    /**
     * IPv6 ND (seen in the link-local tables)
     */
    FIB_SOURCE_IP6_ND,
    /**
     * Adjacency source.
     * routes created as a result of ARP/ND entries. This is lower priority
     * then the API/CLI. This is on purpose. trust me.
     */
    FIB_SOURCE_ADJ,
    /**
     * MPLS label. The prefix has been assigned a local label. This source
     * never provides forwarding information, instead it acts as a place-holder
     * so the association of label to prefix can be maintained
     */
    FIB_SOURCE_MPLS,
    /**
     * Attached Export source.
     * routes created as a result of attahced export. routes thus sourced
     * will be present in the export tables
     */
    FIB_SOURCE_AE,
    /**
     * Recursive resolution source.
     * Used to install an entry that is the resolution traget of another.
     */
    FIB_SOURCE_RR,
    /**
     * uRPF bypass/exemption.
     * Used to install an entry that is exempt from the loose uRPF check
     */
    FIB_SOURCE_URPF_EXEMPT,
    /**
     * The default route source.
     * The default route is always added to the FIB table (like the
     * special sources) but we need to be able to over-ride it with
     * 'ip route' sources when provided
     */
    FIB_SOURCE_DEFAULT_ROUTE,
    /**
     * The interpose source.
     * This is not a real source, so don't use it to source a prefix.
     * It exists here to provide a value against which to register to the
     * VFT for providing the interpose actions to a real source.
     */
    FIB_SOURCE_INTERPOSE,
    /**
     * Marker. add new entries before this one.
     */
    FIB_SOURCE_LAST = FIB_SOURCE_INTERPOSE,
} __attribute__ ((packed)) fib_source_t;

STATIC_ASSERT (sizeof(fib_source_t) == 1,
	       "FIB too many sources");

/**
 * The maximum number of sources
 */
#define FIB_SOURCE_MAX (FIB_SOURCE_LAST+1)

#define FIB_SOURCES {					\
    [FIB_SOURCE_SPECIAL] = "special",			\
    [FIB_SOURCE_INTERFACE] = "interface",		\
    [FIB_SOURCE_PROXY] = "proxy",                       \
    [FIB_SOURCE_BIER] = "BIER",			        \
    [FIB_SOURCE_6RD] = "6RD",			        \
    [FIB_SOURCE_API] = "API",			        \
    [FIB_SOURCE_CLI] = "CLI",			        \
    [FIB_SOURCE_ADJ] = "adjacency",			\
    [FIB_SOURCE_MAP] = "MAP",			        \
    [FIB_SOURCE_SR] = "SR",			        \
    [FIB_SOURCE_LISP] = "LISP", 			\
    [FIB_SOURCE_CLASSIFY] = "classify",			\
    [FIB_SOURCE_DHCP] = "DHCP",   			\
    [FIB_SOURCE_IP6_ND_PROXY] = "IPv6-proxy-nd",        \
    [FIB_SOURCE_IP6_ND] = "IPv6-nd",                    \
    [FIB_SOURCE_RR] = "recursive-resolution",	        \
    [FIB_SOURCE_AE] = "attached_export",	        \
    [FIB_SOURCE_MPLS] = "mpls",           	        \
    [FIB_SOURCE_URPF_EXEMPT] = "urpf-exempt",	        \
    [FIB_SOURCE_DEFAULT_ROUTE] = "default-route",	\
    [FIB_SOURCE_PLUGIN_HI] = "plugin-hi",               \
    [FIB_SOURCE_PLUGIN_LOW] = "plugin-low",             \
    [FIB_SOURCE_INTERPOSE] = "interpose",               \
}

#define FOR_EACH_FIB_SOURCE(_item) \
    for (_item = FIB_SOURCE_FIRST; _item < FIB_SOURCE_MAX; _item++)

/**
 * The different sources that can create a route.
 * The sources are defined here the thier relative priority order.
 * The lower the value the higher the priority
 */
typedef enum fib_entry_attribute_t_ {
    /**
     * Marker. Add new values after this one.
     */
    FIB_ENTRY_ATTRIBUTE_FIRST,
    /**
     * Connected. The prefix is configured on an interface.
     */
    FIB_ENTRY_ATTRIBUTE_CONNECTED = FIB_ENTRY_ATTRIBUTE_FIRST,
    /**
     * Attached. The prefix is attached to an interface.
     */
    FIB_ENTRY_ATTRIBUTE_ATTACHED,
    /**
     * The route is an explicit drop.
     */
    FIB_ENTRY_ATTRIBUTE_DROP,
    /**
     * The route is exclusive. The client creating the route is
     * providing an exclusive adjacency.
     */
    FIB_ENTRY_ATTRIBUTE_EXCLUSIVE,
    /**
     * The route is attached cross tables and thus imports covered
     * prefixes from the other table.
     */
    FIB_ENTRY_ATTRIBUTE_IMPORT,
    /**
     * The prefix/address is local to this device
     */
    FIB_ENTRY_ATTRIBUTE_LOCAL,
    /**
     * The prefix/address is a multicast prefix.
     *  this aplies only to MPLS. IP multicast is handled by mfib
     */
    FIB_ENTRY_ATTRIBUTE_MULTICAST,
    /**
     * The prefix/address exempted from loose uRPF check
     * To be used with caution
     */
    FIB_ENTRY_ATTRIBUTE_URPF_EXEMPT,
    /**
     * The prefix/address exempted from attached export
     */
    FIB_ENTRY_ATTRIBUTE_NO_ATTACHED_EXPORT,
    /**
     * This FIB entry imposes its source information on all prefixes
     * that is covers
     */
    FIB_ENTRY_ATTRIBUTE_COVERED_INHERIT,
    /**
     * The interpose attribute.
     * place the forwarding provided by the source infront of the forwarding
     * provided by the best source, or failing that, by the cover.
     */
    FIB_ENTRY_ATTRIBUTE_INTERPOSE,
    /**
     * Marker. add new entries before this one.
     */
    FIB_ENTRY_ATTRIBUTE_LAST = FIB_ENTRY_ATTRIBUTE_INTERPOSE,
} fib_entry_attribute_t;

#define FIB_ENTRY_ATTRIBUTES {		       		\
    [FIB_ENTRY_ATTRIBUTE_CONNECTED] = "connected",	\
    [FIB_ENTRY_ATTRIBUTE_ATTACHED]  = "attached",	\
    [FIB_ENTRY_ATTRIBUTE_IMPORT]    = "import",	        \
    [FIB_ENTRY_ATTRIBUTE_DROP]      = "drop",		\
    [FIB_ENTRY_ATTRIBUTE_EXCLUSIVE] = "exclusive",      \
    [FIB_ENTRY_ATTRIBUTE_LOCAL]     = "local",		\
    [FIB_ENTRY_ATTRIBUTE_URPF_EXEMPT] = "uRPF-exempt",  \
    [FIB_ENTRY_ATTRIBUTE_MULTICAST] = "multicast",	\
    [FIB_ENTRY_ATTRIBUTE_NO_ATTACHED_EXPORT] = "no-attached-export",	\
    [FIB_ENTRY_ATTRIBUTE_COVERED_INHERIT] = "covered-inherit",  \
    [FIB_ENTRY_ATTRIBUTE_INTERPOSE] = "interpose",  \
}

#define FOR_EACH_FIB_ATTRIBUTE(_item)			\
    for (_item = FIB_ENTRY_ATTRIBUTE_FIRST;		\
	 _item <= FIB_ENTRY_ATTRIBUTE_LAST;		\
	 _item++)

typedef enum fib_entry_flag_t_ {
    FIB_ENTRY_FLAG_NONE      = 0,
    FIB_ENTRY_FLAG_CONNECTED = (1 << FIB_ENTRY_ATTRIBUTE_CONNECTED),
    FIB_ENTRY_FLAG_ATTACHED  = (1 << FIB_ENTRY_ATTRIBUTE_ATTACHED),
    FIB_ENTRY_FLAG_DROP      = (1 << FIB_ENTRY_ATTRIBUTE_DROP),
    FIB_ENTRY_FLAG_EXCLUSIVE = (1 << FIB_ENTRY_ATTRIBUTE_EXCLUSIVE),
    FIB_ENTRY_FLAG_LOCAL     = (1 << FIB_ENTRY_ATTRIBUTE_LOCAL),
    FIB_ENTRY_FLAG_IMPORT    = (1 << FIB_ENTRY_ATTRIBUTE_IMPORT),
    FIB_ENTRY_FLAG_NO_ATTACHED_EXPORT = (1 << FIB_ENTRY_ATTRIBUTE_NO_ATTACHED_EXPORT),
    FIB_ENTRY_FLAG_LOOSE_URPF_EXEMPT = (1 << FIB_ENTRY_ATTRIBUTE_URPF_EXEMPT),
    FIB_ENTRY_FLAG_MULTICAST = (1 << FIB_ENTRY_ATTRIBUTE_MULTICAST),
    FIB_ENTRY_FLAG_COVERED_INHERIT = (1 << FIB_ENTRY_ATTRIBUTE_COVERED_INHERIT),
    FIB_ENTRY_FLAG_INTERPOSE = (1 << FIB_ENTRY_ATTRIBUTE_INTERPOSE),
} __attribute__((packed)) fib_entry_flag_t;

extern u8 * format_fib_entry_flags(u8 *s, va_list *args);

/**
 * Flags for the source data
 */
typedef enum fib_entry_src_attribute_t_ {
    /**
     * Marker. Add new values after this one.
     */
    FIB_ENTRY_SRC_ATTRIBUTE_FIRST,
    /**
     * the source has been added to the entry
     */
    FIB_ENTRY_SRC_ATTRIBUTE_ADDED = FIB_ENTRY_SRC_ATTRIBUTE_FIRST,
    /**
     * the source is contributing forwarding
     */
    FIB_ENTRY_SRC_ATTRIBUTE_CONTRIBUTING,
    /**
     * the source is active/best
     */
    FIB_ENTRY_SRC_ATTRIBUTE_ACTIVE,
    /**
     * the source is inherited from its cover
     */
    FIB_ENTRY_SRC_ATTRIBUTE_INHERITED,
    /**
     * Marker. add new entries before this one.
     */
    FIB_ENTRY_SRC_ATTRIBUTE_LAST = FIB_ENTRY_SRC_ATTRIBUTE_INHERITED,
} fib_entry_src_attribute_t;


#define FIB_ENTRY_SRC_ATTRIBUTES {		 \
    [FIB_ENTRY_SRC_ATTRIBUTE_ADDED]  = "added",	 \
    [FIB_ENTRY_SRC_ATTRIBUTE_CONTRIBUTING] = "contributing", \
    [FIB_ENTRY_SRC_ATTRIBUTE_ACTIVE] = "active", \
    [FIB_ENTRY_SRC_ATTRIBUTE_INHERITED] = "inherited", \
}

#define FOR_EACH_FIB_SRC_ATTRIBUTE(_item)      		\
    for (_item = FIB_ENTRY_SRC_ATTRIBUTE_FIRST;		\
	 _item <= FIB_ENTRY_SRC_ATTRIBUTE_LAST;		\
	 _item++)

typedef enum fib_entry_src_flag_t_ {
    FIB_ENTRY_SRC_FLAG_NONE   = 0,
    FIB_ENTRY_SRC_FLAG_ADDED  = (1 << FIB_ENTRY_SRC_ATTRIBUTE_ADDED),
    FIB_ENTRY_SRC_FLAG_CONTRIBUTING = (1 << FIB_ENTRY_SRC_ATTRIBUTE_CONTRIBUTING),
    FIB_ENTRY_SRC_FLAG_ACTIVE = (1 << FIB_ENTRY_SRC_ATTRIBUTE_ACTIVE),
    FIB_ENTRY_SRC_FLAG_INHERITED = (1 << FIB_ENTRY_SRC_ATTRIBUTE_INHERITED),
} __attribute__ ((packed)) fib_entry_src_flag_t;

extern u8 * format_fib_entry_src_flags(u8 *s, va_list *args);

/*
 * Keep the size of the flags field to 2 bytes, so it
 * can be placed next to the 2 bytes reference count
 */
STATIC_ASSERT (sizeof(fib_entry_src_flag_t) <= 2,
	       "FIB entry flags field size too big");

/**
 * Information related to the source of a FIB entry
 */
typedef struct fib_entry_src_t_ {
    /**
     * A vector of path extensions
     */
    fib_path_ext_list_t fes_path_exts;

    /**
     * The path-list created by the source
     */
    fib_node_index_t fes_pl;

    /**
     * Flags the source contributes to the entry
     */
    fib_entry_flag_t fes_entry_flags;

    /**
     * Which source this info block is for
     */
    fib_source_t fes_src;

    /**
     * Flags on the source
     */
    fib_entry_src_flag_t fes_flags;

    /**
     * 1 bytes ref count. This is not the number of users of the Entry
     * (which is itself not large, due to path-list sharing), but the number
     * of times a given source has been added. Which is even fewer
     */
    u8 fes_ref_count;
    
    /**
     * Source specific info
     */
    union {
	struct {
	    /**
	     * the index of the FIB entry that is the covering entry
	     */
	    fib_node_index_t fesr_cover;
	    /**
	     * This source's index in the cover's list
	     */
	    u32 fesr_sibling;
	} rr;
	struct {
	    /**
	     * the index of the FIB entry that is the covering entry
	     */
	    fib_node_index_t fesi_cover;
	    /**
	     * This source's index in the cover's list
	     */
	    u32 fesi_sibling;
            /**
             * DPO type to interpose. The dpo type needs to have registered
             * it's 'contribute interpose' callback function.
             */
            dpo_id_t fesi_dpo;
	} interpose;
	struct {
	    /**
	     * the index of the FIB entry that is the covering entry
	     */
	    fib_node_index_t fesa_cover;
	    /**
	     * This source's index in the cover's list
	     */
	    u32 fesa_sibling;
	} adj;
	struct {
	    /**
	     * the index of the FIB entry that is the covering entry
	     */
	    fib_node_index_t fesi_cover;
	    /**
	     * This source's index in the cover's list
	     */
	    u32 fesi_sibling;
	} interface;
	struct {
	    /**
	     * This MPLS local label associated with the prefix.
	     */
	    mpls_label_t fesm_label;

	    /**
	     * the indicies of the LFIB entries created
	     */
	    fib_node_index_t fesm_lfes[2];
	} mpls;
	struct {
	    /**
	     * The source FIB index.
	     */
            fib_node_index_t fesl_fib_index;
	} lisp;
    } u;
} fib_entry_src_t;

/**
 * An entry in a FIB table.
 *
 * This entry represents a route added to the FIB that is stored
 * in one of the FIB tables.
 */
typedef struct fib_entry_t_ {
    /**
     * Base class. The entry's node representation in the graph.
     */
    fib_node_t fe_node;
    /**
     * The prefix of the route. this is const just to be sure.
     * It is the entry's key/identity and so should never change.
     */
    const fib_prefix_t fe_prefix;
    /**
     * The index of the FIB table this entry is in
     */
    u32 fe_fib_index;
    /**
     * The load-balance used for forwarding.
     *
     * We don't share the EOS and non-EOS even in case when they could be
     * because:
     *   - complexity & reliability v. memory
     *       determining the conditions where sharing is possible is non-trivial.
     *   - separate LBs means we can get the EOS bit right in the MPLS label DPO
     *     and so save a few clock cycles in the DP imposition node since we can
     *     paint the header straight on without the need to check the packet
     *     type to derive the EOS bit value.
     */
    dpo_id_t fe_lb;
    /**
     * Vector of source infos.
     * Most entries will only have 1 source. So we optimise for memory usage,
     * which is preferable since we have many entries.
     */
    fib_entry_src_t *fe_srcs;
    /**
     * the path-list for which this entry is a child. This is also the path-list
     * that is contributing forwarding for this entry.
     */
    fib_node_index_t fe_parent;
    /**
     * index of this entry in the parent's child list.
     * This is set when this entry is added as a child, but can also
     * be changed by the parent as it manages its list.
     */
    u32 fe_sibling;

    /**
     * A vector of delegates.
     */
    fib_entry_delegate_t *fe_delegates;
} fib_entry_t;

#define FOR_EACH_FIB_ENTRY_FLAG(_item) \
    for (_item = FIB_ENTRY_FLAG_FIRST; _item < FIB_ENTRY_FLAG_MAX; _item++)

#define FIB_ENTRY_FORMAT_BRIEF   (0x0)
#define FIB_ENTRY_FORMAT_DETAIL  (0x1)
#define FIB_ENTRY_FORMAT_DETAIL2 (0x2)

extern u8 *format_fib_entry (u8 * s, va_list * args);
extern u8 *format_fib_source (u8 * s, va_list * args);

extern fib_node_index_t fib_entry_create_special(u32 fib_index,
						 const fib_prefix_t *prefix,
						 fib_source_t source,
						 fib_entry_flag_t flags,
						 const dpo_id_t *dpo);

extern fib_node_index_t fib_entry_create (u32 fib_index,
					  const fib_prefix_t *prefix,
					  fib_source_t source,
					  fib_entry_flag_t flags,
					  const fib_route_path_t *paths);
extern void fib_entry_update (fib_node_index_t fib_entry_index,
			      fib_source_t source,
			      fib_entry_flag_t flags,
			      const fib_route_path_t *paths);

extern void fib_entry_path_add(fib_node_index_t fib_entry_index,
			       fib_source_t source,
			       fib_entry_flag_t flags,
			       const fib_route_path_t *rpaths);
extern void fib_entry_special_add(fib_node_index_t fib_entry_index,
				  fib_source_t source,
				  fib_entry_flag_t flags,
				  const dpo_id_t *dpo);
extern void fib_entry_special_update(fib_node_index_t fib_entry_index,
				     fib_source_t source,
				     fib_entry_flag_t flags,
				     const dpo_id_t *dpo);
extern fib_entry_src_flag_t fib_entry_special_remove(fib_node_index_t fib_entry_index,
						     fib_source_t source);

extern fib_entry_src_flag_t fib_entry_path_remove(fib_node_index_t fib_entry_index,
						  fib_source_t source,
						  const fib_route_path_t *rpaths);

extern void fib_entry_inherit(fib_node_index_t cover,
                              fib_node_index_t covered);

extern fib_entry_src_flag_t fib_entry_delete(fib_node_index_t fib_entry_index,
					     fib_source_t source);

extern void fib_entry_recalculate_forwarding(
    fib_node_index_t fib_entry_index);
extern void fib_entry_contribute_urpf(fib_node_index_t path_index,
				      index_t urpf);
extern void fib_entry_contribute_forwarding(
    fib_node_index_t fib_entry_index,
    fib_forward_chain_type_t type,
    dpo_id_t *dpo);
extern const dpo_id_t * fib_entry_contribute_ip_forwarding(
    fib_node_index_t fib_entry_index);
extern adj_index_t fib_entry_get_adj_for_source(
    fib_node_index_t fib_entry_index,
    fib_source_t source);
extern const int fib_entry_get_dpo_for_source (
    fib_node_index_t fib_entry_index,
    fib_source_t source,
    dpo_id_t *dpo);

extern adj_index_t fib_entry_get_adj(fib_node_index_t fib_entry_index);

extern int fib_entry_cmp_for_sort(void *i1, void *i2);

extern void fib_entry_cover_changed(fib_node_index_t fib_entry);
extern void fib_entry_cover_updated(fib_node_index_t fib_entry);
extern int fib_entry_recursive_loop_detect(fib_node_index_t entry_index,
					   fib_node_index_t **entry_indicies);

extern void fib_entry_lock(fib_node_index_t fib_entry_index);
extern void fib_entry_unlock(fib_node_index_t fib_entry_index);

extern u32 fib_entry_child_add(fib_node_index_t fib_entry_index,
			       fib_node_type_t type,
			       fib_node_index_t child_index);
extern void fib_entry_child_remove(fib_node_index_t fib_entry_index,
				   u32 sibling_index);
extern u32 fib_entry_get_resolving_interface(fib_node_index_t fib_entry_index);
extern u32 fib_entry_get_resolving_interface_for_source(
    fib_node_index_t fib_entry_index,
    fib_source_t source);

extern fib_route_path_t* fib_entry_encode(fib_node_index_t fib_entry_index);
extern const fib_prefix_t* fib_entry_get_prefix(fib_node_index_t fib_entry_index);
extern u32 fib_entry_get_fib_index(fib_node_index_t fib_entry_index);
extern void fib_entry_set_source_data(fib_node_index_t fib_entry_index,
                                      fib_source_t source,
                                      const void *data);
extern const void* fib_entry_get_source_data(fib_node_index_t fib_entry_index,
                                             fib_source_t source);

extern fib_entry_flag_t fib_entry_get_flags(fib_node_index_t fib_entry_index);
extern fib_entry_flag_t fib_entry_get_flags_for_source(
    fib_node_index_t fib_entry_index,
    fib_source_t source);
extern fib_source_t fib_entry_get_best_source(fib_node_index_t fib_entry_index);
extern int fib_entry_is_sourced(fib_node_index_t fib_entry_index,
                                fib_source_t source);

extern fib_node_index_t fib_entry_get_path_list(fib_node_index_t fib_entry_index);
extern int fib_entry_is_resolved(fib_node_index_t fib_entry_index);
extern int fib_entry_is_host(fib_node_index_t fib_entry_index);
extern void fib_entry_set_flow_hash_config(fib_node_index_t fib_entry_index,
                                           flow_hash_config_t hash_config);

extern void fib_entry_module_init(void);

extern u32 fib_entry_get_stats_index(fib_node_index_t fib_entry_index);

/*
 * unsafe... beware the raw pointer.
 */
extern fib_node_index_t fib_entry_get_index(const fib_entry_t * fib_entry);
extern fib_entry_t * fib_entry_get(fib_node_index_t fib_entry_index);

/*
 * for testing purposes.
 */
extern u32 fib_entry_pool_size(void);

#endif
