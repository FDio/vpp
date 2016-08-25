/*
 * lfib.h: The Label/MPLS FIB
 *
 * Copyright (c) 2012 Cisco and/or its affiliates.
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

#include <vnet/lfib/lfib_entry.h>
#include <vnet/lfib/lfib_table.h>
#include <vnet/fib/fib_node.h>
#include <vnet/fib/fib_entry.h>
#include <vnet/fib/fib_path_list.h>
#include <vnet/mpls/mpls.h>

/**
 * Configuration Flags for the LFIB entry
 */
typedef enum lfib_entry_cfg_flags_t_
{
    /**
     * Special entries are managed directly by external entities.
     * Here managed means provided with a parent path-list and DPO.
     * A speical entry is not a child of this path-list.
     */
    LFIB_ENTRY_FLAG_SPECIAL = (1 << 0),
} lfib_entry_cfg_flags_t;

/**
 * An entry (aka route) in the label FIB
 */
typedef struct lfib_entry_t_
{
    /**
     * Base class. The entry's node representation in the graph.
     */
    fib_node_t lfe_node;
    /**
     * The label (in host byte order) of the route
     */
    mpls_label_t lfe_label;
    /**
     * the EOS bit
     */
    mpls_eos_bit_t lfe_eos;
    /**
     * The index of the LFIB table this entry is in
     */
    u32 lfe_fib_index;
    /**
     * The load-balance used for forwarding. This is constructed from
     * the load-balance contributed by the path list
     */
    dpo_id_t lfe_lb;
    /**
     * the path-list for which this entry is a child. This is also the path-list
     * that is contributing forwarding for this entry.
     */
    fib_node_index_t lfe_parent;
    /**
     * index of this entry in the parent's child list.
     * This is set when this entry is added as a child, but can also
     * be changed by the parent as it manages its list.
     */
    u32 lfe_sibling;

    /**
     * If the lfib entry is associated with an IP prefix this section
     * captures that relationship.
     */
    struct {
	fib_node_index_t lfe_ip_entry;
    } ip;
} lfib_entry_t;

/*
 * Pool for all lfib entries
 */
static lfib_entry_t *lfib_entry_pool;

/**
 * Debug macro
 */
#ifdef FIB_DEBUG
#define LFIB_ENTRY_DBG(_e, _fmt, _args...)		\
{   		          				\
    u8*__tmp = NULL;					\
    __tmp = format(__tmp, "e:[%d:%U",			\
		   fib_entry_get_index(_e),		\
		   format_lfib_entry_key,		\
		   _e->lfe_key);			\
    __tmp = format(__tmp, _fmt, ##_args);		\
    clib_warning("%s", __tmp);				\
    vec_free(__tmp);					\
}
#else
#define FIB_ENTRY_DBG(_e, _fmt, _args...)
#endif

static inline fib_node_index_t
lfib_entry_get_index (const lfib_entry_t * lfe)
{
    return (lfe - lfib_entry_pool);
}

static inline lfib_entry_t *
lfib_entry_get (fib_node_index_t lfei)
{
    return (&lfib_entry_pool[lfei]);
}

static lfib_entry_t *
lfib_entry_alloc (u32 fib_index,
		  mpls_label_t label,
                  mpls_eos_bit_t eos,
		  fib_node_index_t *index)
{
    lfib_entry_t *lfe;

    pool_get(lfib_entry_pool, lfe);
    memset(lfe, 0, sizeof(*lfe));

    fib_node_init(&lfe->lfe_node, FIB_NODE_TYPE_MPLS_ENTRY);

    lfe->ip.lfe_ip_entry = FIB_NODE_INDEX_INVALID;
    lfe->lfe_fib_index = fib_index;
    lfe->lfe_label = label;
    lfe->lfe_eos = eos;

    dpo_reset(&lfe->lfe_lb);

    *index = lfib_entry_get_index(lfe);

    FIB_ENTRY_DBG(fib_entry, "alloc");

    return (lfe);
}

u8 *
format_lfib_entry (u8 * s, va_list * args)
{
    lfib_entry_t *lfe;
    int flags;

    lfe = va_arg (*args, lfib_entry_t *);
    flags = va_arg (*args, int);

    s = format (s, "%U-%U",
                format_mpls_unicast_label, lfe->lfe_label,
                format_mpls_eos_bit, lfe->lfe_eos);

    if (FIB_NODE_INDEX_INVALID != lfe->ip.lfe_ip_entry)
    {
	fib_prefix_t pfx;

	fib_entry_get_prefix(lfe->ip.lfe_ip_entry, &pfx);

	s = format(s, " [%d:%U]",
		   fib_entry_get_fib_table_id(lfe->ip.lfe_ip_entry),
		   format_fib_prefix, &pfx);
    }
 
    if (flags && LFIB_ENTRY_FORMAT_DETAIL)
    {
	s = format (s, " fib:%d", lfe->lfe_fib_index);
	s = format (s, " index:%d", lfib_entry_get_index(lfe));
	s = format (s, " locks:%d\n", lfe->lfe_node.fn_locks);

	s = fib_path_list_format(lfe->lfe_parent, s);

	s = format (s, "\n forwarding:\n");
    }
    else
    {
	s = format (s, "\n");
    }

    if (!dpo_id_is_valid(&lfe->lfe_lb))
    {
	s = format (s, "UNRESOLVED");
    }
    else
    {
	s = format(s, "  %U",
		   format_dpo_id,
		   &lfe->lfe_lb,
		   4);
	s = format(s, "\n");
    }

    return (s);
}

void
lfib_entry_lock (fib_node_index_t lfei)
{
    lfib_entry_t *lfe;

    lfe = lfib_entry_get(lfei);

    fib_node_lock(&lfe->lfe_node);
}

void
lfib_entry_unlock (fib_node_index_t lfei)
{
    lfib_entry_t *lfe;

    lfe = lfib_entry_get(lfei);

    fib_node_unlock(&lfe->lfe_node);
}

void
lfib_entry_show (fib_node_index_t lfei,
		 int flags,
		 vlib_main_t * vm)
{
    lfib_entry_t *lfe;

    lfe = lfib_entry_get(lfei);

    vlib_cli_output (vm, "%U", format_lfib_entry, lfe, flags);
}

fib_node_index_t
lfib_entry_create_from_ip_fib_entry (fib_node_index_t fib_index,
				     mpls_label_t label,
				     mpls_eos_bit_t eos,
				     fib_node_index_t fib_entry_index)
{
    fib_node_index_t index;
    lfib_entry_t *lfe;

    lfe = lfib_entry_alloc(fib_index, label, eos, &index);
    lfe->ip.lfe_ip_entry = fib_entry_index;
    lfe->lfe_parent = fib_entry_get_path_list(fib_entry_index);
    lfe->lfe_sibling = fib_path_list_child_add(lfe->lfe_parent,
					       FIB_NODE_TYPE_MPLS_ENTRY,
					       lfib_entry_get_index(lfe));

    fib_entry_contribute_forwarding(fib_entry_index,
				    (eos ?
				     FIB_FORW_CHAIN_TYPE_MPLS_EOS :
				     FIB_FORW_CHAIN_TYPE_MPLS_NON_EOS),
				    &lfe->lfe_lb);

    lfib_forwarding_table_update(fib_index,
                                 lfe->lfe_label,
                                 lfe->lfe_eos,
                                 &lfe->lfe_lb);

    return (index);
}

typedef struct lfib_entry_collect_forwarding_ctx_t_
{
    load_balance_path_t * next_hops;
    fib_forward_chain_type_t fct;
} lfib_entry_collect_forwarding_ctx_t;

static int
lfib_entry_collect_forwarding (fib_node_index_t pl_index,
                               fib_node_index_t path_index,
                               void *arg)
{
    lfib_entry_collect_forwarding_ctx_t *ctx;
    load_balance_path_t *nh;

    ctx = arg;

    vec_add2(ctx->next_hops, nh, 1);

    nh->path_index = path_index;
    nh->path_weight = fib_path_get_weight(path_index);
    fib_path_contribute_forwarding(path_index,
                                   ctx->fct,
                                   &nh->path_dpo);
    return (!0);
}

fib_node_index_t
lfib_entry_create (fib_node_index_t lfib_index,
                   mpls_label_t label,
                   mpls_eos_bit_t eos,
                   const fib_route_path_t *paths)
{
    fib_node_index_t index;
    dpo_proto_t dproto;
    lfib_entry_t *lfe;

    lfe = lfib_entry_alloc(lfib_index, label, eos, &index);

    lfe->lfe_parent = fib_path_list_create(FIB_PATH_LIST_FLAG_SHARED,
                                           paths[0].frp_proto,
                                           paths);
    lfe->lfe_sibling = fib_path_list_child_add(lfe->lfe_parent,
					       FIB_NODE_TYPE_MPLS_ENTRY,
					       lfib_entry_get_index(lfe));
    dproto = (eos ?
              fib_proto_to_dpo(paths[0].frp_proto) :
              DPO_PROTO_MPLS);


    lfib_entry_collect_forwarding_ctx_t ctx = {
        .fct = (eos ?
                FIB_FORW_CHAIN_TYPE_MPLS_EOS :
                FIB_FORW_CHAIN_TYPE_MPLS_NON_EOS),
    };

    fib_path_list_walk(lfe->lfe_parent,
                       lfib_entry_collect_forwarding,
                       &ctx);

    if (!dpo_id_is_valid(&lfe->lfe_lb))
    {
        /*
         * first time create
         */
        dpo_set(&lfe->lfe_lb,
                DPO_LOAD_BALANCE,
                dproto,
                // FIXME - flow hash config for MPLS
                load_balance_create(0, dproto, 0));
    }

    load_balance_multipath_update(&lfe->lfe_lb,
                                  ctx.next_hops,
                                  LOAD_BALANCE_FLAG_NONE);

    lfib_forwarding_table_update(lfib_index,
                                 lfe->lfe_label,
                                 lfe->lfe_eos,
                                 &lfe->lfe_lb);

    return (index);

}

void
lfib_entry_path_add2 (fib_node_index_t lfei,
                      const fib_route_path_t *paths)
{
    ASSERT(!"NOT DONE YET");
}


void
lfib_entry_update_from_ip_fib_entry (fib_node_index_t lfei)
{
    lfib_entry_t *lfe;

    lfe = lfib_entry_get(lfei);

    fib_path_list_child_remove(lfe->lfe_parent,
			       lfe->lfe_sibling);

    lfe->lfe_parent = fib_entry_get_path_list(lfe->ip.lfe_ip_entry);
    lfe->lfe_sibling = fib_path_list_child_add(lfe->lfe_parent,
					       FIB_NODE_TYPE_MPLS_ENTRY,
					       lfib_entry_get_index(lfe));

    fib_entry_contribute_forwarding(lfe->ip.lfe_ip_entry,
				    (lfe->lfe_eos & MPLS_EOS ?
				     FIB_FORW_CHAIN_TYPE_MPLS_EOS :
				     FIB_FORW_CHAIN_TYPE_MPLS_NON_EOS),
				    &lfe->lfe_lb);

    lfib_forwarding_table_update(lfe->lfe_fib_index,
				 lfe->lfe_label,
				 lfe->lfe_eos,
				 &lfe->lfe_lb);
}

fib_node_index_t
lfib_entry_special_create (fib_node_index_t lfib_index,
                           mpls_label_t label,
                           mpls_eos_bit_t eos,
                           const dpo_id_t *dpo)
{
    fib_node_index_t index;
    lfib_entry_t *lfe;

    lfe = lfib_entry_alloc(lfib_index, label, eos, &index);

    lfe->lfe_parent = FIB_NODE_INDEX_INVALID;

    /*
     * the client will provide the DPO of its choice. But the
     * lfib result must be a load-balance. create if needed.
     */
    if (DPO_LOAD_BALANCE != dpo->dpoi_type)
    {
	index_t lbi;

	// FIXME
	lbi = load_balance_create(1, DPO_PROTO_MPLS, 0);
	load_balance_set_bucket(lbi, 0, dpo);

	dpo_set(&lfe->lfe_lb, DPO_LOAD_BALANCE, 0, lbi);
    }
    else
    {
	dpo_copy(&lfe->lfe_lb, dpo);
    }

    lfib_forwarding_table_update(lfib_index, label, eos, &lfe->lfe_lb);

    return (index);
}

static lfib_entry_t*
lfib_entry_from_fib_node (fib_node_t *node)
{
#if CLIB_DEBUG > 0
    ASSERT(FIB_NODE_TYPE_MPLS_ENTRY == node->fn_type);
#endif
    return ((lfib_entry_t*)node);
}

static void
lfib_entry_last_lock_gone (fib_node_t *node)
{
    lfib_entry_t *lfe;

    lfe = lfib_entry_from_fib_node(node);

    if (FIB_NODE_INDEX_INVALID != lfe->lfe_parent)
    {
        fib_path_list_child_remove(lfe->lfe_parent,
                                   lfe->lfe_sibling);
    }
    lfe->lfe_parent = FIB_NODE_INDEX_INVALID;

    lfib_forwarding_table_reset(lfe->lfe_fib_index,
				lfe->lfe_label,
                                lfe->lfe_eos);

    dpo_reset(&lfe->lfe_lb);

    fib_node_deinit(&lfe->lfe_node);
    pool_put(lfib_entry_pool, lfe);
}

mpls_label_t 
lfib_entry_get_key (fib_node_index_t lfei)
{
    lfib_entry_t *lfe;

    lfe = lfib_entry_get(lfei);

    return (lfib_entry_mk_key(lfe->lfe_label, lfe->lfe_eos));
}

u32
lfib_entry_get_fib_index (fib_node_index_t lfei)
{
    lfib_entry_t *lfe;

    lfe = lfib_entry_get(lfei);

    return (lfe->lfe_fib_index);
}


const dpo_id_t *
lfib_entry_contribute_forwarding (fib_node_index_t lfei)
{
    lfib_entry_t *lfe;

    lfe = lfib_entry_get(lfei);

    return (&lfe->lfe_lb);
}

/*
 * lfib_entry_back_walk_notify
 *
 * A back walk has reach this entry.
 */
static fib_node_back_walk_rc_t
lfib_entry_back_walk_notify (fib_node_t *node,
			    fib_node_back_walk_ctx_t *ctx)
{
    return (FIB_NODE_BACK_WALK_CONTINUE);
}

static fib_node_t*
lfib_entry_get_node (fib_node_index_t lfei)
{
    lfib_entry_t *lfe;

    lfe = lfib_entry_get(lfei);

    return (&lfe->lfe_node);
}

/*
 * The FIB path-list's graph node virtual function table
 */
static const fib_node_vft_t lfib_entry_vft = {
    .fnv_get = lfib_entry_get_node,
    .fnv_last_lock = lfib_entry_last_lock_gone,
    .fnv_back_walk = lfib_entry_back_walk_notify,
};

static clib_error_t *
lfib_entry_module_init (vlib_main_t *vm)
{
    fib_node_register_type (FIB_NODE_TYPE_MPLS_ENTRY, &lfib_entry_vft);

    return (NULL);
}

VLIB_INIT_FUNCTION(lfib_entry_module_init)
