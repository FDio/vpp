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

#include <vnet/adj/adj.h>
#include <vnet/dpo/load_balance.h>
#include <vnet/dpo/mpls_label_dpo.h>
#include <vnet/dpo/drop_dpo.h>
#include <vnet/dpo/replicate_dpo.h>

#include <vnet/fib/fib_entry_src.h>
#include <vnet/fib/fib_table.h>
#include <vnet/fib/fib_path_ext.h>
#include <vnet/fib/fib_urpf_list.h>
#include <vnet/fib/fib_entry_delegate.h>

/*
 * per-source type vft
 */
static fib_entry_src_vft_t fib_entry_src_bh_vft[FIB_SOURCE_BH_MAX];

/**
 * Get the VFT for a given source. This is a combination of the source
 * enum and the interposer flags
 */
const fib_entry_src_vft_t*
fib_entry_src_get_vft (const fib_entry_src_t *esrc)
{
    fib_source_behaviour_t bh;

    bh = fib_source_get_behaviour(esrc->fes_src);

    if (esrc->fes_entry_flags & FIB_ENTRY_FLAG_INTERPOSE)
    {
        return (&fib_entry_src_bh_vft[FIB_SOURCE_BH_INTERPOSE]);
    }

    return (&fib_entry_src_bh_vft[bh]);
}

static void
fib_entry_src_copy_default (const fib_entry_src_t *orig_src,
                            const fib_entry_t *fib_entry,
                            fib_entry_src_t *copy_src)
{
    clib_memcpy(&copy_src->u, &orig_src->u, sizeof(copy_src->u));
}

void
fib_entry_src_behaviour_register (fib_source_behaviour_t bh,
                                  const fib_entry_src_vft_t *vft)
{
    fib_entry_src_bh_vft[bh] = *vft;

    if (NULL == fib_entry_src_bh_vft[bh].fesv_copy)
    {
        fib_entry_src_bh_vft[bh].fesv_copy = fib_entry_src_copy_default;
    }
}

static int
fib_entry_src_cmp_for_sort (void * v1,
			    void * v2)
{
    fib_entry_src_t *esrc1 = v1, *esrc2 = v2;

    return (fib_source_get_prio(esrc1->fes_src) -
            fib_source_get_prio(esrc2->fes_src));
}

static void
fib_entry_src_action_init (fib_entry_t *fib_entry,
			   fib_source_t source,
                           fib_entry_flag_t flags)
{
    fib_entry_src_t esrc = {
	.fes_pl = FIB_NODE_INDEX_INVALID,
	.fes_flags = FIB_ENTRY_SRC_FLAG_NONE,
	.fes_src = source,
        .fes_entry_flags = flags,
    };

    FIB_ENTRY_SRC_VFT_INVOKE(fib_entry, &esrc, fesv_init, (&esrc));

    vec_add1(fib_entry->fe_srcs, esrc);
    vec_sort_with_function(fib_entry->fe_srcs,
			   fib_entry_src_cmp_for_sort);
}

static fib_entry_src_t *
fib_entry_src_find_i (const fib_entry_t *fib_entry,
                      fib_source_t source,
                      u32 *index)

{
    fib_entry_src_t *esrc;
    int ii;

    ii = 0;
    vec_foreach(esrc, fib_entry->fe_srcs)
    {
	if (esrc->fes_src == source)
	{
	    if (NULL != index)
	    {
		*index = ii;
	    }
	    return (esrc);
	}
	else
	{
	    ii++;
	}
    }

    return (NULL);
}

fib_entry_src_t *
fib_entry_src_find (const fib_entry_t *fib_entry,
		    fib_source_t source)

{
    return (fib_entry_src_find_i(fib_entry, source, NULL));
}

int
fib_entry_is_sourced (fib_node_index_t fib_entry_index,
                      fib_source_t source)
{
    fib_entry_t *fib_entry;

    fib_entry = fib_entry_get(fib_entry_index);

    return (NULL != fib_entry_src_find(fib_entry, source));
}

int
fib_entry_is_marked (fib_node_index_t fib_entry_index,
                      fib_source_t source)
{
    fib_entry_t *fib_entry;
    fib_entry_src_t *esrc;

    fib_entry = fib_entry_get(fib_entry_index);

    esrc = fib_entry_src_find(fib_entry, source);

    if (NULL == esrc)
    {
        return (0);
    }
    else
    {
        return (!!(esrc->fes_flags & FIB_ENTRY_SRC_FLAG_STALE));
    }
}

void
fib_entry_mark (fib_node_index_t fib_entry_index,
                fib_source_t source)
{
    fib_entry_t *fib_entry;
    fib_entry_src_t *esrc;

    fib_entry = fib_entry_get(fib_entry_index);

    esrc = fib_entry_src_find(fib_entry, source);

    if (NULL != esrc)
    {
        esrc->fes_flags |= FIB_ENTRY_SRC_FLAG_STALE;
    }
}

static fib_entry_src_t *
fib_entry_src_find_or_create (fib_entry_t *fib_entry,
			      fib_source_t source,
                              fib_entry_flag_t flags)
{
    fib_entry_src_t *esrc;

    esrc = fib_entry_src_find(fib_entry, source);

    if (NULL == esrc)
    {
	fib_entry_src_action_init(fib_entry, source, flags);
    }

    return (fib_entry_src_find(fib_entry, source));
}

static void
fib_entry_src_action_deinit (fib_entry_t *fib_entry,
			     fib_source_t source)

{
    fib_entry_src_t *esrc;
    u32 index = ~0;

    esrc = fib_entry_src_find_i(fib_entry, source, &index);

    ASSERT(NULL != esrc);

    FIB_ENTRY_SRC_VFT_INVOKE(fib_entry, esrc, fesv_deinit, (esrc));

    fib_path_ext_list_flush(&esrc->fes_path_exts);
    vec_del1(fib_entry->fe_srcs, index);
    vec_sort_with_function(fib_entry->fe_srcs,
			   fib_entry_src_cmp_for_sort);
}

fib_entry_src_cover_res_t
fib_entry_src_action_cover_change (fib_entry_t *fib_entry,
                                   fib_entry_src_t *esrc)
{
    FIB_ENTRY_SRC_VFT_INVOKE_AND_RETURN(esrc, fesv_cover_change,
                                        (esrc, fib_entry));

    fib_entry_src_cover_res_t res = {
	.install = !0,
	.bw_reason = FIB_NODE_BW_REASON_FLAG_NONE,
    };
    return (res);
}

fib_entry_src_cover_res_t
fib_entry_src_action_cover_update (fib_entry_t *fib_entry,
                                   fib_entry_src_t *esrc)
{
    FIB_ENTRY_SRC_VFT_INVOKE_AND_RETURN(esrc, fesv_cover_update,
                                        (esrc, fib_entry));

    fib_entry_src_cover_res_t res = {
	.install = !0,
	.bw_reason = FIB_NODE_BW_REASON_FLAG_NONE,
    };
    return (res);
}

typedef struct fib_entry_src_collect_forwarding_ctx_t_
{
    load_balance_path_t *next_hops;
    const fib_entry_t *fib_entry;
    const fib_entry_src_t *esrc;
    fib_forward_chain_type_t fct;
    int n_recursive_constrained;
    u16 preference;
} fib_entry_src_collect_forwarding_ctx_t;

/**
 * @brief Determine whether this FIB entry should use a load-balance MAP
 * to support PIC edge fast convergence
 */
load_balance_flags_t
fib_entry_calc_lb_flags (fib_entry_src_collect_forwarding_ctx_t *ctx)
{
    /**
     * We'll use a LB map if the path-list has multiple recursive paths.
     * recursive paths implies BGP, and hence scale.
     */
    if (ctx->n_recursive_constrained > 1 &&
        fib_path_list_is_popular(ctx->esrc->fes_pl))
    {
        return (LOAD_BALANCE_FLAG_USES_MAP);
    }
    return (LOAD_BALANCE_FLAG_NONE);
}

static int
fib_entry_src_valid_out_label (mpls_label_t label)
{
    return ((MPLS_LABEL_IS_REAL(label) ||
             MPLS_LABEL_POP == label ||
             MPLS_IETF_IPV4_EXPLICIT_NULL_LABEL == label ||
             MPLS_IETF_IPV6_EXPLICIT_NULL_LABEL == label ||
             MPLS_IETF_IMPLICIT_NULL_LABEL == label));
}

/**
 * @brief Turn the chain type requested by the client into the one they
 * really wanted
 */
fib_forward_chain_type_t
fib_entry_chain_type_fixup (const fib_entry_t *entry,
			    fib_forward_chain_type_t fct)
{
    /*
     * The EOS chain is a tricky since one cannot know the adjacency
     * to link to without knowing what the packets payload protocol
     * will be once the label is popped.
     */
    fib_forward_chain_type_t dfct;

    if (FIB_FORW_CHAIN_TYPE_MPLS_EOS != fct)
    {
        return (fct);
    }

    dfct = fib_entry_get_default_chain_type(entry);

    if (FIB_FORW_CHAIN_TYPE_MPLS_EOS == dfct)
    {
        /*
         * If the entry being asked is a eos-MPLS label entry,
         * then use the payload-protocol field, that we stashed there
         * for just this purpose
         */
        return (fib_forw_chain_type_from_dpo_proto(
                    entry->fe_prefix.fp_payload_proto));
    }
    /*
     * else give them what this entry would be by default. i.e. if it's a v6
     * entry, then the label its local labelled should be carrying v6 traffic.
     * If it's a non-EOS label entry, then there are more labels and we want
     * a non-eos chain.
     */
    return (dfct);
}

static dpo_proto_t
fib_prefix_get_payload_proto (const fib_prefix_t *pfx)
{
    switch (pfx->fp_proto)
    {
    case FIB_PROTOCOL_IP4:
        return (DPO_PROTO_IP4);
    case FIB_PROTOCOL_IP6:
        return (DPO_PROTO_IP6);
    case FIB_PROTOCOL_MPLS:
        return (pfx->fp_payload_proto);
    }

    ASSERT(0);
    return (DPO_PROTO_IP4);
}

static void
fib_entry_src_get_path_forwarding (fib_node_index_t path_index,
                                   fib_entry_src_collect_forwarding_ctx_t *ctx)
{
    load_balance_path_t *nh;

    /*
     * no extension => no out-going label for this path. that's OK
     * in the case of an IP or EOS chain, but not for non-EOS
     */
    switch (ctx->fct)
    {
    case FIB_FORW_CHAIN_TYPE_UNICAST_IP4:
    case FIB_FORW_CHAIN_TYPE_UNICAST_IP6:
    case FIB_FORW_CHAIN_TYPE_MCAST_IP4:
    case FIB_FORW_CHAIN_TYPE_MCAST_IP6:
    case FIB_FORW_CHAIN_TYPE_BIER:
        /*
         * EOS traffic with no label to stack, we need the IP Adj
         */
        vec_add2(ctx->next_hops, nh, 1);

        nh->path_index = path_index;
        nh->path_weight = fib_path_get_weight(path_index);
        fib_path_contribute_forwarding(path_index, ctx->fct, &nh->path_dpo);

        break;
    case FIB_FORW_CHAIN_TYPE_MPLS_NON_EOS:
        if (fib_path_is_exclusive(path_index) ||
            fib_path_is_deag(path_index))
        {
            vec_add2(ctx->next_hops, nh, 1);

            nh->path_index = path_index;
            nh->path_weight = fib_path_get_weight(path_index);
            fib_path_contribute_forwarding(path_index,
                                           FIB_FORW_CHAIN_TYPE_MPLS_NON_EOS,
                                           &nh->path_dpo);
        }
        break;
    case FIB_FORW_CHAIN_TYPE_MPLS_EOS:
        {
            /*
             * no label. we need a chain based on the payload. fixup.
             */
            vec_add2(ctx->next_hops, nh, 1);

            nh->path_index = path_index;
            nh->path_weight = fib_path_get_weight(path_index);
            fib_path_contribute_forwarding(path_index,
                                           fib_entry_chain_type_fixup(ctx->fib_entry,
                                                                      ctx->fct),
                                           &nh->path_dpo);
            fib_path_stack_mpls_disp(path_index,
                                     fib_prefix_get_payload_proto(&ctx->fib_entry->fe_prefix),
                                     FIB_MPLS_LSP_MODE_PIPE,
                                     &nh->path_dpo);

            break;
        }
    case FIB_FORW_CHAIN_TYPE_ETHERNET:
    case FIB_FORW_CHAIN_TYPE_NSH:
        ASSERT(0);
        break;
    }
}

static fib_path_list_walk_rc_t
fib_entry_src_collect_forwarding (fib_node_index_t pl_index,
                                  fib_node_index_t path_index,
                                  void *arg)
{
    fib_entry_src_collect_forwarding_ctx_t *ctx;
    fib_path_ext_t *path_ext;
    u32 n_nhs;

    ctx = arg;
    n_nhs = vec_len(ctx->next_hops);

    /*
     * if the path is not resolved, don't include it.
     */
    if (!fib_path_is_resolved(path_index))
    {
        return (FIB_PATH_LIST_WALK_CONTINUE);
    }

    if (fib_path_is_recursive_constrained(path_index))
    {
        ctx->n_recursive_constrained += 1;
    }
    if (0xffff == ctx->preference)
    {
        /*
         * not set a preference yet, so the first path we encounter
         * sets the preference we are collecting.
         */
        ctx->preference = fib_path_get_preference(path_index);
    }
    else if (ctx->preference != fib_path_get_preference(path_index))
    {
        /*
         * this path does not belong to the same preference as the
         * previous paths encountered. we are done now.
         */
        return (FIB_PATH_LIST_WALK_STOP);
    }

    /*
     * get the matching path-extension for the path being visited.
     */
    path_ext = fib_path_ext_list_find_by_path_index(&ctx->esrc->fes_path_exts,
                                                    path_index);

    if (NULL != path_ext)
    {
        switch (path_ext->fpe_type)
        {
        case FIB_PATH_EXT_MPLS:
            if (fib_entry_src_valid_out_label(path_ext->fpe_label_stack[0].fml_value))
            {
                /*
                 * found a matching extension. stack it to obtain the forwarding
                 * info for this path.
                 */
                ctx->next_hops =
                    fib_path_ext_stack(path_ext,
                                       ctx->fct,
                                       fib_entry_chain_type_fixup(ctx->fib_entry,
                                                                  ctx->fct),
                                       ctx->next_hops);
            }
            else
            {
                fib_entry_src_get_path_forwarding(path_index, ctx);
            }
            break;
        case FIB_PATH_EXT_ADJ:
            if (FIB_PATH_EXT_ADJ_FLAG_REFINES_COVER & path_ext->fpe_adj_flags)
            {
                fib_entry_src_get_path_forwarding(path_index, ctx);
            }
            /*
             * else
             *  the path does not refine the cover, meaning that
             *  the adjacency does/does not match the sub-net on the link.
             *  So this path does not contribute forwarding.
             */
            break;
        }
    }
    else
    {
        fib_entry_src_get_path_forwarding(path_index, ctx);
    }

    /*
     * a this point 'ctx' has the DPO the path contributed, plus
     * any labels from path extensions.
     * check if there are any interpose sources that want to contribute
     */
    if (n_nhs < vec_len(ctx->next_hops))
    {
        /*
         * the path contributed a new choice.
         */
        const fib_entry_src_vft_t *vft;

        vft = fib_entry_src_get_vft(ctx->esrc);

        if (NULL != vft->fesv_contribute_interpose)
        {
            const dpo_id_t *interposer;

            interposer = vft->fesv_contribute_interpose(ctx->esrc,
                                                        ctx->fib_entry);

            if (NULL != interposer)
            {
                dpo_id_t clone = DPO_INVALID;

                dpo_mk_interpose(interposer,
                                 &ctx->next_hops[n_nhs].path_dpo,
                                 &clone);

                dpo_copy(&ctx->next_hops[n_nhs].path_dpo, &clone);
                dpo_reset(&clone);
            }
        }
    }

    return (FIB_PATH_LIST_WALK_CONTINUE);
}

void
fib_entry_src_mk_lb (fib_entry_t *fib_entry,
		     const fib_entry_src_t *esrc,
		     fib_forward_chain_type_t fct,
		     dpo_id_t *dpo_lb)
{
    dpo_proto_t lb_proto;

    /*
     * If the entry has path extensions then we construct a load-balance
     * by stacking the extensions on the forwarding chains of the paths.
     * Otherwise we use the load-balance of the path-list
     */
    fib_entry_src_collect_forwarding_ctx_t ctx = {
        .esrc = esrc,
        .fib_entry = fib_entry,
        .next_hops = NULL,
        .n_recursive_constrained = 0,
        .fct = fct,
        .preference = 0xffff,
    };

    /*
     * As an optimisation we allocate the vector of next-hops to be sized
     * equal to the maximum number of paths we will need, which is also the
     * most likely number we will need, since in most cases the paths are 'up'.
     */
    vec_validate(ctx.next_hops, fib_path_list_get_n_paths(esrc->fes_pl));
    vec_reset_length(ctx.next_hops);

    lb_proto = fib_forw_chain_type_to_dpo_proto(fct);

    fib_path_list_walk(esrc->fes_pl,
                       fib_entry_src_collect_forwarding,
                       &ctx);

    if (esrc->fes_entry_flags & FIB_ENTRY_FLAG_EXCLUSIVE)
    {
	/*
	 * the client provided the DPO that the entry should link to.
	 * all entries must link to a LB, so if it is an LB already
	 * then we can use it.
	 */
	if ((1 == vec_len(ctx.next_hops)) &&
	    (DPO_LOAD_BALANCE == ctx.next_hops[0].path_dpo.dpoi_type))
	{
	    dpo_copy(dpo_lb, &ctx.next_hops[0].path_dpo);
	    dpo_reset(&ctx.next_hops[0].path_dpo);
	    return;
	}
    }

    if (!dpo_id_is_valid(dpo_lb))
    {
        /*
         * first time create
         */
        if (esrc->fes_entry_flags & FIB_ENTRY_FLAG_MULTICAST)
        {
            dpo_set(dpo_lb,
                    DPO_REPLICATE,
                    lb_proto,
                    MPLS_IS_REPLICATE | replicate_create(0, lb_proto));
        }
        else
        {
            fib_protocol_t flow_hash_proto;
            flow_hash_config_t fhc;

            /*
             * if the protocol for the LB we are building does not match that
             * of the fib_entry (i.e. we are build the [n]EOS LB for an IPv[46]
             * then the fib_index is not an index that relates to the table
             * type we need. So get the default flow-hash config instead.
             */
            flow_hash_proto = dpo_proto_to_fib(lb_proto);
            if (fib_entry->fe_prefix.fp_proto != flow_hash_proto)
            {
                fhc = fib_table_get_default_flow_hash_config(flow_hash_proto);
            }
            else
            {
                fhc = fib_table_get_flow_hash_config(fib_entry->fe_fib_index,
                                                     flow_hash_proto);
            }

            dpo_set(dpo_lb,
                    DPO_LOAD_BALANCE,
                    lb_proto,
                    load_balance_create(0, lb_proto, fhc));
        }
    }

    if (esrc->fes_entry_flags & FIB_ENTRY_FLAG_MULTICAST)
    {
        /*
         * MPLS multicast
         */
        replicate_multipath_update(dpo_lb, ctx.next_hops);
    }
    else
    {
        load_balance_multipath_update(dpo_lb,
                                      ctx.next_hops,
                                      fib_entry_calc_lb_flags(&ctx));
        vec_free(ctx.next_hops);

        /*
         * if this entry is sourced by the uRPF-exempt source then we
         * append the always present local0 interface (index 0) to the
         * uRPF list so it is not empty. that way packets pass the loose check.
         */
        index_t ui = fib_path_list_get_urpf(esrc->fes_pl);

        if ((fib_entry_is_sourced(fib_entry_get_index(fib_entry),
                                  FIB_SOURCE_URPF_EXEMPT) ||
             (esrc->fes_entry_flags & FIB_ENTRY_FLAG_LOOSE_URPF_EXEMPT))&&
            (0 == fib_urpf_check_size(ui)))
        {
            /*
             * The uRPF list we get from the path-list is shared by all
             * other users of the list, but the uRPF exemption applies
             * only to this prefix. So we need our own list.
             */
            ui = fib_urpf_list_alloc_and_lock();
            fib_urpf_list_append(ui, 0);
            fib_urpf_list_bake(ui);
            load_balance_set_urpf(dpo_lb->dpoi_index, ui);
            fib_urpf_list_unlock(ui);
        }
        else
        {
            load_balance_set_urpf(dpo_lb->dpoi_index, ui);
        }
        load_balance_set_fib_entry_flags(dpo_lb->dpoi_index,
                                         fib_entry_get_flags_i(fib_entry));
    }
}

void
fib_entry_src_action_install (fib_entry_t *fib_entry,
			      fib_source_t source)
{
    /*
     * Install the forwarding chain for the given source into the forwarding
     * tables
     */
    fib_forward_chain_type_t fct;
    fib_entry_src_t *esrc;
    int insert;

    fct = fib_entry_get_default_chain_type(fib_entry);
    esrc = fib_entry_src_find(fib_entry, source);

    /*
     * Every entry has its own load-balance object. All changes to the entry's
     * forwarding result in an inplace modify of the load-balance. This means
     * the load-balance object only needs to be added to the forwarding
     * DB once, when it is created.
     */
    insert = !dpo_id_is_valid(&fib_entry->fe_lb);

    fib_entry_src_mk_lb(fib_entry, esrc, fct, &fib_entry->fe_lb);

    ASSERT(dpo_id_is_valid(&fib_entry->fe_lb));
    FIB_ENTRY_DBG(fib_entry, "install: %d", fib_entry->fe_lb);

    /*
     * insert the adj into the data-plane forwarding trie
     */
    if (insert)
    {
       fib_table_fwding_dpo_update(fib_entry->fe_fib_index,
                                   &fib_entry->fe_prefix,
                                   &fib_entry->fe_lb);
    }

    /*
     * if any of the other chain types are already created they will need
     * updating too
     */
    fib_entry_delegate_type_t fdt;
    fib_entry_delegate_t *fed;

    FOR_EACH_DELEGATE_CHAIN(fib_entry, fdt, fed,
    {
        fib_entry_src_mk_lb(fib_entry, esrc,
                            fib_entry_delegate_type_to_chain_type(fdt),
                            &fed->fd_dpo);
    });
}

void
fib_entry_src_action_uninstall (fib_entry_t *fib_entry)
{
    /*
     * uninstall the forwarding chain from the forwarding tables
     */
    FIB_ENTRY_DBG(fib_entry, "uninstall");

    if (dpo_id_is_valid(&fib_entry->fe_lb))
    {
	fib_table_fwding_dpo_remove(
	    fib_entry->fe_fib_index,
	    &fib_entry->fe_prefix,
	    &fib_entry->fe_lb);

	dpo_reset(&fib_entry->fe_lb);
    }
}

static void
fib_entry_recursive_loop_detect_i (fib_node_index_t path_list_index)
{
    fib_node_index_t *entries = NULL;

    fib_path_list_recursive_loop_detect(path_list_index, &entries);

    vec_free(entries);
}

/*
 * fib_entry_src_action_copy
 *
 * copy a source data from another entry to this one
 */
static fib_entry_t *
fib_entry_src_action_copy (fib_entry_t *fib_entry,
                           const fib_entry_src_t *orig_src)
{
    fib_entry_src_t *esrc;

    esrc = fib_entry_src_find_or_create(fib_entry,
                                        orig_src->fes_src,
                                        orig_src->fes_entry_flags);

    FIB_ENTRY_SRC_VFT_INVOKE(fib_entry, esrc, fesv_copy,
                             (orig_src, fib_entry, esrc));

    fib_path_list_unlock(esrc->fes_pl);

    /*
     * copy over all the data ...
     */
    esrc->fes_flags = orig_src->fes_flags;
    esrc->fes_pl = orig_src->fes_pl;

    /*
     *  ... then update
     */
    esrc->fes_ref_count = 1;
    esrc->fes_flags |= FIB_ENTRY_SRC_FLAG_INHERITED;
    esrc->fes_flags &= ~(FIB_ENTRY_SRC_FLAG_ACTIVE |
                         FIB_ENTRY_SRC_FLAG_CONTRIBUTING);
    esrc->fes_entry_flags &= ~FIB_ENTRY_FLAG_COVERED_INHERIT;

    /*
     * the source owns a lock on the entry
     */
    fib_path_list_lock(esrc->fes_pl);
    fib_entry_lock(fib_entry_get_index(fib_entry));

    return (fib_entry);
}

/*
 * fib_entry_src_action_update
 *
 * copy a source data from another entry to this one
 */
static fib_entry_src_t *
fib_entry_src_action_update_from_cover (fib_entry_t *fib_entry,
                                        const fib_entry_src_t *orig_src)
{
    fib_entry_src_t *esrc;

    esrc = fib_entry_src_find_or_create(fib_entry,
                                        orig_src->fes_src,
                                        orig_src->fes_entry_flags);

    /*
     * the source owns a lock on the entry
     */
    fib_path_list_unlock(esrc->fes_pl);
    esrc->fes_pl = orig_src->fes_pl;
    fib_path_list_lock(esrc->fes_pl);

    return (esrc);
}

static fib_table_walk_rc_t
fib_entry_src_covered_inherit_add_i (fib_entry_t *fib_entry,
                                     const fib_entry_src_t *cover_src)
{
    fib_entry_src_t *esrc;

    esrc = fib_entry_src_find(fib_entry, cover_src->fes_src);

    if (cover_src == esrc)
    {
        return (FIB_TABLE_WALK_CONTINUE);
    }

    if (NULL != esrc)
    {
        /*
         * the covered entry already has this source.
         */
        if (esrc->fes_entry_flags & FIB_ENTRY_FLAG_COVERED_INHERIT)
        {
            /*
             * the covered source is itself a COVERED_INHERIT, i.e.
             * it also pushes this source down the sub-tree.
             * We consider this more specific covered to be the owner
             * of the sub-tree from this point down.
             */
            return (FIB_TABLE_WALK_SUB_TREE_STOP);
        }
        if (esrc->fes_flags & FIB_ENTRY_SRC_FLAG_INHERITED)
        {
            /*
             * The covered's source data has been inherited, presumably
             * from this cover, i.e. this is a modify.
             */
            esrc = fib_entry_src_action_update_from_cover(fib_entry, cover_src);
            fib_entry_source_change(fib_entry, esrc->fes_src, esrc->fes_src);
        }
        else
        {
            /*
             * The covered's source was not inherited and it is also
             * not inheriting. Nevertheless, it still owns the sub-tree from
             * this point down.
             */
            return (FIB_TABLE_WALK_SUB_TREE_STOP);
        }
    }
    else
    {
        /*
         * The covered does not have this source - add it.
         */
        fib_source_t best_source;

        best_source = fib_entry_get_best_source(
            fib_entry_get_index(fib_entry));

        fib_entry_src_action_copy(fib_entry, cover_src);
        fib_entry_source_change(fib_entry, best_source, cover_src->fes_src);

    }
    return (FIB_TABLE_WALK_CONTINUE);
}

static fib_table_walk_rc_t
fib_entry_src_covered_inherit_walk_add (fib_node_index_t fei,
                                        void *ctx)
{
    return (fib_entry_src_covered_inherit_add_i(fib_entry_get(fei), ctx));
}

static fib_table_walk_rc_t
fib_entry_src_covered_inherit_walk_remove (fib_node_index_t fei,
                                           void *ctx)
{
    fib_entry_src_t *cover_src, *esrc;
    fib_entry_t *fib_entry;

    fib_entry = fib_entry_get(fei);

    cover_src = ctx;
    esrc = fib_entry_src_find(fib_entry, cover_src->fes_src);

    if (cover_src == esrc)
    {
        return (FIB_TABLE_WALK_CONTINUE);
    }

    if (NULL != esrc)
    {
        /*
         * the covered entry already has this source.
         */
        if (esrc->fes_entry_flags & FIB_ENTRY_FLAG_COVERED_INHERIT)
        {
            /*
             * the covered source is itself a COVERED_INHERIT, i.e.
             * it also pushes this source down the sub-tree.
             * We consider this more specific covered to be the owner
             * of the sub-tree from this point down.
             */
            return (FIB_TABLE_WALK_SUB_TREE_STOP);
        }
        if (esrc->fes_flags & FIB_ENTRY_SRC_FLAG_INHERITED)
        {
            /*
             * The covered's source data has been inherited, presumably
             * from this cover
             */
            fib_entry_src_flag_t remaining;

            remaining = fib_entry_special_remove(fei, cover_src->fes_src);

            ASSERT(FIB_ENTRY_SRC_FLAG_ADDED == remaining);
        }
        else
        {
            /*
             * The covered's source was not inherited and it is also
             * not inheriting. Nevertheless, it still owns the sub-tree from
             * this point down.
             */
            return (FIB_TABLE_WALK_SUB_TREE_STOP);
        }
    }
    else
    {
        /*
         * The covered does not have this source - that's an error,
         * since it should have inherited, but there is nothing we can do
         * about it now.
         */
    }
    return (FIB_TABLE_WALK_CONTINUE);
}

void
fib_entry_src_inherit (const fib_entry_t *cover,
                       fib_entry_t *covered)
{
    CLIB_UNUSED(fib_source_t source);
    const fib_entry_src_t *src;

    FOR_EACH_SRC_ADDED(cover, src, source,
    ({
        if ((src->fes_entry_flags & FIB_ENTRY_FLAG_COVERED_INHERIT) ||
            (src->fes_flags & FIB_ENTRY_SRC_FLAG_INHERITED))
        {
            fib_entry_src_covered_inherit_add_i(covered, src);
        }
    }))
}

static void
fib_entry_src_covered_inherit_add (fib_entry_t *fib_entry,
                                   fib_source_t source)

{
    fib_entry_src_t *esrc;

    esrc = fib_entry_src_find(fib_entry, source);

    ASSERT(esrc->fes_flags & FIB_ENTRY_SRC_FLAG_ACTIVE);

    if ((esrc->fes_entry_flags & FIB_ENTRY_FLAG_COVERED_INHERIT) ||
        (esrc->fes_flags & FIB_ENTRY_SRC_FLAG_INHERITED))
    {
        fib_table_sub_tree_walk(fib_entry->fe_fib_index,
                                fib_entry->fe_prefix.fp_proto,
                                &fib_entry->fe_prefix,
                                fib_entry_src_covered_inherit_walk_add,
                                esrc);
    }
}

static void
fib_entry_src_covered_inherit_remove (fib_entry_t *fib_entry,
                                      fib_entry_src_t *esrc)

{
    ASSERT(!(esrc->fes_flags & FIB_ENTRY_SRC_FLAG_ACTIVE));

    if (esrc->fes_entry_flags & FIB_ENTRY_FLAG_COVERED_INHERIT)
    {
        fib_table_sub_tree_walk(fib_entry->fe_fib_index,
                                fib_entry->fe_prefix.fp_proto,
                                &fib_entry->fe_prefix,
                                fib_entry_src_covered_inherit_walk_remove,
                                esrc);
    }
}

void
fib_entry_src_action_activate (fib_entry_t *fib_entry,
			       fib_source_t source)

{
    int houston_we_are_go_for_install;
    const fib_entry_src_vft_t *vft;
    fib_entry_src_t *esrc;

    esrc = fib_entry_src_find(fib_entry, source);

    ASSERT(!(esrc->fes_flags & FIB_ENTRY_SRC_FLAG_ACTIVE));
    ASSERT(esrc->fes_flags & FIB_ENTRY_SRC_FLAG_ADDED);

    esrc->fes_flags |= (FIB_ENTRY_SRC_FLAG_ACTIVE |
                        FIB_ENTRY_SRC_FLAG_CONTRIBUTING);
    vft = fib_entry_src_get_vft(esrc);

    if (NULL != vft->fesv_activate)
    {
	houston_we_are_go_for_install = vft->fesv_activate(esrc, fib_entry);
    }
    else
    {
	/*
	 * the source is not providing an activate function, we'll assume
	 * therefore it has no objection to installing the entry
	 */
	houston_we_are_go_for_install = !0;
    }

    /*
     * link to the path-list provided by the source, and go check
     * if that forms any loops in the graph.
     */
    fib_entry->fe_parent = esrc->fes_pl;
    fib_entry->fe_sibling =
	fib_path_list_child_add(fib_entry->fe_parent,
				FIB_NODE_TYPE_ENTRY,
				fib_entry_get_index(fib_entry));

    fib_entry_recursive_loop_detect_i(fib_entry->fe_parent);

    FIB_ENTRY_DBG(fib_entry, "activate: %d",
		  fib_entry->fe_parent);

    /*
     * If this source should push its state to covered prefixs, do that now.
     */
    fib_entry_src_covered_inherit_add(fib_entry, source);

    if (0 != houston_we_are_go_for_install)
    {
	fib_entry_src_action_install(fib_entry, source);
    }
    else
    {
	fib_entry_src_action_uninstall(fib_entry);
    }
}

void
fib_entry_src_action_deactivate (fib_entry_t *fib_entry,
				 fib_source_t source)

{
    fib_node_index_t path_list_index;
    fib_entry_src_t *esrc;

    esrc = fib_entry_src_find(fib_entry, source);

    ASSERT(esrc->fes_flags & FIB_ENTRY_SRC_FLAG_ACTIVE);

    FIB_ENTRY_SRC_VFT_INVOKE(fib_entry, esrc, fesv_deactivate,
                             (esrc, fib_entry));

    esrc->fes_flags &= ~(FIB_ENTRY_SRC_FLAG_ACTIVE |
                         FIB_ENTRY_SRC_FLAG_CONTRIBUTING);

    FIB_ENTRY_DBG(fib_entry, "deactivate: %d", fib_entry->fe_parent);

    /*
     * If this source should pull its state from covered prefixs, do that now.
     * If this source also has the INHERITED flag set then it has a cover
     * that wants to push down forwarding. We only want the covereds to see
     * one update.
     */
    fib_entry_src_covered_inherit_remove(fib_entry, esrc);

    /*
     * un-link from an old path-list. Check for any loops this will clear
     */
    path_list_index = fib_entry->fe_parent;
    fib_entry->fe_parent = FIB_NODE_INDEX_INVALID;

    fib_entry_recursive_loop_detect_i(path_list_index);

    /*
     * this will unlock the path-list, so it may be invalid thereafter.
     */
    fib_path_list_child_remove(path_list_index, fib_entry->fe_sibling);
    fib_entry->fe_sibling = FIB_NODE_INDEX_INVALID;
}

static void
fib_entry_src_action_fwd_update (const fib_entry_t *fib_entry,
				 fib_source_t source)
{
    fib_entry_src_t *esrc;

    vec_foreach(esrc, fib_entry->fe_srcs)
    {
	FIB_ENTRY_SRC_VFT_INVOKE(fib_entry, esrc, fesv_fwd_update,
                                 (esrc, fib_entry, source));
    }
}

void
fib_entry_src_action_reactivate (fib_entry_t *fib_entry,
				 fib_source_t source)
{
    fib_node_index_t path_list_index;
    const fib_entry_src_vft_t *vft;
    fib_entry_src_t *esrc;
    int remain_installed;

    esrc = fib_entry_src_find(fib_entry, source);

    ASSERT(esrc->fes_flags & FIB_ENTRY_SRC_FLAG_ACTIVE);

    FIB_ENTRY_DBG(fib_entry, "reactivate: %d to %d",
		  fib_entry->fe_parent,
		  esrc->fes_pl);

    /*
     * call the source to reactive and get the go/no-go to remain installed
     */
    vft = fib_entry_src_get_vft(esrc);

    if (NULL != vft->fesv_reactivate)
    {
        remain_installed = vft->fesv_reactivate(esrc, fib_entry);
    }
    else
    {
        remain_installed = 1;
    }

    if (fib_entry->fe_parent != esrc->fes_pl)
    {
	/*
	 * un-link from an old path-list. Check for any loops this will clear
	 */
	path_list_index = fib_entry->fe_parent;
	fib_entry->fe_parent = FIB_NODE_INDEX_INVALID;

	/*
	 * temporary lock so it doesn't get deleted when this entry is no
	 * longer a child.
	 */
	fib_path_list_lock(path_list_index);

	/*
	 * this entry is no longer a child. after unlinking check if any loops
	 * were broken
	 */
	fib_path_list_child_remove(path_list_index,
				   fib_entry->fe_sibling);

	fib_entry_recursive_loop_detect_i(path_list_index);

	/*
	 * link to the path-list provided by the source, and go check
	 * if that forms any loops in the graph.
	 */
	fib_entry->fe_parent = esrc->fes_pl;
	fib_entry->fe_sibling =
	    fib_path_list_child_add(fib_entry->fe_parent,
				    FIB_NODE_TYPE_ENTRY,
				    fib_entry_get_index(fib_entry));

	fib_entry_recursive_loop_detect_i(fib_entry->fe_parent);
	fib_path_list_unlock(path_list_index);

        /*
         * If this source should push its state to covered prefixs, do that now.
         */
        fib_entry_src_covered_inherit_add(fib_entry, source);
    }

    if (!remain_installed)
    {
        fib_entry_src_action_uninstall(fib_entry);
    }
    else
    {
        fib_entry_src_action_install(fib_entry, source);
    }
    fib_entry_src_action_fwd_update(fib_entry, source);
}

fib_entry_t *
fib_entry_src_action_installed (fib_entry_t *fib_entry,
				fib_source_t source)
{
    fib_entry_src_t *esrc;

    esrc = fib_entry_src_find(fib_entry, source);

    FIB_ENTRY_SRC_VFT_INVOKE(fib_entry, esrc, fesv_installed,
                             (esrc, fib_entry));

    fib_entry_src_action_fwd_update(fib_entry, source);

    return (fib_entry);
}

/*
 * fib_entry_src_action_add
 *
 * Adding a source can result in a new fib_entry being created, which
 * can inturn mean the pool is realloc'd and thus the entry passed as
 * an argument it also realloc'd
 * @return the original entry
 */
fib_entry_t *
fib_entry_src_action_add (fib_entry_t *fib_entry,
			  fib_source_t source,
			  fib_entry_flag_t flags,
			  const dpo_id_t *dpo)
{
    fib_entry_src_t *esrc;

    esrc = fib_entry_src_find_or_create(fib_entry, source, flags);

    ASSERT(esrc->fes_ref_count < 255);
    esrc->fes_ref_count++;

    if (flags != esrc->fes_entry_flags)
    {
        FIB_ENTRY_SRC_VFT_INVOKE(fib_entry, esrc, fesv_flags_change,
                                 (esrc, fib_entry, flags));
    }
    esrc->fes_entry_flags = flags;

    if (1 != esrc->fes_ref_count)
    {
        /*
         * we only want to add the source on the 0->1 transition
         */
        return (fib_entry);
    }

    FIB_ENTRY_SRC_VFT_INVOKE(fib_entry, esrc, fesv_add,
                             (esrc,
                              fib_entry,
                              flags,
                              fib_entry_get_dpo_proto(fib_entry),
                              dpo));

    esrc->fes_flags |= FIB_ENTRY_SRC_FLAG_ADDED;

    fib_path_list_lock(esrc->fes_pl);

    /*
     * the source owns a lock on the entry
     */
    fib_entry_lock(fib_entry_get_index(fib_entry));

    return (fib_entry);
}

/*
 * fib_entry_src_action_update
 *
 * Adding a source can result in a new fib_entry being created, which
 * can inturn mean the pool is realloc'd and thus the entry passed as
 * an argument it also realloc'd
 * @return the original entry
 */
fib_entry_t *
fib_entry_src_action_update (fib_entry_t *fib_entry,
			     fib_source_t source,
			     fib_entry_flag_t flags,
			     const dpo_id_t *dpo)
{
    fib_node_index_t old_path_list_index;
    fib_entry_src_t *esrc;

    esrc = fib_entry_src_find_or_create(fib_entry, source, flags);

    if (NULL == esrc)
    {
	return (fib_entry_src_action_add(fib_entry, source, flags, dpo));
    }

    old_path_list_index = esrc->fes_pl;
    esrc->fes_entry_flags = flags;

    FIB_ENTRY_SRC_VFT_INVOKE(fib_entry, esrc, fesv_add,
                             (esrc,
                              fib_entry,
                              flags,
                              fib_entry_get_dpo_proto(fib_entry),
                              dpo));

    esrc->fes_flags |= FIB_ENTRY_SRC_FLAG_ADDED;

    fib_path_list_lock(esrc->fes_pl);
    fib_path_list_unlock(old_path_list_index);

    return (fib_entry);
}

fib_entry_src_flag_t
fib_entry_src_action_remove_or_update_inherit (fib_entry_t *fib_entry,
                                               fib_source_t source)
{
    fib_entry_src_t *esrc;

    esrc = fib_entry_src_find(fib_entry, source);

    if (NULL == esrc)
        return (FIB_ENTRY_SRC_FLAG_ACTIVE);

    if ((esrc->fes_entry_flags & FIB_ENTRY_FLAG_COVERED_INHERIT) &&
        (esrc->fes_flags & FIB_ENTRY_SRC_FLAG_INHERITED))
    {
        fib_entry_src_t *cover_src;
        fib_node_index_t coveri;
        fib_entry_t *cover;

        /*
         * this source was pushing inherited state, but so is its
         * cover. Now that this source is going away, we need to
         * pull the covers forwarding and use it to update the covereds.
         * Go grab the path-list from the cover, rather than start a walk from
         * the cover, so we don't recursively update this entry.
         */
        coveri = fib_table_get_less_specific(fib_entry->fe_fib_index,
                                             &fib_entry->fe_prefix);

        /*
         * only the default route has itself as its own cover, but the
         * default route cannot have inherited from something else.
         */
        ASSERT(coveri != fib_entry_get_index(fib_entry));

        cover = fib_entry_get(coveri);
        cover_src = fib_entry_src_find(cover, source);

        ASSERT(NULL != cover_src);

        esrc = fib_entry_src_action_update_from_cover(fib_entry, cover_src);
        esrc->fes_entry_flags &= ~FIB_ENTRY_FLAG_COVERED_INHERIT;

        /*
         * Now push the new state from the cover down to the covereds
         */
        fib_entry_src_covered_inherit_add(fib_entry, source);

        return (esrc->fes_flags);
    }
    else
    {
        return (fib_entry_src_action_remove(fib_entry, source));
    }
}

fib_entry_src_flag_t
fib_entry_src_action_remove (fib_entry_t *fib_entry,
			     fib_source_t source)

{
    fib_node_index_t old_path_list;
    fib_entry_src_flag_t sflags;
    fib_entry_src_t *esrc;

    esrc = fib_entry_src_find(fib_entry, source);

    if (NULL == esrc)
	return (FIB_ENTRY_SRC_FLAG_ACTIVE);

    esrc->fes_ref_count--;
    sflags = esrc->fes_flags;

    if (0 != esrc->fes_ref_count)
    {
        /*
         * only remove the source on the 1->0 transisition
         */
        return (sflags);
    }

    if (esrc->fes_flags & FIB_ENTRY_SRC_FLAG_ACTIVE)
    {
        fib_entry_src_action_deactivate(fib_entry, source);
    }
    else if (esrc->fes_flags & FIB_ENTRY_SRC_FLAG_CONTRIBUTING)
    {
        FIB_ENTRY_SRC_VFT_INVOKE(fib_entry, esrc, fesv_deactivate,
                                 (esrc, fib_entry));
        esrc->fes_flags &= ~FIB_ENTRY_SRC_FLAG_CONTRIBUTING;
    }

    old_path_list = esrc->fes_pl;

    FIB_ENTRY_SRC_VFT_INVOKE(fib_entry, esrc, fesv_remove, (esrc));

    fib_path_list_unlock(old_path_list);
    fib_entry_unlock(fib_entry_get_index(fib_entry));

    sflags &= ~FIB_ENTRY_SRC_FLAG_ADDED;
    fib_entry_src_action_deinit(fib_entry, source);

    return (sflags);
}

/*
 * fib_route_attached_cross_table
 *
 * Return true the the route is attached via an interface that
 * is not in the same table as the route
 */
static inline int
fib_route_attached_cross_table (const fib_entry_t *fib_entry,
				const fib_route_path_t *rpath)
{
    /*
     * - All zeros next-hop
     * - a valid interface
     * - entry's fib index not equeal to interface's index
     */
    if (ip46_address_is_zero(&rpath->frp_addr) &&
	(~0 != rpath->frp_sw_if_index) &&
        !(rpath->frp_flags & FIB_ROUTE_PATH_DVR) &&
	(fib_entry->fe_fib_index != 
	 fib_table_get_index_for_sw_if_index(fib_entry_get_proto(fib_entry),
					     rpath->frp_sw_if_index)))
    {
	return (!0);
    }
    return (0);
}

/*
 * Return true if the path is attached
 */
static inline int
fib_path_is_attached (const fib_route_path_t *rpath)
{
    /*
     * DVR paths are not attached, since we are not playing the
     * L3 game with these
     */
    if (rpath->frp_flags & FIB_ROUTE_PATH_DVR)
    {
        return (0);
    }

    /*
     * - All zeros next-hop
     * - a valid interface
     */
    if (ip46_address_is_zero(&rpath->frp_addr) &&
	(~0 != rpath->frp_sw_if_index))
    {
	return (!0);
    }
    else if (rpath->frp_flags & FIB_ROUTE_PATH_ATTACHED ||
             rpath->frp_flags & FIB_ROUTE_PATH_GLEAN)
    {
        return (!0);
    }
    return (0);
}

fib_path_list_flags_t
fib_entry_src_flags_2_path_list_flags (fib_entry_flag_t eflags)
{
    fib_path_list_flags_t plf = FIB_PATH_LIST_FLAG_NONE;

    if (eflags & FIB_ENTRY_FLAG_DROP)
    {
	plf |= FIB_PATH_LIST_FLAG_DROP;
    }
    if (eflags & FIB_ENTRY_FLAG_EXCLUSIVE)
    {
	plf |= FIB_PATH_LIST_FLAG_EXCLUSIVE;
    }
    if (eflags & FIB_ENTRY_FLAG_LOCAL)
    {
	plf |= FIB_PATH_LIST_FLAG_LOCAL;
    }

    return (plf);
}

static void
fib_entry_flags_update (const fib_entry_t *fib_entry,
			const fib_route_path_t *rpaths,
			fib_path_list_flags_t *pl_flags,
			fib_entry_src_t *esrc)
{
    const fib_route_path_t *rpath;

    vec_foreach(rpath, rpaths)
    {
        if ((esrc->fes_src == FIB_SOURCE_API) ||
            (esrc->fes_src == FIB_SOURCE_CLI))
        {
            if (fib_path_is_attached(rpath))
            {
                esrc->fes_entry_flags |= FIB_ENTRY_FLAG_ATTACHED;
            }
            else
            {
                esrc->fes_entry_flags &= ~FIB_ENTRY_FLAG_ATTACHED;
            }
            if (rpath->frp_flags & FIB_ROUTE_PATH_DEAG)
            {
                esrc->fes_entry_flags |= FIB_ENTRY_FLAG_LOOSE_URPF_EXEMPT;
            }
        }
        if (fib_route_attached_cross_table(fib_entry, rpath) &&
            !(esrc->fes_entry_flags & FIB_ENTRY_FLAG_NO_ATTACHED_EXPORT))
        {
            esrc->fes_entry_flags |= FIB_ENTRY_FLAG_IMPORT;
        }
        else
        {
            esrc->fes_entry_flags &= ~FIB_ENTRY_FLAG_IMPORT;
        }
    }
}

/*
 * fib_entry_src_action_add
 *
 * Adding a source can result in a new fib_entry being created, which
 * can inturn mean the pool is realloc'd and thus the entry passed as
 * an argument it also realloc'd
 * @return the entry
 */
fib_entry_t*
fib_entry_src_action_path_add (fib_entry_t *fib_entry,
			       fib_source_t source,
			       fib_entry_flag_t flags,
			       const fib_route_path_t *rpaths)
{
    fib_node_index_t old_path_list;
    fib_path_list_flags_t pl_flags;
    fib_entry_src_t *esrc;

    esrc = fib_entry_src_find(fib_entry, source);
    if (NULL == esrc)
    {
	const dpo_id_t *dpo;

	if (flags == FIB_ENTRY_FLAG_EXCLUSIVE) {
	    dpo = &rpaths->dpo;
	} else {
	    dpo = drop_dpo_get(fib_entry_get_dpo_proto(fib_entry));
	}

	fib_entry =
            fib_entry_src_action_add(fib_entry,
                                     source,
                                     flags,
                                     dpo);
	esrc = fib_entry_src_find(fib_entry, source);
    }

    /*
     * we are no doubt modifying a path-list. If the path-list
     * is shared, and hence not modifiable, then the index returned
     * will be for a different path-list. This FIB entry to needs
     * to maintain its lock appropriately.
     */
    old_path_list = esrc->fes_pl;

    ASSERT(FIB_ENTRY_SRC_VFT_EXISTS(esrc, fesv_path_add));

    pl_flags = fib_entry_src_flags_2_path_list_flags(fib_entry_get_flags_i(fib_entry));
    fib_entry_flags_update(fib_entry, rpaths, &pl_flags, esrc);

    FIB_ENTRY_SRC_VFT_INVOKE(fib_entry, esrc, fesv_path_add,
                             (esrc, fib_entry, pl_flags, rpaths));

    fib_path_list_lock(esrc->fes_pl);
    fib_path_list_unlock(old_path_list);

    return (fib_entry);
}

/*
 * fib_entry_src_action_swap
 *
 * The source is providing new paths to replace the old ones.
 * Adding a source can result in a new fib_entry being created, which
 * can inturn mean the pool is realloc'd and thus the entry passed as
 * an argument it also realloc'd
 * @return the entry
 */
fib_entry_t*
fib_entry_src_action_path_swap (fib_entry_t *fib_entry,
				fib_source_t source,
				fib_entry_flag_t flags,
				const fib_route_path_t *rpaths)
{
    fib_node_index_t old_path_list;
    fib_path_list_flags_t pl_flags;
    fib_entry_src_t *esrc;

    esrc = fib_entry_src_find(fib_entry, source);

    if (NULL == esrc)
    {
	const dpo_id_t *dpo;

	if (flags == FIB_ENTRY_FLAG_EXCLUSIVE) {
	    dpo = &rpaths->dpo;
	} else {
	    dpo = drop_dpo_get(fib_entry_get_dpo_proto(fib_entry));
	}

        fib_entry = fib_entry_src_action_add(fib_entry,
					     source,
					     flags,
                                             dpo);
	esrc = fib_entry_src_find(fib_entry, source);
    }
    else
    {
        if (flags != esrc->fes_entry_flags)
        {
            FIB_ENTRY_SRC_VFT_INVOKE(fib_entry, esrc, fesv_flags_change,
                                     (esrc, fib_entry, flags));
        }
        esrc->fes_entry_flags = flags;
    }

    /*
     * swapping paths may create a new path-list (or may use an existing shared)
     * but we are certainly getting a different one. This FIB entry to needs
     * to maintain its lock appropriately.
     */
    old_path_list = esrc->fes_pl;

    ASSERT(FIB_ENTRY_SRC_VFT_EXISTS(esrc, fesv_path_swap));

    pl_flags = fib_entry_src_flags_2_path_list_flags(flags);

    fib_entry_flags_update(fib_entry, rpaths, &pl_flags, esrc);

    FIB_ENTRY_SRC_VFT_INVOKE(fib_entry, esrc, fesv_path_swap,
                             (esrc, fib_entry,
                              pl_flags, rpaths));

    fib_path_list_lock(esrc->fes_pl);
    fib_path_list_unlock(old_path_list);

    return (fib_entry);
}

fib_entry_src_flag_t
fib_entry_src_action_path_remove (fib_entry_t *fib_entry,
				  fib_source_t source,
				  const fib_route_path_t *rpaths)
{
    fib_path_list_flags_t pl_flags;
    fib_node_index_t old_path_list;
    fib_entry_src_t *esrc;

    esrc = fib_entry_src_find(fib_entry, source);

    ASSERT(NULL != esrc);
    ASSERT(esrc->fes_flags & FIB_ENTRY_SRC_FLAG_ADDED);

    /*
     * we no doubt modifying a path-list. If the path-list
     * is shared, and hence not modifiable, then the index returned
     * will be for a different path-list. This FIB entry to needs
     * to maintain its lock appropriately.
     */
    old_path_list = esrc->fes_pl;

    ASSERT(FIB_ENTRY_SRC_VFT_EXISTS(esrc, fesv_path_remove));

    pl_flags = fib_entry_src_flags_2_path_list_flags(fib_entry_get_flags_i(fib_entry));
    fib_entry_flags_update(fib_entry, rpaths, &pl_flags, esrc);

    FIB_ENTRY_SRC_VFT_INVOKE(fib_entry, esrc, fesv_path_remove,
                             (esrc, pl_flags, rpaths));

    /*
     * lock the new path-list, unlock the old if it had one
     */
    fib_path_list_unlock(old_path_list);

    if (FIB_NODE_INDEX_INVALID != esrc->fes_pl) {
	fib_path_list_lock(esrc->fes_pl);
	return (FIB_ENTRY_SRC_FLAG_ADDED);
    }
    else
    {
	/*
	 * no more paths left from this source
	 */
	fib_entry_src_action_remove_or_update_inherit(fib_entry, source);
	return (FIB_ENTRY_SRC_FLAG_NONE);
    }
}

u8*
fib_entry_src_format (fib_entry_t *fib_entry,
		      fib_source_t source,
		      u8* s)
{
    fib_entry_src_t *esrc;

    esrc = fib_entry_src_find(fib_entry, source);

    FIB_ENTRY_SRC_VFT_INVOKE_AND_RETURN(esrc, fesv_format, (esrc, s));

    return (s);
}

adj_index_t
fib_entry_get_adj_for_source (fib_node_index_t fib_entry_index,
			      fib_source_t source)
{
    fib_entry_t *fib_entry;
    fib_entry_src_t *esrc;

    if (FIB_NODE_INDEX_INVALID == fib_entry_index)
	return (ADJ_INDEX_INVALID);

    fib_entry = fib_entry_get(fib_entry_index);
    esrc = fib_entry_src_find(fib_entry, source);

    if (NULL != esrc)
    {
	if (FIB_NODE_INDEX_INVALID != esrc->fes_pl)
	{
	    return (fib_path_list_get_adj(
			esrc->fes_pl,
			fib_entry_get_default_chain_type(fib_entry)));
	}
    }
    return (ADJ_INDEX_INVALID);
}

const int
fib_entry_get_dpo_for_source (fib_node_index_t fib_entry_index,
			      fib_source_t source,
			      dpo_id_t *dpo)
{
    fib_entry_t *fib_entry;
    fib_entry_src_t *esrc;

    if (FIB_NODE_INDEX_INVALID == fib_entry_index)
	return (0);

    fib_entry = fib_entry_get(fib_entry_index);
    esrc = fib_entry_src_find(fib_entry, source);

    if (NULL != esrc)
    {
	if (FIB_NODE_INDEX_INVALID != esrc->fes_pl)
	{
	    fib_path_list_contribute_forwarding(
		esrc->fes_pl,
		fib_entry_get_default_chain_type(fib_entry),
                FIB_PATH_LIST_FWD_FLAG_NONE,
		dpo);

	    return (dpo_id_is_valid(dpo));
	}
    }
    return (0);
}

u32
fib_entry_get_resolving_interface_for_source (fib_node_index_t entry_index,
					      fib_source_t source)
{
    fib_entry_t *fib_entry;
    fib_entry_src_t *esrc;

    fib_entry = fib_entry_get(entry_index);

    esrc = fib_entry_src_find(fib_entry, source);

    if (NULL != esrc)
    {
	if (FIB_NODE_INDEX_INVALID != esrc->fes_pl)
	{
	    return (fib_path_list_get_resolving_interface(esrc->fes_pl));
	}
    }
    return (~0);
}

fib_entry_flag_t
fib_entry_get_flags_for_source (fib_node_index_t entry_index,
				fib_source_t source)
{
    fib_entry_t *fib_entry;
    fib_entry_src_t *esrc;

    fib_entry = fib_entry_get(entry_index);

    esrc = fib_entry_src_find(fib_entry, source);

    if (NULL != esrc)
    {
	return (esrc->fes_entry_flags);
    }

    return (FIB_ENTRY_FLAG_NONE);
}

fib_source_t
fib_entry_get_source_i (const fib_entry_t *fib_entry)
{
    /* the vector of sources is deliberately arranged in priority order */
    if (0 == vec_len(fib_entry->fe_srcs))
        return (FIB_SOURCE_INVALID);
    return (vec_elt(fib_entry->fe_srcs, 0).fes_src);
}

fib_entry_flag_t
fib_entry_get_flags_i (const fib_entry_t *fib_entry)
{
    /* the vector of sources is deliberately arranged in priority order */
    if (0 == vec_len(fib_entry->fe_srcs))
        return (FIB_ENTRY_FLAG_NONE);
    return (vec_elt(fib_entry->fe_srcs, 0).fes_entry_flags);
}

void
fib_entry_set_source_data (fib_node_index_t fib_entry_index,
                           fib_source_t source,
                           const void *data)
{
    fib_entry_t *fib_entry;
    fib_entry_src_t *esrc;

    fib_entry = fib_entry_get(fib_entry_index);
    esrc = fib_entry_src_find(fib_entry, source);

    if (NULL != esrc)
    {
        FIB_ENTRY_SRC_VFT_INVOKE(fib_entry, esrc, fesv_set_data,
                                 (esrc, fib_entry, data));
    }
}

const void*
fib_entry_get_source_data (fib_node_index_t fib_entry_index,
                           fib_source_t source)
{
    fib_entry_t *fib_entry;
    fib_entry_src_t *esrc;

    fib_entry = fib_entry_get(fib_entry_index);
    esrc = fib_entry_src_find(fib_entry, source);

    if (NULL != esrc)
    {
        FIB_ENTRY_SRC_VFT_INVOKE_AND_RETURN(esrc, fesv_get_data,
                                            (esrc, fib_entry));
    }
    return (NULL);
}

void
fib_entry_src_module_init (void)
{
    fib_entry_src_rr_register();
    fib_entry_src_interface_register();
    fib_entry_src_interpose_register();
    fib_entry_src_drop_register();
    fib_entry_src_simple_register();
    fib_entry_src_api_register();
    fib_entry_src_adj_register();
    fib_entry_src_mpls_register();
    fib_entry_src_lisp_register();
}
