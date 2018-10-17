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

#include <vnet/fib/fib_entry.h>
#include <vnet/fib/fib_table.h>
#include <vnet/fib/fib_walk.h>
#include <vnet/fib/fib_path_list.h>

#include <vnet/bier/bier_table.h>
#include <vnet/bier/bier_fmask.h>
#include <vnet/bier/bier_bit_string.h>
#include <vnet/bier/bier_disp_table.h>

#include <vnet/mpls/mpls.h>
#include <vnet/dpo/drop_dpo.h>
#include <vnet/dpo/load_balance.h>

/*
 * attributes names for formatting
 */
static const char *const bier_fmask_attr_names[] = BIER_FMASK_ATTR_NAMES;

/*
 * pool of BIER fmask objects
 */
bier_fmask_t *bier_fmask_pool;

/**
 * Stats for each BIER fmask object
 */
vlib_combined_counter_main_t bier_fmask_counters;

static inline index_t
bier_fmask_get_index (const bier_fmask_t *bfm)
{
    return (bfm - bier_fmask_pool);
}

static void
bier_fmask_bits_init (bier_fmask_bits_t *bits,
                      bier_hdr_len_id_t hlid)
{
    bits->bfmb_refs = clib_mem_alloc(sizeof(bits->bfmb_refs[0]) *
                                     bier_hdr_len_id_to_num_bits(hlid));
    clib_memset(bits->bfmb_refs,
           0,
           (sizeof(bits->bfmb_refs[0]) *
            bier_hdr_len_id_to_num_bits(hlid)));

    bits->bfmb_input_reset_string.bbs_len =
        bier_hdr_len_id_to_num_buckets(hlid);

    /*
     * The buckets are accessed in the switch path
     */
    bits->bfmb_input_reset_string.bbs_buckets =
        clib_mem_alloc_aligned(
            sizeof(bits->bfmb_input_reset_string.bbs_buckets[0]) *
            bier_hdr_len_id_to_num_buckets(hlid),
            CLIB_CACHE_LINE_BYTES);
    clib_memset(bits->bfmb_input_reset_string.bbs_buckets,
           0,
           sizeof(bits->bfmb_input_reset_string.bbs_buckets[0]) *
           bier_hdr_len_id_to_num_buckets(hlid));
}

static void
bier_fmask_stack (bier_fmask_t *bfm)
{
    dpo_id_t via_dpo = DPO_INVALID;
    fib_forward_chain_type_t fct;

    if (bfm->bfm_flags & BIER_FMASK_FLAG_MPLS)
    {
        fct = FIB_FORW_CHAIN_TYPE_MPLS_NON_EOS;
    }
    else
    {
        fct = FIB_FORW_CHAIN_TYPE_BIER;
    }

    fib_path_list_contribute_forwarding(bfm->bfm_pl, fct,
                                        FIB_PATH_LIST_FWD_FLAG_COLLAPSE,
                                        &via_dpo);

    /*
     * If the via PL entry provides no forwarding (i.e. a drop)
     * then neither does this fmask. That way children consider this fmask
     * unresolved and other ECMP options are used instead.
     */
    if (dpo_is_drop(&via_dpo))
    {
        bfm->bfm_flags &= ~BIER_FMASK_FLAG_FORWARDING;
    }
    else
    {
        bfm->bfm_flags |= BIER_FMASK_FLAG_FORWARDING;
    }

    dpo_stack(DPO_BIER_FMASK,
              DPO_PROTO_BIER,
              &bfm->bfm_dpo,
              &via_dpo);
    dpo_reset(&via_dpo);
}

void
bier_fmask_contribute_forwarding (index_t bfmi,
                                  dpo_id_t *dpo)
{
    bier_fmask_t *bfm;

    bfm = bier_fmask_get(bfmi);

    if (bfm->bfm_flags & BIER_FMASK_FLAG_FORWARDING)
    {
        dpo_set(dpo,
                DPO_BIER_FMASK,
                DPO_PROTO_BIER,
                bfmi);
    }
    else
    {
        dpo_copy(dpo, drop_dpo_get(DPO_PROTO_BIER));
    }
}

u32
bier_fmask_child_add (fib_node_index_t bfmi,
                     fib_node_type_t child_type,
                     fib_node_index_t child_index)
{
    return (fib_node_child_add(FIB_NODE_TYPE_BIER_FMASK,
                               bfmi,
                               child_type,
                               child_index));
};

void
bier_fmask_child_remove (fib_node_index_t bfmi,
                         u32 sibling_index)
{
    if (INDEX_INVALID == bfmi)
    {
        return;
    }

    fib_node_child_remove(FIB_NODE_TYPE_BIER_FMASK,
                          bfmi,
                          sibling_index);
}

static void
bier_fmask_init (bier_fmask_t *bfm,
                 const bier_fmask_id_t *fmid,
                 const fib_route_path_t *rpath)
{
    const bier_table_id_t *btid;
    fib_route_path_t *rpaths;
    mpls_label_t olabel;

    clib_memset(bfm, 0, sizeof(*bfm));
    
    bfm->bfm_id = clib_mem_alloc(sizeof(*bfm->bfm_id));

    fib_node_init(&bfm->bfm_node, FIB_NODE_TYPE_BIER_FMASK);
    *bfm->bfm_id = *fmid;
    dpo_reset(&bfm->bfm_dpo);
    btid = bier_table_get_id(bfm->bfm_id->bfmi_bti);
    bier_fmask_bits_init(&bfm->bfm_bits, btid->bti_hdr_len);

    if (rpath->frp_flags & FIB_ROUTE_PATH_UDP_ENCAP)
    {
        bfm->bfm_id->bfmi_nh_type = BIER_NH_UDP;
    }
    else if (ip46_address_is_zero(&(bfm->bfm_id->bfmi_nh)))
    {
        bfm->bfm_flags |= BIER_FMASK_FLAG_DISP;
    }

    if (!(bfm->bfm_flags & BIER_FMASK_FLAG_DISP))
    {
        if (NULL != rpath->frp_label_stack)
        {
            olabel = rpath->frp_label_stack[0].fml_value;
            vnet_mpls_uc_set_label(&bfm->bfm_label, olabel);
            vnet_mpls_uc_set_exp(&bfm->bfm_label, 0);
            vnet_mpls_uc_set_s(&bfm->bfm_label, 1);
            vnet_mpls_uc_set_ttl(&bfm->bfm_label, 64);
            bfm->bfm_flags |= BIER_FMASK_FLAG_MPLS;
        }
        else
        {
            bier_bift_id_t id;

            /*
             * not an MPLS label
             */
            bfm->bfm_flags &= ~BIER_FMASK_FLAG_MPLS;

            /*
             * use a label as encoded for BIFT value
             */
            id = bier_bift_id_encode(btid->bti_set,
                                     btid->bti_sub_domain,
                                     btid->bti_hdr_len);
            vnet_mpls_uc_set_label(&bfm->bfm_label, id);
            vnet_mpls_uc_set_s(&bfm->bfm_label, 1);
            vnet_mpls_uc_set_exp(&bfm->bfm_label, 0);
            vnet_mpls_uc_set_ttl(&bfm->bfm_label, 64);
        }
        bfm->bfm_label = clib_host_to_net_u32(bfm->bfm_label);
    }

    rpaths = NULL;
    vec_add1(rpaths, *rpath);
    bfm->bfm_pl = fib_path_list_create((FIB_PATH_LIST_FLAG_SHARED |
                                        FIB_PATH_LIST_FLAG_NO_URPF),
                                       rpaths);
    bfm->bfm_sibling = fib_path_list_child_add(bfm->bfm_pl,
                                               FIB_NODE_TYPE_BIER_FMASK,
                                               bier_fmask_get_index(bfm));
    vec_free(rpaths);
    bier_fmask_stack(bfm);
}

static void
bier_fmask_destroy (bier_fmask_t *bfm)
{
    clib_mem_free(bfm->bfm_bits.bfmb_refs);
    clib_mem_free(bfm->bfm_bits.bfmb_input_reset_string.bbs_buckets);

    bier_fmask_db_remove(bfm->bfm_id);
    fib_path_list_child_remove(bfm->bfm_pl,
                               bfm->bfm_sibling);
    dpo_reset(&bfm->bfm_dpo);
    clib_mem_free(bfm->bfm_id);
    pool_put(bier_fmask_pool, bfm);
}

void
bier_fmask_unlock (index_t bfmi)
{
    bier_fmask_t *bfm;

    if (INDEX_INVALID == bfmi)
    {
        return;
    }

    bfm = bier_fmask_get(bfmi);

    fib_node_unlock(&bfm->bfm_node);
}

void
bier_fmask_lock (index_t bfmi)
{
    bier_fmask_t *bfm;

    if (INDEX_INVALID == bfmi)
    {
        return;
    }

    bfm = bier_fmask_get(bfmi);

    fib_node_lock(&bfm->bfm_node);
}

index_t
bier_fmask_create_and_lock (const bier_fmask_id_t *fmid,
                            const fib_route_path_t *rpath)
{
    bier_fmask_t *bfm;
    index_t bfmi;

    pool_get_aligned(bier_fmask_pool, bfm, CLIB_CACHE_LINE_BYTES);
    bfmi = bier_fmask_get_index(bfm);

    vlib_validate_combined_counter (&(bier_fmask_counters), bfmi);
    vlib_zero_combined_counter (&(bier_fmask_counters), bfmi);

    bier_fmask_init(bfm, fmid, rpath);

    bier_fmask_lock(bfmi);

    return (bfmi);
}

void
bier_fmask_link (index_t bfmi,
                 bier_bp_t bp)
{
    bier_fmask_t *bfm;

    bfm = bier_fmask_get(bfmi);

    if (0 == bfm->bfm_bits.bfmb_refs[BIER_BP_TO_INDEX(bp)])
    {
        /*
         * 0 -> 1 transistion - set the bit in the string
         */
        bier_bit_string_set_bit(&bfm->bfm_bits.bfmb_input_reset_string, bp);
    }

    ++bfm->bfm_bits.bfmb_refs[BIER_BP_TO_INDEX(bp)];
    ++bfm->bfm_bits.bfmb_count;
}

void
bier_fmask_unlink (index_t bfmi,
                   bier_bp_t bp)
{
    bier_fmask_t *bfm;

    bfm = bier_fmask_get(bfmi);

    --bfm->bfm_bits.bfmb_refs[BIER_BP_TO_INDEX(bp)];
    --bfm->bfm_bits.bfmb_count;

    if (0 == bfm->bfm_bits.bfmb_refs[BIER_BP_TO_INDEX(bp)])
    {
        /*
         * 1 -> 0 transistion - clear the bit in the string
         */
        bier_bit_string_clear_bit(&bfm->bfm_bits.bfmb_input_reset_string, bp);
    }
}

u8*
format_bier_fmask (u8 *s, va_list *ap)
{
    index_t bfmi = va_arg(*ap, index_t);
    u32 indent = va_arg(*ap, u32);
    bier_fmask_attributes_t attr;
    bier_fmask_t *bfm;
    vlib_counter_t to;

    if (pool_is_free_index(bier_fmask_pool, bfmi))
    {
        return (format(s, "No BIER f-mask %d", bfmi));
    }

    bfm = bier_fmask_get(bfmi);

    s = format(s, "fmask: nh:%U bs:%U locks:%d ",
               format_ip46_address, &bfm->bfm_id->bfmi_nh, IP46_TYPE_ANY,
               format_bier_bit_string, &bfm->bfm_bits.bfmb_input_reset_string,
               bfm->bfm_node.fn_locks);
    s = format(s, "flags:");
    FOR_EACH_BIER_FMASK_ATTR(attr) {
        if ((1<<attr) & bfm->bfm_flags) {
            s = format (s, "%s,", bier_fmask_attr_names[attr]);
        }
    }
    vlib_get_combined_counter (&(bier_fmask_counters), bfmi, &to);
    s = format (s, " to:[%Ld:%Ld]]", to.packets, to.bytes);
    s = format(s, "\n");
    s = fib_path_list_format(bfm->bfm_pl, s);

    if (bfm->bfm_flags & BIER_FMASK_FLAG_MPLS)
    {
        s = format(s, "  output-label:%U",
                   format_mpls_unicast_label,
                   vnet_mpls_uc_get_label(clib_net_to_host_u32(bfm->bfm_label)));
    }
    else
    {
        s = format(s, "  output-bfit:[%U]",
                   format_bier_bift_id,
                   vnet_mpls_uc_get_label(clib_net_to_host_u32(bfm->bfm_label)));
    }
    s = format(s, "\n %U%U",
               format_white_space, indent,
               format_dpo_id, &bfm->bfm_dpo, indent+2);

    return (s);
}

void
bier_fmask_get_stats (index_t bfmi, u64 * packets, u64 * bytes)
{
  vlib_counter_t to;

  vlib_get_combined_counter (&(bier_fmask_counters), bfmi, &to);

  *packets = to.packets;
  *bytes = to.bytes;
}

void
bier_fmask_encode (index_t bfmi,
                   bier_table_id_t *btid,
                   fib_route_path_encode_t *rpath)
{
    bier_fmask_t *bfm;

    bfm = bier_fmask_get(bfmi);
    *btid = *bier_table_get_id(bfm->bfm_id->bfmi_bti);

    clib_memset(rpath, 0, sizeof(*rpath));

    rpath->rpath.frp_sw_if_index = ~0;

    switch (bfm->bfm_id->bfmi_nh_type)
    {
    case BIER_NH_UDP:
        rpath->rpath.frp_flags = FIB_ROUTE_PATH_UDP_ENCAP;
        rpath->rpath.frp_udp_encap_id = bfm->bfm_id->bfmi_id;
        break;
    case BIER_NH_IP:
        memcpy(&rpath->rpath.frp_addr, &bfm->bfm_id->bfmi_nh,
               sizeof(rpath->rpath.frp_addr));
        break;
    }
}

static fib_node_t *
bier_fmask_get_node (fib_node_index_t index)
{
    bier_fmask_t *bfm = bier_fmask_get(index);
    return (&(bfm->bfm_node));
}

static bier_fmask_t*
bier_fmask_get_from_node (fib_node_t *node)
{
    return ((bier_fmask_t*)(((char*)node) -
                            STRUCT_OFFSET_OF(bier_fmask_t,
                                             bfm_node)));
}

/*
 * bier_fmask_last_lock_gone
 */
static void
bier_fmask_last_lock_gone (fib_node_t *node)
{
    bier_fmask_destroy(bier_fmask_get_from_node(node));
}

/*
 * bier_fmask_back_walk_notify
 *
 * A back walk has reached this BIER fmask
 */
static fib_node_back_walk_rc_t
bier_fmask_back_walk_notify (fib_node_t *node,
                             fib_node_back_walk_ctx_t *ctx)
{
    /*
     * re-stack the fmask on the n-eos of the via
     */
    bier_fmask_t *bfm = bier_fmask_get_from_node(node);

    bier_fmask_stack(bfm);

    /*
     * propagate further up the graph.
     * we can do this synchronously since the fan out is small.
     */
    fib_walk_sync(FIB_NODE_TYPE_BIER_FMASK, bier_fmask_get_index(bfm), ctx);

    return (FIB_NODE_BACK_WALK_CONTINUE);
}

/*
 * The BIER fmask's graph node virtual function table
 */
static const fib_node_vft_t bier_fmask_vft = {
    .fnv_get = bier_fmask_get_node,
    .fnv_last_lock = bier_fmask_last_lock_gone,
    .fnv_back_walk = bier_fmask_back_walk_notify,
};

static void
bier_fmask_dpo_lock (dpo_id_t *dpo)
{
}

static void
bier_fmask_dpo_unlock (dpo_id_t *dpo)
{
}

static void
bier_fmask_dpo_mem_show (void)
{
    fib_show_memory_usage("BIER-fmask",
                          pool_elts(bier_fmask_pool),
                          pool_len(bier_fmask_pool),
                          sizeof(bier_fmask_t));
}

const static dpo_vft_t bier_fmask_dpo_vft = {
    .dv_lock = bier_fmask_dpo_lock,
    .dv_unlock = bier_fmask_dpo_unlock,
    .dv_mem_show = bier_fmask_dpo_mem_show,
    .dv_format = format_bier_fmask,
};

const static char *const bier_fmask_mpls_nodes[] =
{
    "bier-output",
    NULL
};
const static char * const * const bier_fmask_nodes[DPO_PROTO_NUM] =
{
    [DPO_PROTO_BIER] = bier_fmask_mpls_nodes,
    [DPO_PROTO_MPLS] = bier_fmask_mpls_nodes,
};

clib_error_t *
bier_fmask_module_init (vlib_main_t * vm)
{
    fib_node_register_type (FIB_NODE_TYPE_BIER_FMASK, &bier_fmask_vft);
    dpo_register(DPO_BIER_FMASK, &bier_fmask_dpo_vft, bier_fmask_nodes);

    return (NULL);
}

VLIB_INIT_FUNCTION (bier_fmask_module_init);

static clib_error_t *
bier_fmask_show (vlib_main_t * vm,
                 unformat_input_t * input,
                 vlib_cli_command_t * cmd)
{
    bier_fmask_t *bfm;
    index_t bfmi;

    bfmi = INDEX_INVALID;

    while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
        if (unformat (input, "%d", &bfmi))
        {
            ;
        } else
        {
            break;
        }
    }

    if (INDEX_INVALID == bfmi)
    {
        pool_foreach(bfm, bier_fmask_pool,
        ({
            vlib_cli_output (vm, "[@%d] %U",
                             bier_fmask_get_index(bfm),
                             format_bier_fmask, bier_fmask_get_index(bfm), 0);
        }));
    }
    else
    {
        vlib_cli_output (vm, "%U", format_bier_fmask, bfmi, 0);
    }

    return (NULL);
}

VLIB_CLI_COMMAND (show_bier_fmask, static) = {
    .path = "show bier fmask",
    .short_help = "show bier fmask",
    .function = bier_fmask_show,
};
