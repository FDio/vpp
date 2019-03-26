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

#include <vnet/adj/adj_delegate.h>
#include <vnet/adj/adj_midchain.h>
#include <vnet/fib/fib_table.h>

/**
 * Midchain stacker delegate
 */
typedef struct adj_midchain_delegate_t_
{
    /**
     * the Fib Entry we are stacked on
     */
    fib_node_index_t amd_fei;

    /**
     * The sibling entry on the FIB entry
     */
    u32 amd_sibling;
} adj_midchain_delegate_t;

/**
 * Pool of delegates
 */
static adj_midchain_delegate_t *amd_pool;

static inline const adj_midchain_delegate_t*
adj_midchain_from_const_base (const adj_delegate_t *ad)
{
    if (NULL != ad)
    {
        return (pool_elt_at_index(amd_pool, ad->ad_index));
    }
    return (NULL);
}

static void
adj_midchain_delegate_restack_i (adj_index_t ai,
                                 adj_midchain_delegate_t *amd)
{
    if (vnet_sw_interface_is_admin_up (vnet_get_main (),
                                       adj_get_sw_if_index(ai)) &&
        (FIB_NODE_INDEX_INVALID != amd->amd_fei))
    {
        const fib_prefix_t *pfx;

        pfx = fib_entry_get_prefix(amd->amd_fei);

        adj_nbr_midchain_stack_on_fib_entry (
            ai,
            amd->amd_fei,
            fib_forw_chain_type_from_fib_proto(pfx->fp_proto));
    }
    else
    {
        adj_nbr_midchain_unstack (ai);
    }
}

void
adj_midchain_delegate_restack (adj_index_t ai)
{
    adj_midchain_delegate_t *amd;
    ip_adjacency_t *adj;
    adj_delegate_t *ad;

    /*
     * if there's a delegate already use that
     */
    adj = adj_get(ai);
    ad = adj_delegate_get(adj, ADJ_DELEGATE_MIDCHAIN);

    if (NULL != ad)
    {
        amd = pool_elt_at_index(amd_pool, ad->ad_index);

        adj_midchain_delegate_restack_i(ai, amd);
    }
    /*
     * else
     *  nothing to stack
     */
}

void
adj_midchain_delegate_stack (adj_index_t ai,
                             u32 fib_index,
                             const fib_prefix_t *pfx)
{
    adj_midchain_delegate_t *amd;
    ip_adjacency_t *adj;
    adj_delegate_t *ad;

    /*
     * if there's a delegate already use that
     */
    adj = adj_get(ai);
    ad = adj_delegate_get(adj, ADJ_DELEGATE_MIDCHAIN);

    if (NULL != ad)
    {
        amd = pool_elt_at_index(amd_pool, ad->ad_index);
    }
    else
    {
        pool_get(amd_pool, amd);
        amd->amd_fei = FIB_NODE_INDEX_INVALID;
        adj_delegate_add(adj, ADJ_DELEGATE_MIDCHAIN, amd - amd_pool);

        amd->amd_fei = fib_table_entry_special_add(fib_index,
                                                   pfx,
                                                   FIB_SOURCE_RR,
                                                   FIB_ENTRY_FLAG_NONE);
        amd->amd_sibling = fib_entry_child_add(amd->amd_fei,
                                               FIB_NODE_TYPE_ADJ,
                                               ai);
    }
    adj_midchain_delegate_restack_i(ai, amd);
}

void
adj_midchain_delegate_unstack (adj_index_t ai)
{
    adj_nbr_midchain_unstack(ai);
}

static void
adj_midchain_delegate_adj_deleted (adj_delegate_t *ad)
{
    adj_midchain_delegate_t *amd;

    amd = pool_elt_at_index(amd_pool, ad->ad_index);

    fib_entry_child_remove (amd->amd_fei, amd->amd_sibling);
    fib_table_entry_delete_index (amd->amd_fei, FIB_SOURCE_RR);

    pool_put(amd_pool, amd);
}

/**
 * Print a delegate that represents MIDCHAIN tracking
 */
static u8 *
adj_midchain_delegate_fmt (const adj_delegate_t *aed, u8 *s)
{
    const adj_midchain_delegate_t *amd = adj_midchain_from_const_base(aed);

    s = format(s, "MIDCHAIN:[fib-entry:%d]", amd->amd_fei);

    return (s);
}

const static adj_delegate_vft_t adj_delegate_vft = {
  .adv_format = adj_midchain_delegate_fmt,
  .adv_adj_deleted = adj_midchain_delegate_adj_deleted,
};

static clib_error_t *
adj_midchain_delegate_module_init (vlib_main_t * vm)
{
    clib_error_t * error = NULL;

    adj_delegate_register_type (ADJ_DELEGATE_MIDCHAIN, &adj_delegate_vft);

    return (error);
}

VLIB_INIT_FUNCTION (adj_midchain_delegate_module_init);

