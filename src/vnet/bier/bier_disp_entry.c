/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
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
/**
 * bier_dispositon : The BIER dispositon object
 *
 * A BIER dispositon object is present in the IP mcast output list
 * and represents the dispositon of a BIER bitmask. After BIER header
 * dispositon the packet is forward within the appropriate/specifid
 * BIER table
 */

#include <vnet/bier/bier_disp_entry.h>
#include <vnet/bier/bier_hdr_inlines.h>
#include <vnet/fib/fib_path_list.h>
#include <vnet/dpo/drop_dpo.h>

/**
 * The memory pool of all imp objects
 */
bier_disp_entry_t *bier_disp_entry_pool;

/**
 * When constructing the BIER imp ID from an index and BSL, shift
 * the BSL this far
 */
#define BIER_DISP_ENTRY_ID_HLEN_SHIFT 24

static void
bier_disp_entry_lock_i (bier_disp_entry_t *bde)
{
    bde->bde_locks++;
}

void
bier_disp_entry_lock (index_t bdei)
{
    bier_disp_entry_lock_i(bier_disp_entry_get(bdei));
}

static index_t
bier_disp_entry_get_index(bier_disp_entry_t *bde)
{
    return (bde - bier_disp_entry_pool);
}

index_t
bier_disp_entry_add_or_lock (void)
{
    dpo_id_t invalid = DPO_INVALID;
    bier_hdr_proto_id_t pproto;
    bier_disp_entry_t *bde;

    pool_get_aligned(bier_disp_entry_pool, bde, CLIB_CACHE_LINE_BYTES);

    bde->bde_locks = 0;

    FOR_EACH_BIER_HDR_PROTO(pproto)
    {
        bde->bde_fwd[pproto].bde_dpo = invalid;
        bde->bde_fwd[pproto].bde_rpf_id = ~0;
        bde->bde_pl[pproto] = FIB_NODE_INDEX_INVALID;
    }

    bier_disp_entry_lock_i(bde);
    return (bier_disp_entry_get_index(bde));
}

void
bier_disp_entry_unlock (index_t bdei)
{
    bier_disp_entry_t *bde;

    if (INDEX_INVALID == bdei)
    {
        return;
    }

    bde = bier_disp_entry_get(bdei);

    bde->bde_locks--;

    if (0 == bde->bde_locks)
    {
        bier_hdr_proto_id_t pproto;

        FOR_EACH_BIER_HDR_PROTO(pproto)
        {
            dpo_unlock(&bde->bde_fwd[pproto].bde_dpo);
            bde->bde_fwd[pproto].bde_rpf_id = ~0;
            fib_path_list_unlock(bde->bde_pl[pproto]);
        }
        pool_put(bier_disp_entry_pool, bde);
    }
}

typedef struct bier_disp_entry_path_list_walk_ctx_t_
{
    u32 bdew_rpf_id;
} bier_disp_entry_path_list_walk_ctx_t;

static fib_path_list_walk_rc_t
bier_disp_entry_path_list_walk (fib_node_index_t pl_index,
                                fib_node_index_t path_index,
                                void *arg)
{
    bier_disp_entry_path_list_walk_ctx_t *ctx = arg;

    ctx->bdew_rpf_id = fib_path_get_rpf_id(path_index);

    if (~0 != ctx->bdew_rpf_id)
    {
        return (FIB_PATH_LIST_WALK_STOP);
    }
    return (FIB_PATH_LIST_WALK_CONTINUE);
}

static void
bier_disp_entry_restack (bier_disp_entry_t *bde,
                         bier_hdr_proto_id_t pproto)
{
    dpo_id_t via_dpo = DPO_INVALID;
    fib_node_index_t pli;

    pli = bde->bde_pl[pproto];

    if (FIB_NODE_INDEX_INVALID == pli)
    {
        dpo_copy(&via_dpo,
                 drop_dpo_get(bier_hdr_proto_to_dpo(pproto)));
    }
    else
    {
        fib_path_list_contribute_forwarding(pli,
                                            fib_forw_chain_type_from_dpo_proto(
                                                bier_hdr_proto_to_dpo(pproto)),
                                            &via_dpo);

        bier_disp_entry_path_list_walk_ctx_t ctx = {
            .bdew_rpf_id = ~0,
        };

        fib_path_list_walk(pli, bier_disp_entry_path_list_walk, &ctx);
        bde->bde_fwd[pproto].bde_rpf_id = ctx.bdew_rpf_id;
    }

    dpo_stack(DPO_BIER_DISP_ENTRY,
              DPO_PROTO_BIER,
              &bde->bde_fwd[pproto].bde_dpo,
              &via_dpo);
}

void
bier_disp_entry_path_add (index_t bdei,
                          bier_hdr_proto_id_t pproto,
                          const fib_route_path_t *rpaths)
{
    fib_node_index_t *pli, old_pli;
    bier_disp_entry_t *bde;

    bde = bier_disp_entry_get(bdei);
    pli = &bde->bde_pl[pproto];
    old_pli = *pli;

    /*
     * create a new or update the exisitng path-list for this
     * payload protocol
     */
    if (FIB_NODE_INDEX_INVALID == *pli)
    {
        *pli = fib_path_list_create((FIB_PATH_LIST_FLAG_SHARED |
                                     FIB_PATH_LIST_FLAG_NO_URPF),
                                    rpaths);
    }
    else
    {
        *pli = fib_path_list_copy_and_path_add(old_pli,
                                               (FIB_PATH_LIST_FLAG_SHARED |
                                                FIB_PATH_LIST_FLAG_NO_URPF),
                                               rpaths);
    }

    fib_path_list_lock(*pli);
    fib_path_list_unlock(old_pli);

    bier_disp_entry_restack(bde, pproto);
}

int
bier_disp_entry_path_remove (index_t bdei,
                             bier_hdr_proto_id_t pproto,
                             const fib_route_path_t *rpaths)
{
    fib_node_index_t *pli, old_pli;
    bier_disp_entry_t *bde;

    bde = bier_disp_entry_get(bdei);
    pli = &bde->bde_pl[pproto];
    old_pli = *pli;

    /*
     * update the exisitng path-list for this payload protocol
     */
    if (FIB_NODE_INDEX_INVALID != *pli)
    {
        *pli = fib_path_list_copy_and_path_remove(old_pli,
                                                  (FIB_PATH_LIST_FLAG_SHARED |
                                                   FIB_PATH_LIST_FLAG_NO_URPF),
                                                  rpaths);

        fib_path_list_lock(*pli);
        fib_path_list_unlock(old_pli);

        bier_disp_entry_restack(bde, pproto);
    }

    /*
     * if there are no path-list defined for any payload protocol
     * then this entry is OK for removal
     */
    int remove = 1;

    FOR_EACH_BIER_HDR_PROTO(pproto)
    {
        if (FIB_NODE_INDEX_INVALID != bde->bde_pl[pproto])
        {
            remove = 0;
            break;
        }
    }

    return (remove);
}

u8*
format_bier_disp_entry (u8* s, va_list *args)
{
    index_t bdei = va_arg (*args, index_t);
    u32 indent = va_arg(*args, u32);
    bier_show_flags_t flags = va_arg(*args, bier_show_flags_t);
    bier_hdr_proto_id_t pproto;
    bier_disp_entry_t *bde;

    bde = bier_disp_entry_get(bdei);

    s = format(s, "bier-disp:[%d]", bdei);

    FOR_EACH_BIER_HDR_PROTO(pproto)
    {
        if (INDEX_INVALID != bde->bde_pl[pproto])
        {
            s = format(s, "\n");
            s = fib_path_list_format(bde->bde_pl[pproto], s);

            if (flags & BIER_SHOW_DETAIL)
            {
                s = format(s, "\n%UForwarding:",
                           format_white_space, indent);
                s = format(s, "\n%Urpf-id:%d",
                           format_white_space, indent+1,
                           bde->bde_fwd[pproto].bde_rpf_id);
                s = format(s, "\n%U%U",
                           format_white_space, indent+1,
                           format_dpo_id, &bde->bde_fwd[pproto].bde_dpo, indent+2);
            }
        }
    }
    return (s);
}

void
bier_disp_entry_contribute_forwarding (index_t bdei,
                                       dpo_id_t *dpo)
{
    dpo_set(dpo, DPO_BIER_DISP_ENTRY, DPO_PROTO_BIER, bdei);
}

const static char* const bier_disp_entry_bier_nodes[] =
{
    "bier-disp-dispatch",
    NULL,
};

const static char* const * const bier_disp_entry_nodes[DPO_PROTO_NUM] =
{
    [DPO_PROTO_BIER]  = bier_disp_entry_bier_nodes,
};

static void
bier_disp_entry_dpo_lock (dpo_id_t *dpo)
{
    bier_disp_entry_lock(dpo->dpoi_index);
}

static void
bier_disp_entry_dpo_unlock (dpo_id_t *dpo)
{
    bier_disp_entry_unlock(dpo->dpoi_index);
}

static void
bier_disp_entry_dpo_mem_show (void)
{
    fib_show_memory_usage("BIER dispositon",
                          pool_elts(bier_disp_entry_pool),
                          pool_len(bier_disp_entry_pool),
                          sizeof(bier_disp_entry_t));
}

static u8*
format_bier_disp_entry_dpo (u8* s, va_list *ap)
{
    index_t index = va_arg(*ap, index_t);
    u32 indent = va_arg(*ap, u32);

    s = format(s, "%U", format_bier_disp_entry, index, indent, BIER_SHOW_DETAIL);

    return (s);
}

const static dpo_vft_t bier_disp_entry_vft = {
    .dv_lock = bier_disp_entry_dpo_lock,
    .dv_unlock = bier_disp_entry_dpo_unlock,
    .dv_format = format_bier_disp_entry_dpo,
    .dv_mem_show = bier_disp_entry_dpo_mem_show,
};

clib_error_t *
bier_disp_entry_db_module_init (vlib_main_t *vm)
{
    dpo_register(DPO_BIER_DISP_ENTRY,
                 &bier_disp_entry_vft,
                 bier_disp_entry_nodes);

    return (NULL);
}

VLIB_INIT_FUNCTION (bier_disp_entry_db_module_init);

static clib_error_t *
show_bier_disp_entry (vlib_main_t * vm,
               unformat_input_t * input,
               vlib_cli_command_t * cmd)
{
    index_t bdei;

    bdei = INDEX_INVALID;

    while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
        if (unformat (input, "%d", &bdei))
            ;
        else
        {
            break;
        }
    }

    if (INDEX_INVALID == bdei)
    {
        return (NULL);
    }
    else
    {
        vlib_cli_output(vm, "%U", format_bier_disp_entry, bdei, 1,
                        BIER_SHOW_DETAIL);
    }
    return (NULL);
}

VLIB_CLI_COMMAND (show_bier_disp_entry_node, static) = {
    .path = "show bier disp entry",
    .short_help = "show bier disp entry index",
    .function = show_bier_disp_entry,
};
