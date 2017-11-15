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

#include <vnet/bier/bier_disp_table.h>
#include <vnet/bier/bier_disp_entry.h>

/**
 * memory pool for disposition tables
 */
bier_disp_table_t *bier_disp_table_pool;

/**
 * Hash table to map client table IDs to VPP index
 */
static uword *bier_disp_table_id_to_index;

static index_t
bier_disp_table_get_index (const bier_disp_table_t *bdt)
{
    return (bdt - bier_disp_table_pool);
}

static void
bier_disp_table_lock_i (bier_disp_table_t *bdt)
{
    bdt->bdt_locks++;
}

index_t
bier_disp_table_find(u32 table_id)
{
    uword *p;

    p = hash_get(bier_disp_table_id_to_index, table_id);

    if (NULL != p)
    {
        return (p[0]);
    }

    return (INDEX_INVALID);
}

index_t
bier_disp_table_add_or_lock (u32 table_id)
{
    bier_disp_table_t *bdt;
    index_t bdti;

    bdti = bier_disp_table_find(table_id);

    if (INDEX_INVALID == bdti)
    {
        pool_get_aligned(bier_disp_table_pool, bdt,
                         CLIB_CACHE_LINE_BYTES);

        bdt->bdt_table_id = table_id;
        bdt->bdt_locks = 0;

        hash_set(bier_disp_table_id_to_index, table_id,
                 bier_disp_table_get_index(bdt));

        /**
         * Set the result for each entry in the DB to be invalid
         */
        memset(bdt->bdt_db, 0xff, sizeof(bdt->bdt_db));
    }
    else
    {
        bdt = pool_elt_at_index(bier_disp_table_pool, bdti);
    }

    bier_disp_table_lock_i(bdt);

    return (bier_disp_table_get_index(bdt));
}

void
bier_disp_table_unlock_w_table_id (u32 table_id)
{
    index_t bdti;

    bdti = bier_disp_table_find(table_id);

    if (INDEX_INVALID != bdti)
    {
        bier_disp_table_unlock(bdti);
    }
}

void
bier_disp_table_unlock (index_t bdti)
{
    bier_disp_table_t *bdt;

    bdt = bier_disp_table_get(bdti);

    bdt->bdt_locks--;

    if (0 == bdt->bdt_locks)
    {
        u32 ii;

        for (ii = 0; ii < BIER_BP_MAX; ii++)
        {
            bier_disp_entry_unlock(bdt->bdt_db[ii]);
        }
        hash_unset(bier_disp_table_id_to_index, bdt->bdt_table_id);
        pool_put(bier_disp_table_pool, bdt);
    }
}

void
bier_disp_table_lock (index_t bdti)
{
    bier_disp_table_lock_i(bier_disp_table_get(bdti));
}

void
bier_disp_table_contribute_forwarding (index_t bdti,
                                       dpo_id_t *dpo)
{
    dpo_set(dpo,
            DPO_BIER_DISP_TABLE,
            DPO_PROTO_BIER,
            bdti);
}


u8*
format_bier_disp_table (u8* s, va_list *ap)
{
    index_t bdti = va_arg(*ap, index_t);
    u32 indent = va_arg(*ap, u32);
    bier_show_flags_t flags = va_arg(*ap, bier_show_flags_t);
    bier_disp_table_t *bdt;

    bdt = bier_disp_table_get(bdti);

    s = format(s, "bier-disp-table:[%d]; table-id:%d locks:%d",
               bdti, bdt->bdt_table_id, bdt->bdt_locks);

    if (flags & BIER_SHOW_DETAIL)
    {
        u32 ii;

        for (ii = 0; ii < BIER_BP_MAX; ii++)
        {
            if (INDEX_INVALID != bdt->bdt_db[ii])
            {
                u16 src = ii;
                s = format(s, "\n%Usrc:%d", format_white_space, indent,
                           clib_host_to_net_u16(src));
                s = format(s, "\n%U%U", format_white_space, indent+2,
                           format_bier_disp_entry, bdt->bdt_db[ii],
                           indent+4, BIER_SHOW_BRIEF);
            }
        }
    }
    return (s);
}

static u8*
format_bier_disp_table_dpo (u8* s, va_list *ap)
{
    index_t bdti = va_arg(*ap, index_t);
    u32 indent = va_arg(*ap, u32);

    return (format(s, "%U",
                   format_bier_disp_table, bdti, indent,
                   BIER_SHOW_BRIEF));
}

static void
bier_disp_table_entry_insert (index_t bdti,
                              bier_bp_t src,
                              index_t bdei)
{
    bier_disp_table_t *bdt;

    bdt = bier_disp_table_get(bdti);
    bdt->bdt_db[clib_host_to_net_u16(src)] = bdei;
}

static void
bier_disp_table_entry_remove (index_t bdti,
                              bier_bp_t src)
{
    bier_disp_table_t *bdt;

    bdt = bier_disp_table_get(bdti);
    bdt->bdt_db[clib_host_to_net_u16(src)] = INDEX_INVALID;
}

static index_t
bier_disp_table_lookup_hton(index_t bdti,
                            bier_bp_t bp)
{
    bier_hdr_src_id_t src = bp;

    return (bier_disp_table_lookup(bdti, clib_host_to_net_u32(src)));
}

void
bier_disp_table_entry_path_add (u32 table_id,
                                bier_bp_t src,
                                bier_hdr_proto_id_t payload_proto,
                                const fib_route_path_t *rpaths)
{
    index_t bdti, bdei;

    bdti = bier_disp_table_find(table_id);

    if (INDEX_INVALID == bdti)
    {
        return;
    }

    bdei = bier_disp_table_lookup_hton(bdti, src);

    if (INDEX_INVALID == bdei)
    {
        bdei = bier_disp_entry_add_or_lock();
        bier_disp_table_entry_insert(bdti, src, bdei);
    }

    bier_disp_entry_path_add(bdei, payload_proto, rpaths);
}

void
bier_disp_table_entry_path_remove (u32 table_id,
                                   bier_bp_t src,
                                   bier_hdr_proto_id_t payload_proto,
                                   const fib_route_path_t *rpath)
{
    index_t bdti, bdei;

    bdti = bier_disp_table_find(table_id);

    if (INDEX_INVALID == bdti)
    {
        return;
    }

    bdei = bier_disp_table_lookup_hton(bdti, src);

    if (INDEX_INVALID != bdei)
    {
        int remove;

        remove = bier_disp_entry_path_remove(bdei, payload_proto, rpath);

        if (remove)
        {
            bier_disp_table_entry_remove(bdti, src);
            bier_disp_entry_unlock(bdei);
        }
    }
}

void
bier_disp_table_walk (u32 table_id,
                      bier_disp_table_walk_fn_t fn,
                      void *ctx)
{
    const bier_disp_table_t *bdt;
    const bier_disp_entry_t *bde;
    index_t bdti;
    u32 ii;

    bdti = bier_disp_table_find(table_id);

    if (INDEX_INVALID != bdti)
    {
        bdt = bier_disp_table_get(bdti);

        for (ii = 0; ii < BIER_BP_MAX; ii++)
        {
            if (INDEX_INVALID != bdt->bdt_db[ii])
            {
                u16 src = ii;

                bde = bier_disp_entry_get(bdt->bdt_db[ii]);

                fn(bdt, bde, clib_host_to_net_u16(src), ctx);
            }
        }
    }
}

static void
bier_disp_table_dpo_lock (dpo_id_t *dpo)
{
    bier_disp_table_lock(dpo->dpoi_index);
}

static void
bier_disp_table_dpo_unlock (dpo_id_t *dpo)
{
    bier_disp_table_unlock(dpo->dpoi_index);
}

static void
bier_disp_table_dpo_mem_show (void)
{
    fib_show_memory_usage("BIER disposition table",
                          pool_elts(bier_disp_table_pool),
                          pool_len(bier_disp_table_pool),
                          sizeof(bier_disp_table_t));
}

const static dpo_vft_t bier_disp_table_dpo_vft = {
    .dv_lock = bier_disp_table_dpo_lock,
    .dv_unlock = bier_disp_table_dpo_unlock,
    .dv_mem_show = bier_disp_table_dpo_mem_show,
    .dv_format = format_bier_disp_table_dpo,
};

const static char *const bier_disp_table_bier_nodes[] =
{
    "bier-disp-lookup",
    NULL
};

const static char * const * const bier_disp_table_nodes[DPO_PROTO_NUM] =
{
    [DPO_PROTO_BIER] = bier_disp_table_bier_nodes,
};

clib_error_t *
bier_disp_table_module_init (vlib_main_t *vm)
{
    dpo_register(DPO_BIER_DISP_TABLE,
                 &bier_disp_table_dpo_vft,
                 bier_disp_table_nodes);

    bier_disp_table_id_to_index = hash_create(0, sizeof(index_t));

    return (NULL);
}

VLIB_INIT_FUNCTION (bier_disp_table_module_init);

static clib_error_t *
show_bier_disp_table (vlib_main_t * vm,
                      unformat_input_t * input,
                      vlib_cli_command_t * cmd)
{
    bier_disp_table_t *bdt;
    index_t bdti;

    bdti = INDEX_INVALID;

    while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
        if (unformat (input, "%d", &bdti))
            ;
        else if (unformat (input, "%d", &bdti))
            ;
        else
        {
            break;
        }
    }

    if (INDEX_INVALID == bdti)
    {
        pool_foreach(bdt, bier_disp_table_pool,
        ({
            vlib_cli_output(vm, "%U", format_bier_disp_table,
                            bier_disp_table_get_index(bdt),
                            1,
                            BIER_SHOW_BRIEF);
        }));
    }
    else
    {
        vlib_cli_output(vm, "%U", format_bier_disp_table, bdti, 1,
                        BIER_SHOW_DETAIL);
    }
    return (NULL);
}

VLIB_CLI_COMMAND (show_bier_disp_table_node, static) = {
    .path = "show bier disp table",
    .short_help = "show bier disp table [index]",
    .function = show_bier_disp_table,
};
