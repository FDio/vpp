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

#include <vppinfra/vec.h>

#include <vnet/bier/bier_table.h>
#include <vnet/bier/bier_entry.h>
#include <vnet/bier/bier_update.h>
#include <vnet/bier/bier_fmask_db.h>
#include <vnet/bier/bier_fmask.h>

#include <vnet/fib/mpls_fib.h>
#include <vnet/mpls/mpls.h>
#include <vnet/fib/fib_path_list.h>

/**
 * Memory pool of all the allocated tables
 */
bier_table_t *bier_table_pool;

/**
 * DB store of all BIER tables index by SD/set/hdr-len
 */
static uword *bier_tables_by_key;

/**
 * The magic number of BIER ECMP tables to create.
 * The load-balance distribution algorithm will use a power of 2
 * for the number of buckets, which constrains the choice.
 */
#define BIER_N_ECMP_TABLES 16

static inline index_t
bier_table_get_index (const bier_table_t *bt)
{
    return (bt - bier_table_pool);
}

int
bier_table_is_main (const bier_table_t *bt)
{
    return (BIER_ECMP_TABLE_ID_MAIN == bt->bt_id.bti_ecmp);
}

/*
 * Construct the key to use to find a BIER table
 * in the global hash map
 */
static u32
bier_table_mk_key (const bier_table_id_t *id)
{
    /*
     * the set and sub-domain Ids are 8 bit values.
     * we have space for ECMP table ID and talbe type (SPF/TE)
     * for later
     */
    u32 key = ((id->bti_sub_domain << 24)  |
               (id->bti_set << 16) |
               (id->bti_ecmp << 8) |
               (id->bti_hdr_len << 4) |
               (id->bti_type));

    return (key);
}

static void
bier_table_init (bier_table_t *bt,
                 const bier_table_id_t *id,
                 mpls_label_t ll)
{
    u32 num_entries;

    bt->bt_lfei = FIB_NODE_INDEX_INVALID;
    bt->bt_id = *id;
    bt->bt_ll = ll;
    num_entries = bier_hdr_len_id_to_num_bits(bt->bt_id.bti_hdr_len);

    /*
     * create the lookup table of entries.
     */
    if (bier_table_is_main(bt))
    {
        vec_validate_init_empty_aligned(bt->bt_entries,
                                        num_entries,
                                        INDEX_INVALID,
                                        CLIB_CACHE_LINE_BYTES);
        fib_table_find_or_create_and_lock(FIB_PROTOCOL_MPLS,
                                          MPLS_FIB_DEFAULT_TABLE_ID,
                                          FIB_SOURCE_BIER);
    }
    else
    {
        vec_validate_init_empty_aligned(bt->bt_fmasks,
                                        num_entries,
                                        INDEX_INVALID,
                                        CLIB_CACHE_LINE_BYTES);
    }
}

static void
bier_table_rm_lfib (bier_table_t *bt)
{
    if (FIB_NODE_INDEX_INVALID != bt->bt_lfei)
    {
        fib_table_entry_delete_index(bt->bt_lfei,
                                     FIB_SOURCE_BIER);
    }
    bt->bt_lfei = FIB_NODE_INDEX_INVALID;
}

static void
bier_table_destroy (bier_table_t *bt)
{
    if (bier_table_is_main(bt))
    {
        index_t *bei;

        fib_path_list_unlock(bt->bt_pl);
        bt->bt_pl = FIB_NODE_INDEX_INVALID;
        /*
         * unresolve/remove all entries from the table
         */
        vec_foreach (bei, bt->bt_entries)
        {
            if (INDEX_INVALID != *bei)
            {
                bier_entry_delete(*bei);
            }
        }
        vec_free (bt->bt_entries);
        fib_table_unlock(fib_table_find(FIB_PROTOCOL_MPLS,
                                        MPLS_FIB_DEFAULT_TABLE_ID),
                         FIB_PROTOCOL_MPLS,
                         FIB_SOURCE_BIER);
    }
    else
    {
        index_t *bfmi;

        /*
         * unlock any fmasks
         */
        vec_foreach (bfmi, bt->bt_fmasks)
        {
            bier_fmask_unlock(*bfmi);
        }
        vec_free(bt->bt_fmasks);
    }

    hash_unset(bier_tables_by_key,
               bier_table_mk_key(&bt->bt_id));
    pool_put(bier_table_pool, bt);
}

static void
bier_table_lock_i (bier_table_t *bt)
{
    bt->bt_locks++;
}

static void
bier_table_unlock_i (bier_table_t *bt)
{
    bt->bt_locks--;

    if (0 == bt->bt_locks)
    {
        bier_table_rm_lfib(bt);
        bier_table_destroy(bt);
    }
}

void
bier_table_unlock (const bier_table_id_t *bti)
{
    uword *p;
    u32 key;

    key = bier_table_mk_key(bti);

    p = hash_get (bier_tables_by_key, key);

    if (NULL != p) {
        bier_table_unlock_i(bier_table_get(p[0]));
    }
}

static void
bier_table_mk_lfib (bier_table_t *bt)
{
    /*
     * Add a new MPLS lfib entry
     */
    if (MPLS_LABEL_INVALID != bt->bt_ll) {
        fib_prefix_t pfx = {
            .fp_proto = FIB_PROTOCOL_MPLS,
            .fp_len = 21,
            .fp_label = bt->bt_ll,
            .fp_eos = MPLS_EOS,
            .fp_payload_proto = DPO_PROTO_BIER,
        };
        u32 mpls_fib_index;
        dpo_id_t dpo = DPO_INVALID;

        /*
         * stack the entry on the forwarding chain prodcued by the
         * path-list via the ECMP tables.
         */
        fib_path_list_contribute_forwarding(bt->bt_pl,
                                            FIB_FORW_CHAIN_TYPE_BIER,
                                            &dpo);

        mpls_fib_index = fib_table_find(FIB_PROTOCOL_MPLS,
                                        MPLS_FIB_DEFAULT_TABLE_ID);
        bt->bt_lfei = fib_table_entry_special_dpo_add(mpls_fib_index,
                                                      &pfx,
                                                      FIB_SOURCE_BIER,
                                                      FIB_ENTRY_FLAG_EXCLUSIVE,
                                                      &dpo);
        dpo_reset(&dpo);
    }
}

static bier_table_t *
bier_table_find (const bier_table_id_t *bti)
{
    uword *p;
    u32 key;

    key = bier_table_mk_key(bti);

    p = hash_get(bier_tables_by_key, key);

    if (NULL != p)
    {
        return (bier_table_get(p[0]));
    }

    return (NULL);
}

static bier_table_t *
bier_table_mk_ecmp (index_t bti)
{
    fib_route_path_t *rpaths;
    fib_node_index_t pli;
    bier_table_t *bt;
    int ii;

    rpaths = NULL;
    bt = bier_table_get(bti);

    vec_validate(rpaths, BIER_N_ECMP_TABLES-1);

    vec_foreach_index(ii, rpaths)
    {
        rpaths[ii].frp_bier_tbl = bt->bt_id;
        rpaths[ii].frp_bier_tbl.bti_ecmp = ii;
        rpaths[ii].frp_flags = FIB_ROUTE_PATH_BIER_TABLE;
    }

    /*
     * no oppotunity to share, this the resolving ECMP tables are unique
     * to this table.
     * no need to be a child of the path list, we can do nothing with any
     * notifications it would generate [not that it will].
     */
    pli = fib_path_list_create(FIB_PATH_LIST_FLAG_NO_URPF, rpaths);
    fib_path_list_lock(pli);

    /*
     * constructing the path-list will have created many more BIER tables,
     * so this main table will no doubt have re-alloc.
     */
    bt = bier_table_get(bti);
    bt->bt_pl = pli;

    vec_free(rpaths);

    return (bt);
}

index_t
bier_table_add_or_lock (const bier_table_id_t *btid,
                        mpls_label_t local_label)
{
    bier_table_t *bt;
    index_t bti;

    bt = bier_table_find(btid);

    if (NULL != bt) {
        /*
         * modify an existing table.
         * change the lfib entry to the new local label
         */
        if (bier_table_is_main(bt) &&
            (local_label != MPLS_LABEL_INVALID))
        {
            bier_table_rm_lfib(bt);

            bt->bt_ll = local_label;
            bier_table_mk_lfib(bt);
        }
        bti = bier_table_get_index(bt);
    }
    else
    {
        /*
         * add a new table
         */
        u32 key;

        key = bier_table_mk_key(btid);

        pool_get_aligned(bier_table_pool, bt, CLIB_CACHE_LINE_BYTES);
        bier_table_init(bt, btid, local_label);

        hash_set(bier_tables_by_key, key, bier_table_get_index(bt));
        bti = bier_table_get_index(bt);

        if (bier_table_is_main(bt))
        {
            bt = bier_table_mk_ecmp(bti);
            bier_table_mk_lfib(bt);
        }
    }

    bier_table_lock_i(bt);

    return (bti);
}

index_t
bier_table_ecmp_create_and_lock (const bier_table_id_t *btid)
{
    return (bier_table_add_or_lock(btid, MPLS_LABEL_INVALID));
}

void
bier_table_ecmp_unlock (index_t bti)
{
    bier_table_unlock_i(bier_table_get(bti));
}

static void
bier_table_dpo_lock (dpo_id_t *dpo)
{
}

static void
bier_table_dpo_unlock (dpo_id_t *dpo)
{
}

static void
bier_table_dpo_mem_show (void)
{
    fib_show_memory_usage("BIER-table",
                          pool_elts(bier_table_pool),
                          pool_len(bier_table_pool),
                          sizeof(bier_table_t));
}
static u8 *
format_bier_table_dpo (u8 *s, va_list *ap)
{
    index_t bti = va_arg(*ap, index_t);
    bier_table_t *bt;

    bt = bier_table_get(bti);

    return (format(s, "[%U]", format_bier_table_id, &bt->bt_id));
}

const static dpo_vft_t bier_table_dpo_vft = {
    .dv_lock = bier_table_dpo_lock,
    .dv_unlock = bier_table_dpo_unlock,
    .dv_format = format_bier_table_dpo,
    .dv_mem_show = bier_table_dpo_mem_show,
};

const static char *const bier_table_mpls_nodes[] =
{
    "bier-input",
    NULL
};
const static char * const * const bier_table_nodes[DPO_PROTO_NUM] =
{
    [DPO_PROTO_BIER] = bier_table_mpls_nodes,
};

static clib_error_t *
bier_table_module_init (vlib_main_t *vm)
{
    dpo_register(DPO_BIER_TABLE, &bier_table_dpo_vft, bier_table_nodes);

    return (NULL);
}

VLIB_INIT_FUNCTION (bier_table_module_init);

const bier_table_id_t *
bier_table_get_id (index_t bti)
{
    bier_table_t *bt;

    bt = bier_table_get(bti);

    return (&bt->bt_id);
}

static void
bier_table_insert (bier_table_t *bt,
                   bier_bp_t bp,
                   index_t bei)
{
    bt->bt_entries[BIER_BP_TO_INDEX(bp)] = bei;
}

static void
bier_table_remove (bier_table_t *bt,
                   bier_bp_t bp)
{
    bt->bt_entries[BIER_BP_TO_INDEX(bp)] = INDEX_INVALID;
}

void
bier_table_route_add (const bier_table_id_t *btid,
                      bier_bp_t bp,
                      fib_route_path_t *brps)
{
    index_t bfmi, bti, bei, *bfmip, *bfmis = NULL;
    fib_route_path_t *brp;
    bier_table_t *bt;

    bt = bier_table_find(btid);

    if (NULL == bt) {
        return;
    }

    bti = bier_table_get_index(bt);
    bei = bier_table_lookup(bt, bp);

    /*
     * set the FIB index in the path to the BIER table index
     */
    vec_foreach(brp, brps)
    {
        bier_fmask_id_t fmid = {
            .bfmi_nh = brp->frp_addr,
            .bfmi_hdr_type = BIER_HDR_O_MPLS,
        };
        bfmi = bier_fmask_db_find_or_create_and_lock(bier_table_get_index(bt),
                                                     &fmid,
                                                     brp);

        brp->frp_bier_fib_index = bti;
        vec_add1(bfmis, bfmi);
    }

    if (INDEX_INVALID == bei)
    {
        bei = bier_entry_create(bti, bp);
        bier_table_insert(bt, bp, bei);
    }
    bier_entry_path_add(bei, brps);

    vec_foreach(bfmip, bfmis)
    {
        bier_fmask_unlock(*bfmip);
    }
    vec_free(bfmis);
}

void
bier_table_route_remove (const bier_table_id_t *bti,
                         bier_bp_t bp,
                         fib_route_path_t *brps)
{
    fib_route_path_t *brp = NULL;
    bier_table_t *bt;
    index_t bei;

    bt = bier_table_find(bti);

    if (NULL == bt) {
        return;
    }

    bei = bier_table_lookup(bt, bp);

    if (INDEX_INVALID == bei)
    {
        /* no such entry */
        return;
    }

    vec_foreach(brp, brps)
    {
        brp->frp_bier_fib_index = bier_table_get_index(bt);
    }

    if (0 == bier_entry_path_remove(bei, brps))
    {
        /* 0 remaining paths */
        bier_table_remove(bt, bp);
        bier_entry_delete(bei);
    }
}

void
bier_table_contribute_forwarding (index_t bti,
                                  dpo_id_t *dpo)
{
    bier_table_t *bt;

    bt = bier_table_get(bti);

    if (BIER_ECMP_TABLE_ID_MAIN == bt->bt_id.bti_ecmp)
    {
        /*
         * return the load-balance for the ECMP tables
         */
        fib_path_list_contribute_forwarding(bt->bt_pl,
                                            FIB_FORW_CHAIN_TYPE_BIER,
                                            dpo);
    }
    else
    {
        dpo_set(dpo, DPO_BIER_TABLE, DPO_PROTO_BIER, bti);
    }
}

typedef struct bier_table_ecmp_walk_ctx_t_
{
    bier_table_ecmp_walk_fn_t fn;
    void *ctx;
} bier_table_ecmp_walk_ctx_t;

static fib_path_list_walk_rc_t
bier_table_ecmp_walk_path_list (fib_node_index_t pl_index,
                                fib_node_index_t path_index,
                                void *arg)
{
    bier_table_ecmp_walk_ctx_t *ctx = arg;

    ctx->fn(fib_path_get_resolving_index(path_index), ctx->ctx);
    /* continue */
    return (FIB_PATH_LIST_WALK_CONTINUE);
}

void
bier_table_ecmp_walk (index_t bti,
                      bier_table_ecmp_walk_fn_t fn,
                      void *ctx)
{
    bier_table_ecmp_walk_ctx_t ewc = {
        .fn = fn,
        .ctx = ctx,
    };
    bier_table_t *bt;

    bt = bier_table_get(bti);

    fib_path_list_walk(bt->bt_pl,
                       bier_table_ecmp_walk_path_list,
                       &ewc);
}

void
bier_table_ecmp_set_fmask (index_t bti,
                           bier_bp_t bp,
                           index_t bfmi)
{
    bier_table_t *bt;

    bt = bier_table_get(bti);

    /*
     * we hold a lock for fmasks in the table
     */
    bier_fmask_lock(bfmi);
    bier_fmask_unlock(bt->bt_fmasks[BIER_BP_TO_INDEX(bp)]);

    bt->bt_fmasks[BIER_BP_TO_INDEX(bp)] = bfmi;
}

u8 *
format_bier_table_entry (u8 *s, va_list *ap)
{
    index_t bti = va_arg(*ap, index_t);
    bier_bp_t bp = va_arg(*ap, bier_bp_t);
    bier_table_t *bt;
    bt = bier_table_get(bti);

    if (bier_table_is_main(bt))
    {
        index_t bei;

        bei = bier_table_lookup(bier_table_get(bti), bp);

        if (INDEX_INVALID != bei)
        {
            s = format(s, "%U", format_bier_entry, bei,
                       BIER_SHOW_DETAIL);
        }
    }
    else
    {
        index_t bfmi;

        bfmi = bier_table_fwd_lookup(bier_table_get(bti), bp);

        if (INDEX_INVALID != bfmi)
        {
            s = format(s, "%U", format_bier_fmask, bfmi,
                       BIER_SHOW_DETAIL);
        }
    }
    return (s);
}

u8 *
format_bier_table (u8 *s, va_list *ap)
{
    index_t bti = va_arg(*ap, index_t);
    bier_show_flags_t flags = va_arg(*ap, bier_show_flags_t);
    bier_table_t *bt;

    if (pool_is_free_index(bier_table_pool, bti))
    {
        return (format(s, "No BIER f-mask %d", bti));
    }

    bt = bier_table_get(bti);

    s = format(s, "[@%d] bier-table:[%U local-label:%U]",
               bti,
               format_bier_table_id, &bt->bt_id,
               format_mpls_unicast_label, bt->bt_ll);

    if (flags & BIER_SHOW_DETAIL)
    {
        s = format(s, " locks:%d", bt->bt_locks);
    }
    s = format(s, "]");

    if (flags & BIER_SHOW_DETAIL)
    {
        if (bier_table_is_main(bt))
        {
            index_t *bei;

            vec_foreach (bei, bt->bt_entries)
            {
                if (INDEX_INVALID != *bei)
                {
                    s = format(s, "\n%U", format_bier_entry, *bei, 2);
                }
            }
        }
        else
        {
            u32 ii;

            vec_foreach_index (ii, bt->bt_fmasks)
            {
                if (INDEX_INVALID != bt->bt_fmasks[ii])
                {
                    s = format(s, "\n bp:%d\n %U", ii,
                               format_bier_fmask, bt->bt_fmasks[ii], 2);
                }
            }
        }
    }

    return (s);
}

void
bier_table_show_all (vlib_main_t * vm,
                     bier_show_flags_t flags)
{
    if (!pool_elts(bier_table_pool))
    {
        vlib_cli_output (vm, "No BIER tables");
    }
    else
    {
        int ii;

        pool_foreach_index(ii, bier_table_pool,
        ({
            vlib_cli_output (vm, "%U", format_bier_table, ii, flags);
        }));
    }
}

void
bier_tables_walk (bier_tables_walk_fn_t fn,
                  void *ctx)
{
    ASSERT(0);
}


void
bier_table_walk (const bier_table_id_t *bti,
                 bier_table_walk_fn_t fn,
                 void *ctx)
{
    bier_table_t *bt;
    bier_entry_t *be;
    index_t *bei;

    bt = bier_table_find(bti);

    if (NULL == bt)
    {
        return;
    }

    vec_foreach (bei, bt->bt_entries)
    {
        if (INDEX_INVALID != *bei)
        {
            be = bier_entry_get(*bei);

            fn(bt, be, ctx);
        }
    }
}
