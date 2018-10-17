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

#include <vnet/bier/bier_fmask_db.h>
#include <vnet/bier/bier_fmask.h>

/**
 * Global Table of fmask objects
 * The key into this table includes the table's key and the fmask's key,
 * so there could be a DB per-table. But it is more efficient
 * at forwarding time to extract the fmask from a single global table
 * which is hot in dcache.
 *
 * The table's key is part of this DB key, since the fmasks therein build up
 * their forwarding mask based on the routes that resolve through
 * it, so cross polination would be bad.
 */
typedef struct bier_fmask_db_t_ {
    /**
     * hash table for underlying storage
     */
    uword *bfdb_hash;

    /**
     * Pool for memory
     */
    struct bier_fmask_t_ *bfdb_pool;
} bier_fmask_db_t;

/**
 * Single fmask DB
 */
static bier_fmask_db_t bier_fmask_db;


u32
bier_fmask_get_index (const bier_fmask_t *bfm)
{
    return (bfm - bier_fmask_db.bfdb_pool);
}

static void
bier_fmask_db_mk_key (index_t bti,
                      const fib_route_path_t *rpath,
                      bier_fmask_id_t *key)
{
    /*
     * Depending on what the ID is there may be padding.
     * This key will be memcmp'd in the mhash, so make sure it's all 0
     */
    clib_memset(key, 0, sizeof(*key));

    /*
     * Pick the attributes from the path that make the FMask unique
     */
    if (FIB_ROUTE_PATH_UDP_ENCAP & rpath->frp_flags)
    {
        key->bfmi_id = rpath->frp_udp_encap_id;
        key->bfmi_nh_type = BIER_NH_UDP;
    }
    else
    {
        memcpy(&key->bfmi_nh, &rpath->frp_addr, sizeof(rpath->frp_addr));
        key->bfmi_nh_type = BIER_NH_IP;
    }
    if (NULL == rpath->frp_label_stack)
    {
        key->bfmi_hdr_type = BIER_HDR_O_OTHER;
    }
    else
    {
        key->bfmi_hdr_type = BIER_HDR_O_MPLS;
    }
    key->bfmi_bti = bti;
}

u32
bier_fmask_db_find (index_t bti,
                    const fib_route_path_t *rpath)
{
    bier_fmask_id_t fmid;
    uword *p;

    bier_fmask_db_mk_key(bti, rpath, &fmid);
    p = hash_get_mem(bier_fmask_db.bfdb_hash, &fmid);

    if (NULL != p)
    {
        return (p[0]);
    }

    return (INDEX_INVALID);
}

u32
bier_fmask_db_find_or_create_and_lock (index_t bti,
                                       const fib_route_path_t *rpath)
{
    bier_fmask_id_t fmid;
    u32 index;
    uword *p;

    bier_fmask_db_mk_key(bti, rpath, &fmid);
    p = hash_get_mem(bier_fmask_db.bfdb_hash, &fmid);

    if (NULL == p)
    {
        bier_fmask_t *bfm;
        /*
         * adding a new fmask object
         */
        index = bier_fmask_create_and_lock(&fmid, rpath);
        bfm = bier_fmask_get(index);
        hash_set_mem(bier_fmask_db.bfdb_hash, bfm->bfm_id, index);
    }
    else
    {
        index = p[0];
        bier_fmask_lock(index);
    }

    return (index);
}

void
bier_fmask_db_remove (const bier_fmask_id_t *fmid)
{
    uword *p;

    p = hash_get_mem(bier_fmask_db.bfdb_hash, fmid);

    if (NULL == p) {
        /*
         * remove a non-exitant entry - oops
         */
        ASSERT (!"remove non-existant fmask");
    } else {
        hash_unset(bier_fmask_db.bfdb_hash, fmid);
    }
}

void
bier_fmask_db_walk (bier_fmask_walk_fn_t fn, void *ctx)
{
    CLIB_UNUSED (bier_fmask_id_t *fmid);
    uword *bfmi;

    hash_foreach(fmid, bfmi, bier_fmask_db.bfdb_hash,
    ({
        if (WALK_STOP == fn(*bfmi, ctx))
            break;
    }));
}

clib_error_t *
bier_fmask_db_module_init (vlib_main_t *vm)
{
    bier_fmask_db.bfdb_hash = hash_create_mem(0,
                                              sizeof(bier_fmask_id_t),
                                              sizeof(index_t));

    return (NULL);
}

VLIB_INIT_FUNCTION (bier_fmask_db_module_init);
