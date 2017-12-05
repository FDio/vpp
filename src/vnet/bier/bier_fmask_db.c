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
    mhash_t bfdb_hash;

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
    memset(key, 0, sizeof(*key));

    /*
     * Pick the attributes from the path that make the FMask unique
     */
    if (FIB_ROUTE_PATH_UDP_ENCAP & rpath->frp_flags)
    {
        key->bfmi_id = rpath->frp_udp_encap_id;
    }
    else
    {
        key->bfmi_sw_if_index = rpath->frp_sw_if_index;
        memcpy(&key->bfmi_nh, &rpath->frp_addr, sizeof(rpath->frp_addr));
    }
    if (NULL == rpath->frp_label_stack)
    {
        key->bfmi_hdr_type = BIER_HDR_O_OTHER;
    }
    else
    {
        key->bfmi_hdr_type = BIER_HDR_O_MPLS;
    }
}

u32
bier_fmask_db_find (index_t bti,
                    const fib_route_path_t *rpath)
{
    bier_fmask_id_t fmid;
    uword *p;

    bier_fmask_db_mk_key(bti, rpath, &fmid);
    p = mhash_get(&bier_fmask_db.bfdb_hash, &fmid);

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
    p = mhash_get(&bier_fmask_db.bfdb_hash, &fmid);

    if (NULL == p)
    {
        bier_fmask_t *bfm;
        /*
         * adding a new fmask object
         */
        index = bier_fmask_create_and_lock(&fmid, rpath);
        bfm = bier_fmask_get(index);
        mhash_set(&bier_fmask_db.bfdb_hash, bfm->bfm_id, index, 0);
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

    p = mhash_get(&bier_fmask_db.bfdb_hash, fmid);

    if (NULL == p) {
        /*
         * remove a non-exitant entry - oops
         */
        ASSERT (!"remove non-existant fmask");
    } else {
        mhash_unset(&(bier_fmask_db.bfdb_hash), (void*)fmid, 0);
    }
}

clib_error_t *
bier_fmask_db_module_init (vlib_main_t *vm)
{
    mhash_init(&bier_fmask_db.bfdb_hash,
               sizeof(index_t),
               sizeof(bier_fmask_id_t));

    return (NULL);
}

VLIB_INIT_FUNCTION (bier_fmask_db_module_init);
