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
 * The key used in the fmask DB to compare fmask objects.
 * There is one global DB, so we need to use the table's ID and the fmasks ID
 */
typedef struct bier_fmask_db_key_t_ {
    bier_fmask_id_t bfmdbk_fm_id;
    index_t bfmdbk_tbl_id;
} bier_fmask_db_key_t;
// TODO packed?

/**
 * Single fmask DB
 */
static bier_fmask_db_t bier_fmask_db;


u32
bier_fmask_get_index (const bier_fmask_t *bfm)
{
    return (bfm - bier_fmask_db.bfdb_pool);
}

u32
bier_fmask_db_find_or_create_and_lock (index_t bti,
                                       const bier_fmask_id_t *fmid,
                                       const fib_route_path_t *rpath)
{
    bier_fmask_db_key_t key;
    u32 index;
    uword *p;

    /*
     * there be padding in that thar key, and it's
     * used as a memcmp in the mhash.
     */
    memset(&key, 0, sizeof(key));
    key.bfmdbk_tbl_id = bti;
    key.bfmdbk_fm_id = *fmid;

    index = INDEX_INVALID;
    p = mhash_get (&bier_fmask_db.bfdb_hash, &key);

    if (NULL == p)
    {
        /*
         * adding a new fmask object
         */
        index = bier_fmask_create_and_lock(fmid, bti, rpath);

        mhash_set (&bier_fmask_db.bfdb_hash, &key, index, 0 /*old_value*/);
    }
    else
    {
        index = p[0];
        bier_fmask_lock(index);
    }

    return (index);
}

u32
bier_fmask_db_find (index_t bti,
                    const bier_fmask_id_t *fmid)
{
    bier_fmask_db_key_t key;
    u32 index;
    uword *p;

    /*
     * there be padding in that thar key, and it's
     * used as a memcmp in the mhash.
     */
    memset(&key, 0, sizeof(key));
    key.bfmdbk_tbl_id = bti;
    key.bfmdbk_fm_id = *fmid;

    index = INDEX_INVALID;
    p = mhash_get(&bier_fmask_db.bfdb_hash, &key);

    if (NULL != p)
    {
        index = p[0];
    }

    return (index);
}

void
bier_fmask_db_remove (index_t bti,
                      const bier_fmask_id_t *fmid)
{
    bier_fmask_db_key_t key = {
        .bfmdbk_tbl_id = bti,
        .bfmdbk_fm_id = *fmid,
    };
    uword *p;

    p = mhash_get (&bier_fmask_db.bfdb_hash, &key);

    if (NULL == p) {
        /*
         * remove a non-exitant entry - oops
         */
        ASSERT (!"remove non-existant fmask");
    } else {
        mhash_unset (&(bier_fmask_db.bfdb_hash), &key, 0);
    }
}

clib_error_t *
bier_fmask_db_module_init (vlib_main_t *vm)
{
    mhash_init (&bier_fmask_db.bfdb_hash,
                sizeof(uword),
                sizeof(bier_fmask_db_key_t));

    return (NULL);
}

VLIB_INIT_FUNCTION (bier_fmask_db_module_init);
