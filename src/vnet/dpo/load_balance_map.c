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
/**
 * @brief
 */
#include <vnet/fib/fib_path.h>
#include <vnet/fib/fib_node_list.h>
#include <vnet/dpo/load_balance_map.h>
#include <vnet/dpo/load_balance.h>

/**
 * A hash-table of load-balance maps by path index.
 * this provides the fast lookup of the LB map when a path goes down
 */
static uword *lb_maps_by_path_index;

/**
 * A hash-table of load-balance maps by set of paths.
 * This provides the LB map sharing.
 * LB maps do not necessarily use all the paths in the list, since
 * the entry that is requesting the map, may not have an out-going
 * label for each of the paths.
 */
static uword *load_balance_map_db;

typedef enum load_balance_map_path_flags_t_
{
    LOAD_BALANCE_MAP_PATH_UP     = (1 << 0),
    LOAD_BALANCE_MAP_PATH_USABLE = (1 << 1),
} __attribute__ ((packed)) load_balance_map_path_flags_t;

typedef struct load_balance_map_path_t_ {
    /**
     * Index of the path
     */
    fib_node_index_t lbmp_index;

    /**
     * Sibling Index in the list of all maps with this path index
     */
    fib_node_index_t lbmp_sibling;

    /**
     * the normalised wegiht of the path
     */
    u32 lbmp_weight;

    /**
     * The sate of the path
     */
    load_balance_map_path_flags_t lbmp_flags;
} load_balance_map_path_t;

/**
 * The global pool of LB maps
 */
load_balance_map_t *load_balance_map_pool;

/**
 * the logger
 */
vlib_log_class_t load_balance_map_logger;

/*
 * Debug macro
 */
#define LOAD_BALANCE_MAP_DBG(_pl, _fmt, _args...)               \
{                                                               \
    vlib_log_debug(load_balance_map_logger,                     \
                   "lbm:" _fmt,                                 \
                   ##_args);                                    \
}

static index_t
load_balance_map_get_index (load_balance_map_t *lbm)
{
    return (lbm - load_balance_map_pool);
}

u8*
format_load_balance_map (u8 *s, va_list * ap)
{
    index_t lbmi = va_arg(*ap, index_t);
    u32 indent = va_arg(*ap, u32);
    load_balance_map_t *lbm;
    u32 n_buckets, ii;

    lbm = load_balance_map_get(lbmi);
    n_buckets = vec_len(lbm->lbm_buckets);

    s = format(s, "load-balance-map: index:%d buckets:%d", lbmi, n_buckets);
    s = format(s, "\n%U index:", format_white_space, indent+2);
    for (ii = 0; ii < n_buckets; ii++)
    {
        s = format(s, "%5d", ii);
    }
    s = format(s, "\n%U   map:", format_white_space, indent+2);
    for (ii = 0; ii < n_buckets; ii++)
    {
        s = format(s, "%5d", lbm->lbm_buckets[ii]);
    }

    return (s);
}


static uword
load_balance_map_hash (load_balance_map_t *lbm)
{
    u32 old_lbm_hash, new_lbm_hash, hash;
    load_balance_map_path_t *lb_path;

    new_lbm_hash = old_lbm_hash = vec_len(lbm->lbm_paths);

    vec_foreach (lb_path, lbm->lbm_paths)
    {
        hash = lb_path->lbmp_index;
        hash_mix32(hash, old_lbm_hash, new_lbm_hash);
    }

    return (new_lbm_hash);
}

always_inline uword
load_balance_map_db_hash_key_from_index (uword index)
{
    return 1 + 2*index;
}

always_inline uword
load_balance_map_db_hash_key_is_index (uword key)
{
    return key & 1;
}

always_inline uword
load_balance_map_db_hash_key_2_index (uword key)
{
    ASSERT (load_balance_map_db_hash_key_is_index (key));
    return key / 2;
}

static load_balance_map_t*
load_balance_map_db_get_from_hash_key (uword key)
{
    load_balance_map_t *lbm;

    if (load_balance_map_db_hash_key_is_index (key))
    {
        index_t lbm_index;

        lbm_index = load_balance_map_db_hash_key_2_index(key);
        lbm = load_balance_map_get(lbm_index);
    }
    else
    {
        lbm = uword_to_pointer (key, load_balance_map_t *);
    }

    return (lbm);
}

static uword
load_balance_map_db_hash_key_sum (hash_t * h,
                                  uword key)
{
    load_balance_map_t *lbm;

    lbm = load_balance_map_db_get_from_hash_key(key);

    return (load_balance_map_hash(lbm));
}

static uword
load_balance_map_db_hash_key_equal (hash_t * h,
                                    uword key1,
                                    uword key2)
{
    load_balance_map_t *lbm1, *lbm2;

    lbm1 = load_balance_map_db_get_from_hash_key(key1);
    lbm2 = load_balance_map_db_get_from_hash_key(key2);

    return (load_balance_map_hash(lbm1) ==
            load_balance_map_hash(lbm2));
}

static index_t
load_balance_map_db_find (load_balance_map_t *lbm)
{
    uword *p;

    p = hash_get(load_balance_map_db, lbm);

    if (NULL != p)
    {
        return p[0];
    }

    return (FIB_NODE_INDEX_INVALID);
}

static void
load_balance_map_db_insert (load_balance_map_t *lbm)
{
    load_balance_map_path_t *lbmp;
    fib_node_list_t list;
    uword *p;

    ASSERT(FIB_NODE_INDEX_INVALID == load_balance_map_db_find(lbm));

    /*
     * insert into the DB based on the set of paths.
     */
    hash_set (load_balance_map_db,
              load_balance_map_db_hash_key_from_index(
                  load_balance_map_get_index(lbm)),
              load_balance_map_get_index(lbm));

    /*
     * insert into each per-path list.
     */
    vec_foreach(lbmp, lbm->lbm_paths)
    {
        p = hash_get(lb_maps_by_path_index, lbmp->lbmp_index);

        if (NULL == p)
        {
            list = fib_node_list_create();
            hash_set(lb_maps_by_path_index, lbmp->lbmp_index, list);
        }
        else
        {
            list = p[0];
        }

        lbmp->lbmp_sibling =
            fib_node_list_push_front(list,
                                     0, FIB_NODE_TYPE_FIRST,
                                     load_balance_map_get_index(lbm));
    }

    LOAD_BALANCE_MAP_DBG(lbm, "DB-inserted");
}

static void
load_balance_map_db_remove (load_balance_map_t *lbm)
{
    load_balance_map_path_t *lbmp;
    uword *p;

    ASSERT(FIB_NODE_INDEX_INVALID != load_balance_map_db_find(lbm));

    hash_unset(load_balance_map_db,
               load_balance_map_db_hash_key_from_index(
                   load_balance_map_get_index(lbm)));

    /*
     * remove from each per-path list.
     */
    vec_foreach(lbmp, lbm->lbm_paths)
    {
        p = hash_get(lb_maps_by_path_index, lbmp->lbmp_index);

        ALWAYS_ASSERT(NULL != p);

        fib_node_list_remove(p[0], lbmp->lbmp_sibling);
    }

    LOAD_BALANCE_MAP_DBG(lbm, "DB-removed");
}

/**
 * @brief from the paths that are usable, fill the Map.
 */
static void
load_balance_map_fill (load_balance_map_t *lbm)
{
    load_balance_map_path_t *lbmp;
    u32 n_buckets, bucket, ii, jj;
    u16 *tmp_buckets;

    tmp_buckets = NULL;
    n_buckets = vec_len(lbm->lbm_buckets);

    /*
     * run throught the set of paths once, and build a vector of the
     * indices that are usable. we do this is a scratch space, since we
     * need to refer to it multiple times as we build the real buckets.
     */
    vec_validate(tmp_buckets, n_buckets-1);

    bucket = jj = 0;
    vec_foreach (lbmp, lbm->lbm_paths)
    {
        if (fib_path_is_resolved(lbmp->lbmp_index))
        {
            for (ii = 0; ii < lbmp->lbmp_weight; ii++)
            {
                tmp_buckets[jj++] = bucket++;
            }
        }
        else
        {
            bucket += lbmp->lbmp_weight;
        }
    }
    _vec_len(tmp_buckets) = jj;

    /*
     * If the number of temporaries written is as many as we need, implying
     * all paths were up, then we can simply copy the scratch area over the
     * actual buckets' memory
     */
    if (jj == n_buckets)
    {
        memcpy(lbm->lbm_buckets,
               tmp_buckets,
               sizeof(lbm->lbm_buckets[0]) * n_buckets);
    }
    else
    {
        /*
         * one or more paths are down.
         */
        if (0 == vec_len(tmp_buckets))
        {
            /*
             * if the scratch area is empty, then no paths are usable.
             * they will all drop. so use them all, lest we account drops
             * against only one.
             */
            for (bucket = 0; bucket < n_buckets; bucket++)
            {
                lbm->lbm_buckets[bucket] = bucket;
            }
        }
        else
        {
            bucket = jj = 0;
            vec_foreach (lbmp, lbm->lbm_paths)
            {
                if (fib_path_is_resolved(lbmp->lbmp_index))
                {
                    for (ii = 0; ii < lbmp->lbmp_weight; ii++)
                    {
                        lbm->lbm_buckets[bucket] = bucket;
                        bucket++;
                    }
                }
                else
                {
                    /*
                     * path is unusable
                     * cycle through the scratch space selecting a index.
                     * this means we load balance, in the intended ratio,
                     * over the paths that are still usable.
                     */
                    for (ii = 0; ii < lbmp->lbmp_weight; ii++)
                    {
                        lbm->lbm_buckets[bucket] = tmp_buckets[jj];
                        jj = (jj + 1) % vec_len(tmp_buckets);
                        bucket++;
                    }
                }
            }
       }
    }

    vec_free(tmp_buckets);
}

static load_balance_map_t*
load_balance_map_alloc (const load_balance_path_t *paths)
{
    load_balance_map_t *lbm;
    u32 ii;
    vlib_main_t *vm;
    u8 did_barrier_sync;

    dpo_pool_barrier_sync (vm, load_balance_map_pool, did_barrier_sync);
    pool_get_aligned(load_balance_map_pool, lbm, CLIB_CACHE_LINE_BYTES);
    dpo_pool_barrier_release (vm, did_barrier_sync);

    clib_memset(lbm, 0, sizeof(*lbm));

    vec_validate(lbm->lbm_paths, vec_len(paths)-1);

    vec_foreach_index(ii, paths)
    {
        lbm->lbm_paths[ii].lbmp_index  = paths[ii].path_index;
        lbm->lbm_paths[ii].lbmp_weight = paths[ii].path_weight;
    }

    return (lbm);
}

static load_balance_map_t *
load_balance_map_init (load_balance_map_t *lbm,
                       u32 n_buckets,
                       u32 sum_of_weights)
{
    lbm->lbm_sum_of_norm_weights = sum_of_weights;
    vec_validate(lbm->lbm_buckets, n_buckets-1);

    load_balance_map_db_insert(lbm);

    load_balance_map_fill(lbm);

    load_balance_map_logger =
        vlib_log_register_class ("dpo", "load-balance-map");

    return (lbm);
}

static void
load_balance_map_destroy (load_balance_map_t *lbm)
{
    vec_free(lbm->lbm_paths);
    vec_free(lbm->lbm_buckets);
    pool_put(load_balance_map_pool, lbm);
}

index_t
load_balance_map_add_or_lock (u32 n_buckets,
                              u32 sum_of_weights,
                              const load_balance_path_t *paths)
{
    load_balance_map_t *tmp, *lbm;
    index_t lbmi;

    tmp = load_balance_map_alloc(paths);

    lbmi = load_balance_map_db_find(tmp);

    if (INDEX_INVALID == lbmi)
    {
        lbm = load_balance_map_init(tmp, n_buckets, sum_of_weights);
    }
    else
    {
        lbm = load_balance_map_get(lbmi);
        load_balance_map_destroy(tmp);
    }

    lbm->lbm_locks++;

    return (load_balance_map_get_index(lbm));
}

void
load_balance_map_lock (index_t lbmi)
{
    load_balance_map_t *lbm;

    lbm = load_balance_map_get(lbmi);

    lbm->lbm_locks++;
}

void
load_balance_map_unlock (index_t lbmi)
{
    load_balance_map_t *lbm;

    if (INDEX_INVALID == lbmi)
    {
        return;
    }

    lbm = load_balance_map_get(lbmi);

    lbm->lbm_locks--;

    if (0 == lbm->lbm_locks)
    {
        load_balance_map_db_remove(lbm);
        load_balance_map_destroy(lbm);
    }
}

static walk_rc_t
load_balance_map_path_state_change_walk (fib_node_ptr_t *fptr,
                                         void *ctx)
{
    load_balance_map_t *lbm;

    lbm = load_balance_map_get(fptr->fnp_index);

    load_balance_map_fill(lbm);

    return (WALK_CONTINUE);
}

/**
 * @brief the state of a path has changed (it has no doubt gone down).
 * This is the trigger to perform a PIC edge cutover and update the maps
 * to exclude this path.
 */
void
load_balance_map_path_state_change (fib_node_index_t path_index)
{
    uword *p;

    /*
     * re-stripe the buckets for each affect MAP
     */
    p = hash_get(lb_maps_by_path_index, path_index);

    if (NULL == p)
        return;

    fib_node_list_walk(p[0], load_balance_map_path_state_change_walk, NULL);
}

/**
 * @brief Make/add a new or lock an existing Load-balance map
 */
void
load_balance_map_module_init (void)
{
    load_balance_map_db =
        hash_create2 (/* elts */ 0,
                      /* user */ 0,
                      /* value_bytes */ sizeof (index_t),
                      load_balance_map_db_hash_key_sum,
                      load_balance_map_db_hash_key_equal,
                      /* format pair/arg */
                      0, 0);

    lb_maps_by_path_index = hash_create(0, sizeof(fib_node_list_t));
}

void
load_balance_map_show_mem (void)
{
    fib_show_memory_usage("Load-Balance Map",
			  pool_elts(load_balance_map_pool),
			  pool_len(load_balance_map_pool),
			  sizeof(load_balance_map_t));
}

static clib_error_t *
load_balance_map_show (vlib_main_t * vm,
                       unformat_input_t * input,
                       vlib_cli_command_t * cmd)
{
    index_t lbmi = INDEX_INVALID;

    while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat (input, "%d", &lbmi))
            ;
        else
            break;
    }

    if (INDEX_INVALID != lbmi)
    {
        vlib_cli_output (vm, "%U", format_load_balance_map, lbmi, 0);
    }
    else
    {
        load_balance_map_t *lbm;

        pool_foreach(lbm, load_balance_map_pool,
        ({
            vlib_cli_output (vm, "%U", format_load_balance_map,
                             load_balance_map_get_index(lbm), 0);
        }));
    }

    return 0;
}

VLIB_CLI_COMMAND (load_balance_map_show_command, static) = {
    .path = "show load-balance-map",
    .short_help = "show load-balance-map [<index>]",
    .function = load_balance_map_show,
};
