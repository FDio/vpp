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

#include <vnet/dpo/load_balance.h>
#include <vnet/dpo/load_balance_map.h>
#include <vnet/dpo/drop_dpo.h>
#include <vppinfra/math.h>              /* for fabs */
#include <vnet/adj/adj.h>
#include <vnet/adj/adj_internal.h>
#include <vnet/fib/fib_urpf_list.h>
#include <vnet/bier/bier_fwd.h>
#include <vnet/fib/mpls_fib.h>
#include <vnet/ip/ip4_inlines.h>
#include <vnet/ip/ip6_inlines.h>

/*
 * distribution error tolerance for load-balancing
 */
const f64 multipath_next_hop_error_tolerance = 0.1;

static const char *load_balance_attr_names[] = LOAD_BALANCE_ATTR_NAMES;

/**
 * the logger
 */
vlib_log_class_t load_balance_logger;

#define LB_DBG(_lb, _fmt, _args...)                                     \
{                                                                       \
    vlib_log_debug(load_balance_logger,                                 \
                   "lb:[%U]:" _fmt,                                     \
                   format_load_balance, load_balance_get_index(_lb),    \
                   LOAD_BALANCE_FORMAT_NONE,                            \
                   ##_args);                                            \
}

/**
 * Pool of all DPOs. It's not static so the DP can have fast access
 */
load_balance_t *load_balance_pool;

/**
 * The one instance of load-balance main
 */
load_balance_main_t load_balance_main = {
    .lbm_to_counters = {
        .name = "route-to",
        .stat_segment_name = "/net/route/to",
    },
    .lbm_via_counters = {
        .name = "route-via",
        .stat_segment_name = "/net/route/via",
    }
};

f64
load_balance_get_multipath_tolerance (void)
{
    return (multipath_next_hop_error_tolerance);
}

static inline index_t
load_balance_get_index (const load_balance_t *lb)
{
    return (lb - load_balance_pool);
}

static inline dpo_id_t*
load_balance_get_buckets (load_balance_t *lb)
{
    if (LB_HAS_INLINE_BUCKETS(lb))
    {
        return (lb->lb_buckets_inline);
    }
    else
    {
        return (lb->lb_buckets);
    }
}

static load_balance_t *
load_balance_alloc_i (void)
{
    load_balance_t *lb;
    u8 need_barrier_sync = 0;
    vlib_main_t *vm = vlib_get_main();
    ASSERT (vm->thread_index == 0);

    pool_get_aligned_will_expand (load_balance_pool, need_barrier_sync,
                                  CLIB_CACHE_LINE_BYTES);
    if (need_barrier_sync)
        vlib_worker_thread_barrier_sync (vm);

    pool_get_aligned(load_balance_pool, lb, CLIB_CACHE_LINE_BYTES);
    clib_memset(lb, 0, sizeof(*lb));

    lb->lb_map = INDEX_INVALID;
    lb->lb_urpf = INDEX_INVALID;

    if (need_barrier_sync == 0)
    {
        need_barrier_sync += vlib_validate_combined_counter_will_expand
            (&(load_balance_main.lbm_to_counters),
             load_balance_get_index(lb));
        need_barrier_sync += vlib_validate_combined_counter_will_expand
            (&(load_balance_main.lbm_via_counters),
             load_balance_get_index(lb));
        if (need_barrier_sync)
            vlib_worker_thread_barrier_sync (vm);
    }

    vlib_validate_combined_counter(&(load_balance_main.lbm_to_counters),
                                   load_balance_get_index(lb));
    vlib_validate_combined_counter(&(load_balance_main.lbm_via_counters),
                                   load_balance_get_index(lb));
    vlib_zero_combined_counter(&(load_balance_main.lbm_to_counters),
                               load_balance_get_index(lb));
    vlib_zero_combined_counter(&(load_balance_main.lbm_via_counters),
                               load_balance_get_index(lb));

    if (need_barrier_sync)
        vlib_worker_thread_barrier_release (vm);

    return (lb);
}

static u8*
load_balance_format (index_t lbi,
                     load_balance_format_flags_t flags,
                     u32 indent,
                     u8 *s)
{
    vlib_counter_t to, via;
    load_balance_t *lb;
    dpo_id_t *buckets;
    u32 i;

    lb = load_balance_get(lbi);
    vlib_get_combined_counter(&(load_balance_main.lbm_to_counters), lbi, &to);
    vlib_get_combined_counter(&(load_balance_main.lbm_via_counters), lbi, &via);
    buckets = load_balance_get_buckets(lb);

    s = format(s, "%U: ", format_dpo_type, DPO_LOAD_BALANCE);
    s = format(s, "[proto:%U ", format_dpo_proto, lb->lb_proto);
    s = format(s, "index:%d buckets:%d ", lbi, lb->lb_n_buckets);
    s = format(s, "uRPF:%d ", lb->lb_urpf);
    if (lb->lb_flags)
    {
        load_balance_attr_t attr;

        s = format(s, "flags:[");

        FOR_EACH_LOAD_BALANCE_ATTR(attr)
        {
            if (lb->lb_flags & (1 << attr))
            {
                s = format (s, "%s", load_balance_attr_names[attr]);
            }
        }
        s = format(s, "] ");
    }
    s = format(s, "to:[%Ld:%Ld]", to.packets, to.bytes);
    if (0 != via.packets)
    {
        s = format(s, " via:[%Ld:%Ld]",
                   via.packets, via.bytes);
    }
    s = format(s, "]");

    if (INDEX_INVALID != lb->lb_map)
    {
        s = format(s, "\n%U%U",
                   format_white_space, indent+4,
                   format_load_balance_map, lb->lb_map, indent+4);
    }
    for (i = 0; i < lb->lb_n_buckets; i++)
    {
        s = format(s, "\n%U[%d] %U",
                   format_white_space, indent+2,
                   i,
                   format_dpo_id,
                   &buckets[i], indent+6);
    }
    return (s);
}

u8*
format_load_balance (u8 * s, va_list * args)
{
    index_t lbi = va_arg(*args, index_t);
    load_balance_format_flags_t flags = va_arg(*args, load_balance_format_flags_t);

    return (load_balance_format(lbi, flags, 0, s));
}

static u8*
format_load_balance_dpo (u8 * s, va_list * args)
{
    index_t lbi = va_arg(*args, index_t);
    u32 indent = va_arg(*args, u32);

    return (load_balance_format(lbi, LOAD_BALANCE_FORMAT_DETAIL, indent, s));
}

flow_hash_config_t
load_balance_get_default_flow_hash (dpo_proto_t lb_proto)
{
    switch (lb_proto)
    {
    case DPO_PROTO_IP4:
    case DPO_PROTO_IP6:
        return (IP_FLOW_HASH_DEFAULT);

    case DPO_PROTO_MPLS:
        return (MPLS_FLOW_HASH_DEFAULT);

    case DPO_PROTO_ETHERNET:
    case DPO_PROTO_BIER:
    case DPO_PROTO_NSH:
        break;
    }

    return (0);
}

static load_balance_t *
load_balance_create_i (u32 num_buckets,
                       dpo_proto_t lb_proto,
                       flow_hash_config_t fhc)
{
    load_balance_t *lb;

    lb = load_balance_alloc_i();
    lb->lb_hash_config = fhc;
    lb->lb_n_buckets = num_buckets;
    lb->lb_n_buckets_minus_1 = num_buckets-1;
    lb->lb_proto = lb_proto;

    if (!LB_HAS_INLINE_BUCKETS(lb))
    {
        vec_validate_aligned(lb->lb_buckets,
                             lb->lb_n_buckets - 1,
                             CLIB_CACHE_LINE_BYTES);
    }

    LB_DBG(lb, "create");

    return (lb);
}

index_t
load_balance_create (u32 n_buckets,
                     dpo_proto_t lb_proto,
                     flow_hash_config_t fhc)
{
    return (load_balance_get_index(load_balance_create_i(n_buckets, lb_proto, fhc)));
}

static inline void
load_balance_set_bucket_i (load_balance_t *lb,
                           u32 bucket,
                           dpo_id_t *buckets,
                           const dpo_id_t *next)
{
    dpo_stack(DPO_LOAD_BALANCE, lb->lb_proto, &buckets[bucket], next);
}

void
load_balance_set_bucket (index_t lbi,
                         u32 bucket,
                         const dpo_id_t *next)
{
    load_balance_t *lb;
    dpo_id_t *buckets;

    lb = load_balance_get(lbi);
    buckets = load_balance_get_buckets(lb);

    ASSERT(bucket < lb->lb_n_buckets);

    load_balance_set_bucket_i(lb, bucket, buckets, next);
}

int
load_balance_is_drop (const dpo_id_t *dpo)
{
    load_balance_t *lb;

    if (DPO_LOAD_BALANCE != dpo->dpoi_type)
        return (0);

    lb = load_balance_get(dpo->dpoi_index);

    if (1 == lb->lb_n_buckets)
    {
        return (dpo_is_drop(load_balance_get_bucket_i(lb, 0)));
    }
    return (0);
}

u16
load_balance_n_buckets (index_t lbi)
{
    load_balance_t *lb;

    lb = load_balance_get(lbi);

    return (lb->lb_n_buckets);
}

void
load_balance_set_fib_entry_flags (index_t lbi,
                                  fib_entry_flag_t flags)
{
    load_balance_t *lb;

    lb = load_balance_get(lbi);
    lb->lb_fib_entry_flags = flags;
}


void
load_balance_set_urpf (index_t lbi,
		       index_t urpf)
{
    load_balance_t *lb;
    index_t old;

    lb = load_balance_get(lbi);

    /*
     * packets in flight we see this change. but it's atomic, so :P
     */
    old = lb->lb_urpf;
    lb->lb_urpf = urpf;

    fib_urpf_list_unlock(old);
    fib_urpf_list_lock(urpf);
}

index_t
load_balance_get_urpf (index_t lbi)
{
    load_balance_t *lb;

    lb = load_balance_get(lbi);

    return (lb->lb_urpf);
}

const dpo_id_t *
load_balance_get_bucket (index_t lbi,
                         u32 bucket)
{
    load_balance_t *lb;

    lb = load_balance_get(lbi);

    return (load_balance_get_bucket_i(lb, bucket));
}

static int
next_hop_sort_by_weight (const load_balance_path_t * n1,
                         const load_balance_path_t * n2)
{
    return ((int) n1->path_weight - (int) n2->path_weight);
}

/* Given next hop vector is over-written with normalized one with sorted weights and
   with weights corresponding to the number of adjacencies for each next hop.
   Returns number of adjacencies in block. */
u32
ip_multipath_normalize_next_hops (const load_balance_path_t * raw_next_hops,
                                  load_balance_path_t ** normalized_next_hops,
                                  u32 *sum_weight_in,
                                  f64 multipath_next_hop_error_tolerance)
{
    load_balance_path_t * nhs;
    uword n_nhs, n_adj, n_adj_left, i, sum_weight;
    f64 norm, error;

    n_nhs = vec_len (raw_next_hops);
    ASSERT (n_nhs > 0);
    if (n_nhs == 0)
        return 0;

    /* Allocate enough space for 2 copies; we'll use second copy to save original weights. */
    nhs = *normalized_next_hops;
    vec_validate (nhs, 2*n_nhs - 1);

    /* Fast path: 1 next hop in block. */
    n_adj = n_nhs;
    if (n_nhs == 1)
    {
        nhs[0] = raw_next_hops[0];
        nhs[0].path_weight = 1;
        _vec_len (nhs) = 1;
        sum_weight = 1;
        goto done;
    }

    else if (n_nhs == 2)
    {
        int cmp = next_hop_sort_by_weight (&raw_next_hops[0], &raw_next_hops[1]) < 0;

        /* Fast sort. */
        nhs[0] = raw_next_hops[cmp];
        nhs[1] = raw_next_hops[cmp ^ 1];

        /* Fast path: equal cost multipath with 2 next hops. */
        if (nhs[0].path_weight == nhs[1].path_weight)
        {
            nhs[0].path_weight = nhs[1].path_weight = 1;
            _vec_len (nhs) = 2;
            sum_weight = 2;
            goto done;
        }
    }
    else
    {
        clib_memcpy_fast (nhs, raw_next_hops, n_nhs * sizeof (raw_next_hops[0]));
        qsort (nhs, n_nhs, sizeof (nhs[0]), (void *) next_hop_sort_by_weight);
    }

    /* Find total weight to normalize weights. */
    sum_weight = 0;
    for (i = 0; i < n_nhs; i++)
        sum_weight += nhs[i].path_weight;

    /* In the unlikely case that all weights are given as 0, set them all to 1. */
    if (sum_weight == 0)
    {
        for (i = 0; i < n_nhs; i++)
            nhs[i].path_weight = 1;
        sum_weight = n_nhs;
    }

    /* Save copies of all next hop weights to avoid being overwritten in loop below. */
    for (i = 0; i < n_nhs; i++)
        nhs[n_nhs + i].path_weight = nhs[i].path_weight;

    /* Try larger and larger power of 2 sized adjacency blocks until we
       find one where traffic flows to within 1% of specified weights. */
    for (n_adj = max_pow2 (n_nhs); ; n_adj *= 2)
    {
        error = 0;

        norm = n_adj / ((f64) sum_weight);
        n_adj_left = n_adj;
        for (i = 0; i < n_nhs; i++)
        {
            f64 nf = nhs[n_nhs + i].path_weight * norm; /* use saved weights */
            word n = flt_round_nearest (nf);

            n = n > n_adj_left ? n_adj_left : n;
            n_adj_left -= n;
            error += fabs (nf - n);
            nhs[i].path_weight = n;

            if (0 == nhs[i].path_weight)
            {
                /*
                 * when the weight skew is high (norm is small) and n == nf.
                 * without this correction the path with a low weight would have
                 * no representation in the load-balanace - don't want that.
                 * If the weight skew is high so the load-balance has many buckets
                 * to allow it. pays ya money takes ya choice.
                 */
                error = n_adj;
                break;
            }
        }

        nhs[0].path_weight += n_adj_left;

        /* Less than 5% average error per adjacency with this size adjacency block? */
        if (error <= multipath_next_hop_error_tolerance*n_adj)
        {
            /* Truncate any next hops with zero weight. */
            _vec_len (nhs) = i;
            break;
        }
    }

done:
    /* Save vector for next call. */
    *normalized_next_hops = nhs;
    *sum_weight_in = sum_weight;
    return n_adj;
}

static load_balance_path_t *
load_balance_multipath_next_hop_fixup (const load_balance_path_t *nhs,
                                       dpo_proto_t drop_proto)
{
    if (0 == vec_len(nhs))
    {
        load_balance_path_t *new_nhs = NULL, *nh;

        /*
         * we need something for the load-balance. so use the drop
         */
        vec_add2(new_nhs, nh, 1);

        nh->path_weight = 1;
        dpo_copy(&nh->path_dpo, drop_dpo_get(drop_proto));

        return (new_nhs);
    }

    return (NULL);
}

/*
 * Fill in adjacencies in block based on corresponding
 * next hop adjacencies.
 */
static void
load_balance_fill_buckets_norm (load_balance_t *lb,
                                load_balance_path_t *nhs,
                                dpo_id_t *buckets,
                                u32 n_buckets)
{
    load_balance_path_t *nh;
    u16 ii, bucket;

    bucket = 0;

    /*
     * the next-hops have normalised weights. that means their sum is the number
     * of buckets we need to fill.
     */
    vec_foreach (nh, nhs)
    {
        for (ii = 0; ii < nh->path_weight; ii++)
        {
            ASSERT(bucket < n_buckets);
            load_balance_set_bucket_i(lb, bucket++, buckets, &nh->path_dpo);
        }
    }
}
static void
load_balance_fill_buckets_sticky (load_balance_t *lb,
                                  load_balance_path_t *nhs,
                                  dpo_id_t *buckets,
                                  u32 n_buckets)
{
    load_balance_path_t *nh, *fwding_paths;
    u16 ii, bucket, fpath;

    fpath = bucket = 0;
    fwding_paths = NULL;

    vec_foreach (nh, nhs)
    {
        if (!dpo_is_drop(&nh->path_dpo))
        {
            vec_add1(fwding_paths, *nh);
        }
    }
    if (vec_len(fwding_paths) == 0)
        fwding_paths = vec_dup(nhs);

    /*
     * the next-hops have normalised weights. that means their sum is the number
     * of buckets we need to fill.
     */
    vec_foreach (nh, nhs)
    {
        for (ii = 0; ii < nh->path_weight; ii++)
        {
            ASSERT(bucket < n_buckets);
            if (!dpo_is_drop(&nh->path_dpo))
            {
                load_balance_set_bucket_i(lb, bucket++, buckets, &nh->path_dpo);
            }
            else
            {
                /* fill the bucks from the next up path */
                load_balance_set_bucket_i(lb, bucket++, buckets, &fwding_paths[fpath].path_dpo);
                fpath = (fpath + 1) % vec_len(fwding_paths);
            }
        }
    }

    vec_free(fwding_paths);
}

static void
load_balance_fill_buckets (load_balance_t *lb,
                           load_balance_path_t *nhs,
                           dpo_id_t *buckets,
                           u32 n_buckets,
                           load_balance_flags_t flags)
{
    if (flags & LOAD_BALANCE_FLAG_STICKY)
    {
        load_balance_fill_buckets_sticky(lb, nhs, buckets, n_buckets);
    }
    else
    {
        load_balance_fill_buckets_norm(lb, nhs, buckets, n_buckets);
    }
}

static inline void
load_balance_set_n_buckets (load_balance_t *lb,
                            u32 n_buckets)
{
    lb->lb_n_buckets = n_buckets;
    lb->lb_n_buckets_minus_1 = n_buckets-1;
}

void
load_balance_multipath_update (const dpo_id_t *dpo,
                               const load_balance_path_t * raw_nhs,
                               load_balance_flags_t flags)
{
    load_balance_path_t *nh, *nhs, *fixed_nhs;
    u32 sum_of_weights, n_buckets, ii;
    index_t lbmi, old_lbmi;
    load_balance_t *lb;
    dpo_id_t *tmp_dpo;

    nhs = NULL;

    ASSERT(DPO_LOAD_BALANCE == dpo->dpoi_type);
    lb = load_balance_get(dpo->dpoi_index);
    lb->lb_flags = flags;
    fixed_nhs = load_balance_multipath_next_hop_fixup(raw_nhs, lb->lb_proto);
    n_buckets =
        ip_multipath_normalize_next_hops((NULL == fixed_nhs ?
                                          raw_nhs :
                                          fixed_nhs),
                                         &nhs,
                                         &sum_of_weights,
                                         multipath_next_hop_error_tolerance);

    ASSERT (n_buckets >= vec_len (raw_nhs));

    /*
     * Save the old load-balance map used, and get a new one if required.
     */
    old_lbmi = lb->lb_map;
    if (flags & LOAD_BALANCE_FLAG_USES_MAP)
    {
        lbmi = load_balance_map_add_or_lock(n_buckets, sum_of_weights, nhs);
    }
    else
    {
        lbmi = INDEX_INVALID;
    }

    if (0 == lb->lb_n_buckets)
    {
        /*
         * first time initialisation. no packets inflight, so we can write
         * at leisure.
         */
        load_balance_set_n_buckets(lb, n_buckets);

        if (!LB_HAS_INLINE_BUCKETS(lb))
            vec_validate_aligned(lb->lb_buckets,
                                 lb->lb_n_buckets - 1,
                                 CLIB_CACHE_LINE_BYTES);

        load_balance_fill_buckets(lb, nhs,
                                  load_balance_get_buckets(lb),
                                  n_buckets, flags);
        lb->lb_map = lbmi;
    }
    else
    {
        /*
         * This is a modification of an existing load-balance.
         * We need to ensure that packets inflight see a consistent state, that
         * is the number of reported buckets the LB has (read from
         * lb_n_buckets_minus_1) is not more than it actually has. So if the
         * number of buckets is increasing, we must update the bucket array first,
         * then the reported number. vice-versa if the number of buckets goes down.
         */
        if (n_buckets == lb->lb_n_buckets)
        {
            /*
             * no change in the number of buckets. we can simply fill what
             * is new over what is old.
             */
            load_balance_fill_buckets(lb, nhs,
                                      load_balance_get_buckets(lb),
                                      n_buckets, flags);
            lb->lb_map = lbmi;
        }
        else if (n_buckets > lb->lb_n_buckets)
        {
            /*
             * we have more buckets. the old load-balance map (if there is one)
             * will remain valid, i.e. mapping to indices within range, so we
             * update it last.
             */
            if (n_buckets > LB_NUM_INLINE_BUCKETS &&
                lb->lb_n_buckets <= LB_NUM_INLINE_BUCKETS)
            {
                /*
                 * the new increased number of buckets is crossing the threshold
                 * from the inline storage to out-line. Alloc the outline buckets
                 * first, then fixup the number. then reset the inlines.
                 */
                ASSERT(NULL == lb->lb_buckets);
                vec_validate_aligned(lb->lb_buckets,
                                     n_buckets - 1,
                                     CLIB_CACHE_LINE_BYTES);

                load_balance_fill_buckets(lb, nhs,
                                          lb->lb_buckets,
                                          n_buckets, flags);
                CLIB_MEMORY_BARRIER();
                load_balance_set_n_buckets(lb, n_buckets);

                CLIB_MEMORY_BARRIER();

                for (ii = 0; ii < LB_NUM_INLINE_BUCKETS; ii++)
                {
                    dpo_reset(&lb->lb_buckets_inline[ii]);
                }
            }
            else
            {
                if (n_buckets <= LB_NUM_INLINE_BUCKETS)
                {
                    /*
                     * we are not crossing the threshold and it's still inline buckets.
                     * we can write the new on the old..
                     */
                    load_balance_fill_buckets(lb, nhs,
                                              load_balance_get_buckets(lb),
                                              n_buckets, flags);
                    CLIB_MEMORY_BARRIER();
                    load_balance_set_n_buckets(lb, n_buckets);
                }
                else
                {
                    /*
                     * we are not crossing the threshold. We need a new bucket array to
                     * hold the increased number of choices.
                     */
                    dpo_id_t *new_buckets, *old_buckets, *tmp_dpo;

                    new_buckets = NULL;
                    old_buckets = load_balance_get_buckets(lb);

                    vec_validate_aligned(new_buckets,
                                         n_buckets - 1,
                                         CLIB_CACHE_LINE_BYTES);

                    load_balance_fill_buckets(lb, nhs, new_buckets,
                                              n_buckets, flags);
                    CLIB_MEMORY_BARRIER();
                    lb->lb_buckets = new_buckets;
                    CLIB_MEMORY_BARRIER();
                    load_balance_set_n_buckets(lb, n_buckets);

                    vec_foreach(tmp_dpo, old_buckets)
                    {
                        dpo_reset(tmp_dpo);
                    }
                    vec_free(old_buckets);
                }
            }

            /*
             * buckets fixed. ready for the MAP update.
             */
            lb->lb_map = lbmi;
        }
        else
        {
            /*
             * bucket size shrinkage.
             * Any map we have will be based on the old
             * larger number of buckets, so will be translating to indices
             * out of range. So the new MAP must be installed first.
             */
            lb->lb_map = lbmi;
            CLIB_MEMORY_BARRIER();


            if (n_buckets <= LB_NUM_INLINE_BUCKETS &&
                lb->lb_n_buckets > LB_NUM_INLINE_BUCKETS)
            {
                /*
                 * the new decreased number of buckets is crossing the threshold
                 * from out-line storage to inline:
                 *   1 - Fill the inline buckets,
                 *   2 - fixup the number (and this point the inline buckets are
                 *       used).
                 *   3 - free the outline buckets
                 */
                load_balance_fill_buckets(lb, nhs,
                                          lb->lb_buckets_inline,
                                          n_buckets, flags);
                CLIB_MEMORY_BARRIER();
                load_balance_set_n_buckets(lb, n_buckets);
                CLIB_MEMORY_BARRIER();

                vec_foreach(tmp_dpo, lb->lb_buckets)
                {
                    dpo_reset(tmp_dpo);
                }
                vec_free(lb->lb_buckets);
            }
            else
            {
                /*
                 * not crossing the threshold.
                 *  1 - update the number to the smaller size
                 *  2 - write the new buckets
                 *  3 - reset those no longer used.
                 */
                dpo_id_t *buckets;
                u32 old_n_buckets;

                old_n_buckets = lb->lb_n_buckets;
                buckets = load_balance_get_buckets(lb);

                load_balance_set_n_buckets(lb, n_buckets);
                CLIB_MEMORY_BARRIER();

                load_balance_fill_buckets(lb, nhs, buckets,
                                          n_buckets, flags);

                for (ii = n_buckets; ii < old_n_buckets; ii++)
                {
                    dpo_reset(&buckets[ii]);
                }
            }
        }
    }

    vec_foreach (nh, nhs)
    {
        dpo_reset(&nh->path_dpo);
    }
    vec_free(nhs);
    vec_free(fixed_nhs);

    load_balance_map_unlock(old_lbmi);
}

static void
load_balance_lock (dpo_id_t *dpo)
{
    load_balance_t *lb;

    lb = load_balance_get(dpo->dpoi_index);

    lb->lb_locks++;
}

static void
load_balance_destroy (load_balance_t *lb)
{
    dpo_id_t *buckets;
    int i;

    buckets = load_balance_get_buckets(lb);

    for (i = 0; i < lb->lb_n_buckets; i++)
    {
        dpo_reset(&buckets[i]);
    }

    LB_DBG(lb, "destroy");
    if (!LB_HAS_INLINE_BUCKETS(lb))
    {
        vec_free(lb->lb_buckets);
    }

    fib_urpf_list_unlock(lb->lb_urpf);
    load_balance_map_unlock(lb->lb_map);

    pool_put(load_balance_pool, lb);
}

static void
load_balance_unlock (dpo_id_t *dpo)
{
    load_balance_t *lb;

    lb = load_balance_get(dpo->dpoi_index);

    lb->lb_locks--;

    if (0 == lb->lb_locks)
    {
        load_balance_destroy(lb);
    }
}

static void
load_balance_mem_show (void)
{
    fib_show_memory_usage("load-balance",
			  pool_elts(load_balance_pool),
			  pool_len(load_balance_pool),
			  sizeof(load_balance_t));
    load_balance_map_show_mem();
}

const static dpo_vft_t lb_vft = {
    .dv_lock = load_balance_lock,
    .dv_unlock = load_balance_unlock,
    .dv_format = format_load_balance_dpo,
    .dv_mem_show = load_balance_mem_show,
};

/**
 * @brief The per-protocol VLIB graph nodes that are assigned to a load-balance
 *        object.
 *
 * this means that these graph nodes are ones from which a load-balance is the
 * parent object in the DPO-graph.
 *
 * We do not list all the load-balance nodes, such as the *-lookup. instead
 * we are relying on the correct use of the .sibling_of field when setting
 * up these sibling nodes.
 */
const static char* const load_balance_ip4_nodes[] =
{
    "ip4-load-balance",
    NULL,
};
const static char* const load_balance_ip6_nodes[] =
{
    "ip6-load-balance",
    NULL,
};
const static char* const load_balance_mpls_nodes[] =
{
    "mpls-load-balance",
    NULL,
};
const static char* const load_balance_l2_nodes[] =
{
    "l2-load-balance",
    NULL,
};
const static char* const load_balance_nsh_nodes[] =
{
    "nsh-load-balance",
    NULL
};
const static char* const load_balance_bier_nodes[] =
{
    "bier-load-balance",
    NULL,
};
const static char* const * const load_balance_nodes[DPO_PROTO_NUM] =
{
    [DPO_PROTO_IP4]  = load_balance_ip4_nodes,
    [DPO_PROTO_IP6]  = load_balance_ip6_nodes,
    [DPO_PROTO_MPLS] = load_balance_mpls_nodes,
    [DPO_PROTO_ETHERNET] = load_balance_l2_nodes,
    [DPO_PROTO_NSH] = load_balance_nsh_nodes,
    [DPO_PROTO_BIER] = load_balance_bier_nodes,
};

void
load_balance_module_init (void)
{
    index_t lbi;

    dpo_register(DPO_LOAD_BALANCE, &lb_vft, load_balance_nodes);

    /*
     * Special LB with index zero. we need to define this since the v4 mtrie
     * assumes an index of 0 implies the ply is empty. therefore all 'real'
     * adjs need a non-zero index.
     * This should never be used, but just in case, stack it on a drop.
     */
    lbi = load_balance_create(1, DPO_PROTO_IP4, 0);
    load_balance_set_bucket(lbi, 0, drop_dpo_get(DPO_PROTO_IP4));

    load_balance_logger =
        vlib_log_register_class("dpo", "load-balance");

    load_balance_map_module_init();
}

static clib_error_t *
load_balance_show (vlib_main_t * vm,
                   unformat_input_t * input,
                   vlib_cli_command_t * cmd)
{
    index_t lbi = INDEX_INVALID;

    while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat (input, "%d", &lbi))
            ;
        else
            break;
    }

    if (INDEX_INVALID != lbi)
    {
        if (pool_is_free_index(load_balance_pool, lbi))
        {
            vlib_cli_output (vm, "no such load-balance:%d", lbi);
        }
        else
        {
            vlib_cli_output (vm, "%U", format_load_balance, lbi,
                         LOAD_BALANCE_FORMAT_DETAIL);
        }
    }
    else
    {
        load_balance_t *lb;

        pool_foreach(lb, load_balance_pool,
        ({
            vlib_cli_output (vm, "%U", format_load_balance,
                             load_balance_get_index(lb),
                             LOAD_BALANCE_FORMAT_NONE);
        }));
    }

    return 0;
}

VLIB_CLI_COMMAND (load_balance_show_command, static) = {
    .path = "show load-balance",
    .short_help = "show load-balance [<index>]",
    .function = load_balance_show,
};


always_inline u32
ip_flow_hash (void *data)
{
  ip4_header_t *iph = (ip4_header_t *) data;

  if ((iph->ip_version_and_header_length & 0xF0) == 0x40)
    return ip4_compute_flow_hash (iph, IP_FLOW_HASH_DEFAULT);
  else
    return ip6_compute_flow_hash ((ip6_header_t *) iph, IP_FLOW_HASH_DEFAULT);
}

always_inline u64
mac_to_u64 (u8 * m)
{
  return (*((u64 *) m) & 0xffffffffffff);
}

always_inline u32
l2_flow_hash (vlib_buffer_t * b0)
{
  ethernet_header_t *eh;
  u64 a, b, c;
  uword is_ip, eh_size;
  u16 eh_type;

  eh = vlib_buffer_get_current (b0);
  eh_type = clib_net_to_host_u16 (eh->type);
  eh_size = ethernet_buffer_header_size (b0);

  is_ip = (eh_type == ETHERNET_TYPE_IP4 || eh_type == ETHERNET_TYPE_IP6);

  /* since we have 2 cache lines, use them */
  if (is_ip)
    a = ip_flow_hash ((u8 *) vlib_buffer_get_current (b0) + eh_size);
  else
    a = eh->type;

  b = mac_to_u64 ((u8 *) eh->dst_address);
  c = mac_to_u64 ((u8 *) eh->src_address);
  hash_mix64 (a, b, c);

  return (u32) c;
}

typedef struct load_balance_trace_t_
{
    index_t lb_index;
} load_balance_trace_t;

always_inline uword
load_balance_inline (vlib_main_t * vm,
		     vlib_node_runtime_t * node,
		     vlib_frame_t * frame,
		     int is_l2)
{
  u32 n_left_from, next_index, *from, *to_next;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;

  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  vlib_buffer_t *b0;
	  u32 bi0, lbi0, next0;
	  const dpo_id_t *dpo0;
	  const load_balance_t *lb0;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

	  /* lookup dst + src mac */
	  lbi0 =  vnet_buffer (b0)->ip.adj_index;
	  lb0 = load_balance_get(lbi0);

	  if (is_l2)
	  {
	      vnet_buffer(b0)->ip.flow_hash = l2_flow_hash(b0);
	  }
	  else
	  {
	      /* it's BIER */
	      const bier_hdr_t *bh0 = vlib_buffer_get_current(b0);
	      vnet_buffer(b0)->ip.flow_hash = bier_compute_flow_hash(bh0);
	  }

	  dpo0 = load_balance_get_bucket_i(lb0,
					   vnet_buffer(b0)->ip.flow_hash &
					   (lb0->lb_n_buckets_minus_1));

	  next0 = dpo0->dpoi_next_node;
	  vnet_buffer (b0)->ip.adj_index = dpo0->dpoi_index;

	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      load_balance_trace_t *tr = vlib_add_trace (vm, node, b0,
							 sizeof (*tr));
	      tr->lb_index = lbi0;
	    }
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

static uword
l2_load_balance (vlib_main_t * vm,
		 vlib_node_runtime_t * node,
		 vlib_frame_t * frame)
{
    return (load_balance_inline(vm, node, frame, 1));
}

static u8 *
format_l2_load_balance_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  load_balance_trace_t *t = va_arg (*args, load_balance_trace_t *);

  s = format (s, "L2-load-balance: index %d", t->lb_index);
  return s;
}

/**
 * @brief
 */
VLIB_REGISTER_NODE (l2_load_balance_node) = {
  .function = l2_load_balance,
  .name = "l2-load-balance",
  .vector_size = sizeof (u32),

  .format_trace = format_l2_load_balance_trace,
  .n_next_nodes = 1,
  .next_nodes = {
      [0] = "error-drop",
  },
};

static uword
nsh_load_balance (vlib_main_t * vm,
                 vlib_node_runtime_t * node,
                 vlib_frame_t * frame)
{
  u32 n_left_from, next_index, *from, *to_next;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;

  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
        {
          vlib_buffer_t *b0;
          u32 bi0, lbi0, next0, *nsh0;
          const dpo_id_t *dpo0;
          const load_balance_t *lb0;

          bi0 = from[0];
          to_next[0] = bi0;
          from += 1;
          to_next += 1;
          n_left_from -= 1;
          n_left_to_next -= 1;

          b0 = vlib_get_buffer (vm, bi0);

          lbi0 =  vnet_buffer (b0)->ip.adj_index;
          lb0 = load_balance_get(lbi0);

          /* SPI + SI are the second word of the NSH header */
          nsh0 = vlib_buffer_get_current (b0);
          vnet_buffer(b0)->ip.flow_hash = nsh0[1] % lb0->lb_n_buckets;

          dpo0 = load_balance_get_bucket_i(lb0,
                                           vnet_buffer(b0)->ip.flow_hash &
                                           (lb0->lb_n_buckets_minus_1));

          next0 = dpo0->dpoi_next_node;
          vnet_buffer (b0)->ip.adj_index = dpo0->dpoi_index;

          if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
            {
              load_balance_trace_t *tr = vlib_add_trace (vm, node, b0,
                                                         sizeof (*tr));
              tr->lb_index = lbi0;
            }
          vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
                                           n_left_to_next, bi0, next0);
        }

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

static u8 *
format_nsh_load_balance_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  load_balance_trace_t *t = va_arg (*args, load_balance_trace_t *);

  s = format (s, "NSH-load-balance: index %d", t->lb_index);
  return s;
}

/**
 * @brief
 */
VLIB_REGISTER_NODE (nsh_load_balance_node) = {
  .function = nsh_load_balance,
  .name = "nsh-load-balance",
  .vector_size = sizeof (u32),

  .format_trace = format_nsh_load_balance_trace,
  .n_next_nodes = 1,
  .next_nodes = {
      [0] = "error-drop",
  },
};

static u8 *
format_bier_load_balance_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  load_balance_trace_t *t = va_arg (*args, load_balance_trace_t *);

  s = format (s, "BIER-load-balance: index %d", t->lb_index);
  return s;
}

static uword
bier_load_balance (vlib_main_t * vm,
		   vlib_node_runtime_t * node,
		   vlib_frame_t * frame)
{
    return (load_balance_inline(vm, node, frame, 0));
}

/**
 * @brief
 */
VLIB_REGISTER_NODE (bier_load_balance_node) = {
  .function = bier_load_balance,
  .name = "bier-load-balance",
  .vector_size = sizeof (u32),

  .format_trace = format_bier_load_balance_trace,
  .sibling_of = "mpls-load-balance",
};
