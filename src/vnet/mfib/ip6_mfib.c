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

#include <vnet/mfib/ip6_mfib.h>

#include <vnet/mfib/mfib_table.h>
#include <vnet/mfib/mfib_entry.h>
#include <vnet/fib/ip6_fib.h>

ip6_mfib_table_instance_t ip6_mfib_table;

/**
 * Key and mask for radix
 */
typedef clib_bihash_kv_40_8_t ip6_mfib_key_t;

static const mfib_prefix_t all_zeros = {
    /* (*,*) */
    .fp_src_addr = {
        .ip6.as_u64 = {0, 0},
    },
    .fp_grp_addr = {
        .ip6.as_u64 = {0, 0},
    },
    .fp_len  = 0,
    .fp_proto = FIB_PROTOCOL_IP6,
};

typedef enum ip6_mfib_special_type_t_ {
    IP6_MFIB_SPECIAL_TYPE_NONE,
    IP6_MFIB_SPECIAL_TYPE_SOLICITED,
} ip6_mfib_special_type_t;

typedef struct ip6_mfib_special_t_ {
    /**
     * @brief solicited or not
     */
    ip6_mfib_special_type_t ims_type;

    /**
     * @brief the Prefix length
     */
    u8 ims_len;

    /**
     * @brief The last byte of the mcast address
     */
    u8 ims_byte;
    /**
     * @brief The scope of the address
     */
    u8 ims_scope;
} ip6_mfib_special_t;

static const ip6_mfib_special_t ip6_mfib_specials[] =
{
    {
        /*
         * Add ff02::1:ff00:0/104 via local route for all tables.
         *  This is required for neighbor discovery to work.
         */
        .ims_type = IP6_MFIB_SPECIAL_TYPE_SOLICITED,
        .ims_len = 104,
    },
    {
        /*
         * all-routers multicast address
         */
        .ims_type = IP6_MFIB_SPECIAL_TYPE_NONE,
        .ims_scope = IP6_MULTICAST_SCOPE_link_local,
        .ims_byte = IP6_MULTICAST_GROUP_ID_all_routers,
        .ims_len = 128,
    },
    {
        /*
         * all-nodes multicast address
         */
        .ims_type = IP6_MFIB_SPECIAL_TYPE_NONE,
        .ims_scope = IP6_MULTICAST_SCOPE_link_local,
        .ims_byte = IP6_MULTICAST_GROUP_ID_all_hosts,
        .ims_len = 128,
    },
    {
        /*
         *  Add all-mldv2  multicast address via local route for all tables
         */
        .ims_type = IP6_MFIB_SPECIAL_TYPE_NONE,
        .ims_len = 128,
        .ims_scope = IP6_MULTICAST_SCOPE_link_local,
        .ims_byte = IP6_MULTICAST_GROUP_ID_mldv2_routers,
    }
};

#define FOR_EACH_IP6_SPECIAL(_pfx, _body)                               \
{                                                                       \
    const ip6_mfib_special_t *_spec;                                    \
    u8 _ii;                                                             \
    for (_ii = 0;                                                       \
         _ii < ARRAY_LEN(ip6_mfib_specials);                            \
         _ii++)                                                         \
    {                                                                   \
        _spec = &ip6_mfib_specials[_ii];                                \
        if (IP6_MFIB_SPECIAL_TYPE_SOLICITED == _spec->ims_type)         \
        {                                                               \
            ip6_set_solicited_node_multicast_address(                   \
                &(_pfx)->fp_grp_addr.ip6, 0);                           \
        }                                                               \
        else                                                            \
        {                                                               \
            ip6_set_reserved_multicast_address (                        \
                &(_pfx)->fp_grp_addr.ip6,                               \
                _spec->ims_scope,                                       \
                _spec->ims_byte);                                       \
        }                                                               \
        (_pfx)->fp_len = _spec->ims_len;                                \
        do { _body; } while (0);                                        \
    }                                                                   \
}


static u32
ip6_create_mfib_with_table_id (u32 table_id,
                               mfib_source_t src)
{
    mfib_table_t *mfib_table;
    mfib_prefix_t pfx = {
        .fp_proto = FIB_PROTOCOL_IP6,
    };
    const fib_route_path_t path_for_us = {
        .frp_proto = DPO_PROTO_IP6,
        .frp_addr = zero_addr,
        .frp_sw_if_index = 0xffffffff,
        .frp_fib_index = ~0,
        .frp_weight = 1,
        .frp_flags = FIB_ROUTE_PATH_LOCAL,
        .frp_mitf_flags = MFIB_ITF_FLAG_FORWARD,
    };

    pool_get_aligned(ip6_main.mfibs, mfib_table, CLIB_CACHE_LINE_BYTES);
    clib_memset(mfib_table, 0, sizeof(*mfib_table));

    mfib_table->mft_proto = FIB_PROTOCOL_IP6;
    mfib_table->mft_index =
        mfib_table->v6.index =
            (mfib_table - ip6_main.mfibs);

    hash_set (ip6_main.mfib_index_by_table_id,
              table_id,
              mfib_table->mft_index);

    mfib_table->mft_table_id =
        mfib_table->v6.table_id =
            table_id;

    mfib_table_lock(mfib_table->mft_index, FIB_PROTOCOL_IP6, src);

    /*
     * add the special entries into the new FIB
     */
    mfib_table_entry_update(mfib_table->mft_index,
                            &all_zeros,
                            MFIB_SOURCE_DEFAULT_ROUTE,
                            MFIB_RPF_ID_NONE,
                            MFIB_ENTRY_FLAG_DROP);

    /*
     * Add each of the specials
     */
    FOR_EACH_IP6_SPECIAL(&pfx,
    ({
        mfib_table_entry_path_update(mfib_table->mft_index,
                                     &pfx,
                                     MFIB_SOURCE_SPECIAL,
                                     MFIB_ENTRY_FLAG_NONE,
                                     &path_for_us);
    }));

    return (mfib_table->mft_index);
}

void
ip6_mfib_table_destroy (ip6_mfib_t *mfib)
{
    mfib_table_t *mfib_table = (mfib_table_t*)mfib;
    fib_node_index_t mfei;
    mfib_prefix_t pfx = {
        .fp_proto = FIB_PROTOCOL_IP6,
    };
    const fib_route_path_t path_for_us = {
        .frp_proto = DPO_PROTO_IP6,
        .frp_addr = zero_addr,
        .frp_sw_if_index = 0xffffffff,
        .frp_fib_index = ~0,
        .frp_weight = 1,
        .frp_flags = FIB_ROUTE_PATH_LOCAL,
    };

    /*
     * remove all the specials we added when the table was created.
     */
    FOR_EACH_IP6_SPECIAL(&pfx,
    {
        mfib_table_entry_path_remove(mfib_table->mft_index,
                                     &pfx,
                                     MFIB_SOURCE_SPECIAL,
                                     &path_for_us);
    });

    mfei = mfib_table_lookup_exact_match(mfib_table->mft_index, &all_zeros);
    mfib_table_entry_delete_index(mfei, MFIB_SOURCE_DEFAULT_ROUTE);

    /*
     * validate no more routes.
     */
    ASSERT(0 == mfib_table->mft_total_route_counts);
    ASSERT(~0 != mfib_table->mft_table_id);

    hash_unset (ip6_main.mfib_index_by_table_id, mfib_table->mft_table_id);
    pool_put(ip6_main.mfibs, mfib_table);
}

void
ip6_mfib_interface_enable_disable (u32 sw_if_index, int is_enable)
{
    const fib_route_path_t path = {
        .frp_proto = DPO_PROTO_IP6,
        .frp_addr = zero_addr,
        .frp_sw_if_index = sw_if_index,
        .frp_fib_index = ~0,
        .frp_weight = 1,
        .frp_mitf_flags = MFIB_ITF_FLAG_ACCEPT,
    };
    mfib_prefix_t pfx = {
        .fp_proto = FIB_PROTOCOL_IP6,
    };
    u32 mfib_index;

    mfib_index = ip6_mfib_table_get_index_for_sw_if_index(sw_if_index);

    if (is_enable)
    {
        FOR_EACH_IP6_SPECIAL(&pfx,
        {
            mfib_table_entry_path_update(mfib_index,
                                         &pfx,
                                         MFIB_SOURCE_SPECIAL,
                                         MFIB_ENTRY_FLAG_NONE,
                                         &path);
        });
    }
    else
    {
        FOR_EACH_IP6_SPECIAL(&pfx,
        {
            mfib_table_entry_path_remove(mfib_index,
                                         &pfx,
                                         MFIB_SOURCE_SPECIAL,
                                         &path);
        });
    }
}

u32
ip6_mfib_table_find_or_create_and_lock (u32 table_id,
                                        mfib_source_t src)
{
    u32 index;

    index = ip6_mfib_index_from_table_id(table_id);
    if (~0 == index)
        return ip6_create_mfib_with_table_id(table_id, src);
    mfib_table_lock(index, FIB_PROTOCOL_IP6, src);

    return (index);
}

u32
ip6_mfib_table_get_index_for_sw_if_index (u32 sw_if_index)
{
    if (sw_if_index >= vec_len(ip6_main.mfib_index_by_sw_if_index))
    {
        /*
         * This is the case for interfaces that are not yet mapped to
         * a IP table
         */
        return (~0);
    }
    return (ip6_main.mfib_index_by_sw_if_index[sw_if_index]);
}

#define IPV6_MFIB_GRP_LEN(_len)                 \
    (_len > 128 ? 128 : _len)

#define IP6_MFIB_MK_KEY(_mfib, _grp, _src, _len, _key)                  \
{                                                                       \
    _key.key[0] = (_grp->as_u64[0] &                                    \
                   ip6_main.fib_masks[IPV6_MFIB_GRP_LEN(_len)].as_u64[0]); \
    _key.key[1] = (_grp->as_u64[1] &                                    \
                   ip6_main.fib_masks[IPV6_MFIB_GRP_LEN(_len)].as_u64[1]); \
    if (_len == 256) {                                                  \
        _key.key[2] = _src->as_u64[0];                                  \
        _key.key[3] = _src->as_u64[1];                                  \
    } else {                                                            \
        _key.key[2] = 0;                                                \
        _key.key[3] = 0;                                                \
    }                                                                   \
    _key.key[4] = _mfib->index;                                         \
    _key.key[4] = (_key.key[4] << 32) | len;                            \
}

/*
 * ip6_fib_table_lookup_exact_match
 *
 * Exact match prefix lookup
 */
fib_node_index_t
ip6_mfib_table_lookup_exact_match (const ip6_mfib_t *mfib,
                                   const ip6_address_t *grp,
                                   const ip6_address_t *src,
                                   u32 len)
{
    ip6_mfib_key_t key, value;
    int rv;

    IP6_MFIB_MK_KEY(mfib, grp, src, len, key);

    rv = clib_bihash_search_inline_2_40_8(&ip6_mfib_table.ip6_mhash,
                                          &key, &value);
    if (rv == 0)
	return value.value;

    return (FIB_NODE_INDEX_INVALID);
}

/*
 * ip6_fib_table_lookup
 *
 * Longest prefix match for the forwarding plane (no mask given)
 */
fib_node_index_t
ip6_mfib_table_fwd_lookup (const ip6_mfib_t *mfib,
                           const ip6_address_t *src,
                           const ip6_address_t *grp)
{
    ip6_mfib_table_instance_t *table;
    ip6_mfib_key_t key, value;
    int i, n, len;
    int rv;

    table = &ip6_mfib_table;
    n = vec_len (table->prefix_lengths_in_search_order);

    for (i = 0; i < n; i++)
    {
	len = table->prefix_lengths_in_search_order[i];

	ASSERT(len >= 0 && len <= 256);
        IP6_MFIB_MK_KEY(mfib, grp, src, len, key);
	rv = clib_bihash_search_inline_2_40_8(&table->ip6_mhash, &key, &value);
	if (rv == 0)
	    return value.value;
    }

    return (FIB_NODE_INDEX_INVALID);
}


fib_node_index_t
ip6_mfib_table_get_less_specific (const ip6_mfib_t *mfib,
                                  const ip6_address_t *src,
                                  const ip6_address_t *grp,
                                  u32 len)
{
    u32 mask_len;

    /*
     * in the absence of a tree structure for the table that allows for an O(1)
     * parent get, a cheeky way to find the cover is to LPM for the prefix with
     * mask-1.
     * there should always be a cover, though it may be the default route. the
     * default route's cover is the default route.
     */
    if (len == 256)
    {
        /* go from (S,G) to (*,G*) */
        mask_len = 128;
    }
    else if (len != 0)
    {
	mask_len = len - 1;
    }
    else
    {
        mask_len = len;
    }

    return (ip6_mfib_table_lookup(mfib, src, grp, mask_len));
}

/*
 * ip6_fib_table_lookup
 *
 * Longest prefix match
 */
fib_node_index_t
ip6_mfib_table_lookup (const ip6_mfib_t *mfib,
                       const ip6_address_t *src,
                       const ip6_address_t *grp,
                       u32 len)
{
    ip6_mfib_table_instance_t *table;
    ip6_mfib_key_t key, value;
    int i, n, rv;

    table = &ip6_mfib_table;
    n = vec_len (table->prefix_lengths_in_search_order);

    /*
     * start search from a mask length same length or shorter.
     * we don't want matches longer than the mask passed
     */
    i = 0;
    while (i < n && table->prefix_lengths_in_search_order[i] > len)
    {
        i++;
    }

    for (; i < n; i++)
    {
	len = table->prefix_lengths_in_search_order[i];

	ASSERT(len <= 256);
        IP6_MFIB_MK_KEY(mfib, grp, src, len, key);

	rv = clib_bihash_search_inline_2_40_8(&table->ip6_mhash, &key, &value);
	if (rv == 0)
	    return value.value;
    }

    return (FIB_NODE_INDEX_INVALID);
}

static void
compute_prefix_lengths_in_search_order (ip6_mfib_table_instance_t *table)
{
    int i;
    vec_reset_length (table->prefix_lengths_in_search_order);
    /* Note: bitmap reversed so this is in fact a longest prefix match */
    clib_bitmap_foreach (i, table->non_empty_dst_address_length_bitmap)
     {
	vec_add1(table->prefix_lengths_in_search_order, (256 - i));
    }
}

void
ip6_mfib_table_entry_insert (ip6_mfib_t *mfib,
                             const ip6_address_t *grp,
                             const ip6_address_t *src,
                             u32 len,
                             fib_node_index_t mfib_entry_index)
{
    ip6_mfib_table_instance_t *table;
    ip6_mfib_key_t key;

    table = &ip6_mfib_table;
    IP6_MFIB_MK_KEY(mfib, grp, src, len, key);
    key.value = mfib_entry_index;

    clib_bihash_add_del_40_8(&table->ip6_mhash, &key, 1);

    if (0 == table->dst_address_length_refcounts[len]++)
    {
        table->non_empty_dst_address_length_bitmap =
            clib_bitmap_set (table->non_empty_dst_address_length_bitmap, 
                             256 - len, 1);
        compute_prefix_lengths_in_search_order (table);
    }
}

void
ip6_mfib_table_entry_remove (ip6_mfib_t *mfib,
                             const ip6_address_t *grp,
                             const ip6_address_t *src,
                             u32 len)
{
    ip6_mfib_table_instance_t *table;
    ip6_mfib_key_t key;

    IP6_MFIB_MK_KEY(mfib, grp, src, len, key);

    table = &ip6_mfib_table;
    clib_bihash_add_del_40_8(&table->ip6_mhash, &key, 0);

    ASSERT (table->dst_address_length_refcounts[len] > 0);
    if (--table->dst_address_length_refcounts[len] == 0)
    {
	table->non_empty_dst_address_length_bitmap =
            clib_bitmap_set (table->non_empty_dst_address_length_bitmap, 
                             256 - len, 0);
	compute_prefix_lengths_in_search_order (table);
    }
}

static clib_error_t *
ip6_mfib_module_init (vlib_main_t * vm)
{
    return (NULL);
}

VLIB_INIT_FUNCTION(ip6_mfib_module_init);

u8 *
format_ip6_mfib_table_memory (u8 * s, va_list * args)
{
    u64 bytes_inuse;

    bytes_inuse = alloc_arena_next(&(ip6_mfib_table.ip6_mhash));

    s = format(s, "%=30s %=6d %=12ld\n",
               "IPv6 multicast",
               pool_elts(ip6_main.mfibs),
               bytes_inuse);

    return (s);
}

static void
ip6_mfib_table_show_one (ip6_mfib_t *mfib,
                         vlib_main_t * vm,
                         ip6_address_t *src,
                         ip6_address_t *grp,
                         u32 mask_len,
                         u32 cover)
{
    if (cover)
    {
        vlib_cli_output(vm, "%U",
                        format_mfib_entry,
                        ip6_mfib_table_get_less_specific(mfib, src, grp, mask_len),
                        MFIB_ENTRY_FORMAT_DETAIL);
    }
    else
    {
        vlib_cli_output(vm, "%U",
                        format_mfib_entry,
                        ip6_mfib_table_lookup(mfib, src, grp, mask_len),
                        MFIB_ENTRY_FORMAT_DETAIL);
    }
}

typedef struct ip6_mfib_show_ctx_t_ {
    fib_node_index_t *entries;
} ip6_mfib_show_ctx_t;


static walk_rc_t
ip6_mfib_table_collect_entries (fib_node_index_t mfei, void *arg)
{
    ip6_mfib_show_ctx_t *ctx = arg;

    vec_add1(ctx->entries, mfei);

    return (WALK_CONTINUE);
}

static void
ip6_mfib_table_show_all (ip6_mfib_t *mfib,
                         vlib_main_t * vm)
{
    fib_node_index_t *mfib_entry_index;
    ip6_mfib_show_ctx_t ctx = {
        .entries = NULL,
    };

    ip6_mfib_table_walk(mfib,
                        ip6_mfib_table_collect_entries,
                        &ctx);

    vec_sort_with_function(ctx.entries, mfib_entry_cmp_for_sort);

    vec_foreach(mfib_entry_index, ctx.entries)
    {
        vlib_cli_output(vm, "%U",
                        format_mfib_entry,
                        *mfib_entry_index,
                        MFIB_ENTRY_FORMAT_BRIEF);
    }

    vec_free(ctx.entries);
}

/**
 * @brief Context when walking the IPv6 table. Since all VRFs are in the
 * same hash table, we need to filter only those we need as we walk
 */
typedef struct ip6_mfib_walk_ctx_t_
{
    u32 i6w_mfib_index;
    mfib_table_walk_fn_t i6w_fn;
    void *i6w_ctx;
} ip6_mfib_walk_ctx_t;

static int
ip6_mfib_walk_cb (clib_bihash_kv_40_8_t * kvp,
                 void *arg)
{
    ip6_mfib_walk_ctx_t *ctx = arg;

    if ((kvp->key[4] >> 32) == ctx->i6w_mfib_index)
    {
        ctx->i6w_fn(kvp->value, ctx->i6w_ctx);
    }
    return (BIHASH_WALK_CONTINUE);
}

void
ip6_mfib_table_walk (ip6_mfib_t *mfib,
                     mfib_table_walk_fn_t fn,
                     void *arg)
{
    ip6_mfib_walk_ctx_t ctx = {
        .i6w_mfib_index = mfib->index,
        .i6w_fn = fn,
        .i6w_ctx = arg,
    };

    clib_bihash_foreach_key_value_pair_40_8(
        &ip6_mfib_table.ip6_mhash,
        ip6_mfib_walk_cb,
        &ctx);
}

static clib_error_t *
ip6_show_mfib (vlib_main_t * vm,
               unformat_input_t * input,
               vlib_cli_command_t * cmd)
{
    ip6_main_t * im6 = &ip6_main;
    mfib_table_t *mfib_table;
    int verbose, matching;
    ip6_address_t grp, src = {{0}};
    u32 mask = 128, cover;
    u32 table_id = ~0, fib_index = ~0;

    verbose = 1;
    matching = 0;
    cover = 0;

    while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat (input, "brief") || unformat (input, "summary")
            || unformat (input, "sum"))
            verbose = 0;

        else if (unformat (input, "%U %U",
                           unformat_ip6_address, &src,
                           unformat_ip6_address, &grp))
        {
            matching = 1;
            mask = 256;
        }
        else if (unformat (input, "%U/%d", unformat_ip6_address, &grp, &mask))
        {
            clib_memset(&src, 0, sizeof(src));
            matching = 1;
        }
        else if (unformat (input, "%U", unformat_ip6_address, &grp))
        {
            clib_memset(&src, 0, sizeof(src));
            matching = 1;
            mask = 128;
        }
        else if (unformat (input, "table %u", &table_id))
            ;
        else if (unformat (input, "index %d", &fib_index))
            ;
        else if (unformat (input, "cover"))
            cover = 1;
        else
            break;
    }

    pool_foreach (mfib_table, im6->mfibs)
     {
        ip6_mfib_t *mfib = &mfib_table->v6;

        if (table_id != ~0 && table_id != (int)mfib->table_id)
            continue;
        if (fib_index != ~0 && fib_index != (int)mfib->index)
            continue;

        vlib_cli_output (vm, "%U, fib_index %d",
                         format_mfib_table_name, mfib->index, FIB_PROTOCOL_IP6,
                         mfib->index);

        /* Show summary? */
        if (! verbose)
        {
            /* vlib_cli_output (vm, "%=20s%=16s", "Prefix length", "Count"); */
            /* for (i = 0; i < ARRAY_LEN (mfib->fib_entry_by_dst_address); i++) */
            /* { */
            /*     uword * hash = mfib->fib_entry_by_dst_address[i]; */
            /*     uword n_elts = hash_elts (hash); */
            /*     if (n_elts > 0) */
            /*         vlib_cli_output (vm, "%20d%16d", i, n_elts); */
            /* } */
            continue;
        }

        if (!matching)
        {
            ip6_mfib_table_show_all(mfib, vm);
        }
        else
        {
            ip6_mfib_table_show_one(mfib, vm, &src, &grp, mask, cover);
        }
    }

    return 0;
}

/* clang-format off */
/*?
 * This command displays the IPv6 MulticasrFIB Tables (VRF Tables) and
 * the route entries for each table.
 *
 * @note This command will run for a long time when the FIB tables are
 * comprised of millions of entries. For those scenarios, consider displaying
 * a single table or summary mode.
 *
 * @cliexpar
 * Example of how to display all the IPv6 Multicast FIB tables:
 * @cliexstart{show ip fib}
 * ipv6-VRF:0, fib_index 0
 * (*, 0.0.0.0/0):  flags:D,
 *  Interfaces:
 *  multicast-ip6-chain
 *   [@1]: dpo-drop ip6
 * (*, 232.1.1.1/32):
 * Interfaces:
 *  test-eth1: Forward,
 *  test-eth2: Forward,
 *  test-eth0: Accept,
 * multicast-ip6-chain
 * [@2]: dpo-replicate: [index:1 buckets:2 to:[0:0]]
 *   [0] [@1]: ipv6-mcast: test-eth1: IP6: d0:d1:d2:d3:d4:01 -> 01:00:05:00:00:00
 *   [1] [@1]: ipv6-mcast: test-eth2: IP6: d0:d1:d2:d3:d4:02 -> 01:00:05:00:00:00
 *
 * @cliexend
 * Example of how to display a summary of all IPv6 FIB tables:
 * @cliexstart{show ip fib summary}
 * ipv6-VRF:0, fib_index 0, flow hash: src dst sport dport proto
 *     Prefix length         Count
 *                    0               1
 *                    8               2
 *                   32               4
 * ipv6-VRF:7, fib_index 1, flow hash: src dst sport dport proto
 *     Prefix length         Count
 *                    0               1
 *                    8               2
 *                   24               2
 *                   32               4
 * @cliexend
 ?*/
/* clang-format on */
VLIB_CLI_COMMAND (ip6_show_fib_command, static) = {
    .path = "show ip6 mfib",
    .short_help = "show ip mfib [summary] [table <table-id>] [index <fib-id>] [<grp-addr>[/<mask>]] [<grp-addr>] [<src-addr> <grp-addr>]",
    .function = ip6_show_mfib,
};

static clib_error_t *
ip6_mfib_init (vlib_main_t * vm)
{
    clib_bihash_init_40_8 (&ip6_mfib_table.ip6_mhash,
                           "ip6 mFIB table",
                           IP6_MFIB_DEFAULT_HASH_NUM_BUCKETS,
                           IP6_MFIB_DEFAULT_HASH_MEMORY_SIZE);

    return (NULL);
}

VLIB_INIT_FUNCTION (ip6_mfib_init) =
{
  .runs_before = VLIB_INITS("ip6_lookup_init"),
};
