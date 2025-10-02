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

#include <vlib/vlib.h>
#include <vnet/fib/fib_table.h>
#include <vnet/fib/fib_entry.h>
#include <vnet/fib/ip4_fib.h>

/*
 * ip4_fib_hash_table_lookup_exact_match
 *
 * Exact match prefix lookup
 */
fib_node_index_t
ip4_fib_hash_table_lookup_exact_match (const ip4_fib_hash_t *fib,
                                       const ip4_address_t *addr,
                                       u32 len)
{
    uword * hash, * result;
    u32 key;

    hash = fib->fib_entry_by_dst_address[len];
    key  = (addr->data_u32 & ip4_main.fib_masks[len]);

    result = hash_get(hash, key);

    if (NULL != result) {
	return (result[0]);
    }
    return (FIB_NODE_INDEX_INVALID);
}

/*
 * ip4_fib_hash_table_lookup_adj
 *
 * Longest prefix match
 */
index_t
ip4_fib_hash_table_lookup_lb (const ip4_fib_hash_t *fib,
                              const ip4_address_t *addr)
{
    fib_node_index_t fei;

    fei = ip4_fib_hash_table_lookup(fib, addr, 32);

    if (FIB_NODE_INDEX_INVALID != fei)
    {
	const dpo_id_t *dpo;

	dpo = fib_entry_contribute_ip_forwarding(fei);

	return (dpo->dpoi_index);
    }
    return (INDEX_INVALID);
}

/*
 * ip4_fib_hash_table_lookup
 *
 * Longest prefix match
 */
fib_node_index_t
ip4_fib_hash_table_lookup (const ip4_fib_hash_t *fib,
                           const ip4_address_t *addr,
                           u32 len)
{
    uword * hash, * result;
    i32 mask_len;
    u32 key;

    for (mask_len = len; mask_len >= 0; mask_len--)
    {
	hash = fib->fib_entry_by_dst_address[mask_len];
	key = (addr->data_u32 & ip4_main.fib_masks[mask_len]);

	result = hash_get (hash, key);

	if (NULL != result) {
	    return (result[0]);
	}
    }
    return (FIB_NODE_INDEX_INVALID);
}

void
ip4_fib_hash_table_entry_insert (ip4_fib_hash_t *fib,
                                 const ip4_address_t *addr,
                                 u32 len,
                                 fib_node_index_t fib_entry_index)
{
    uword * hash, * result;
    u32 key;

    key = (addr->data_u32 & ip4_main.fib_masks[len]);
    hash = fib->fib_entry_by_dst_address[len];
    result = hash_get (hash, key);

    if (NULL == result) {
	/*
	 * adding a new entry
	 */

	if (NULL == hash) {
	    hash = hash_create (32 /* elts */, sizeof (uword));
	    hash_set_flags (hash, HASH_FLAG_NO_AUTO_SHRINK);

	}
	hash = hash_set_mt_safe(hash, key, fib_entry_index);
	fib->fib_entry_by_dst_address[len] = hash;
    }
    else
    {
	ASSERT(0);
    }
}

void
ip4_fib_hash_table_entry_remove (ip4_fib_hash_t *fib,
                                 const ip4_address_t *addr,
                                 u32 len)
{
    uword * hash, * result;
    u32 key;

    key = (addr->data_u32 & ip4_main.fib_masks[len]);
    hash = fib->fib_entry_by_dst_address[len];
    result = hash_get (hash, key);

    if (NULL == result)
    {
	/*
	 * removing a non-existent entry. i'll allow it.
	 */
    }
    else
    {
	hash_unset_mt_safe(hash, key);
    }

    fib->fib_entry_by_dst_address[len] = hash;
}

void
ip4_fib_hash_table_walk (ip4_fib_hash_t *fib,
                         fib_table_walk_fn_t fn,
                         void *ctx)
{
    fib_prefix_t root = {
        .fp_proto = FIB_PROTOCOL_IP4,
        // address and length default to all 0
    };

    /*
     * A full tree walk is the dengenerate case of a sub-tree from
     * the very root
     */
    return (ip4_fib_hash_table_sub_tree_walk(fib, &root, fn, ctx));
}

void
ip4_fib_hash_table_sub_tree_walk (ip4_fib_hash_t *fib,
                                  const fib_prefix_t *root,
                                  fib_table_walk_fn_t fn,
                                  void *ctx)
{
    fib_prefix_t *sub_trees = NULL;
    int i;

    /*
     * There is no efficient way to walk this array of hash tables.
     * so we walk each table with a mask length greater than and equal to
     * the required root and check it is covered by the root.
     */
    for (i = root->fp_len;
         i < ARRAY_LEN (fib->fib_entry_by_dst_address);
         i++)
    {
	uword * hash = fib->fib_entry_by_dst_address[i];

	if (NULL != hash)
	{
            ip4_address_t key;
	    hash_pair_t * p;

	    hash_foreach_pair (p, hash,
	    ({
                key.as_u32 = p->key;
                if (ip4_destination_matches_route(&ip4_main,
                                                  &key,
                                                  &root->fp_addr.ip4,
                                                  root->fp_len))
                {
                    const fib_prefix_t *sub_tree;
                    int skip = 0;

                    /*
                     * exclude sub-trees the walk does not want to explore
                     */
                    vec_foreach(sub_tree, sub_trees)
                    {
                        if (ip4_destination_matches_route(&ip4_main,
                                                          &key,
                                                          &sub_tree->fp_addr.ip4,
                                                          sub_tree->fp_len))
                        {
                            skip = 1;
                            break;
                        }
                    }

                    if (!skip)
                    {
                        switch (fn(p->value[0], ctx))
                        {
                        case FIB_TABLE_WALK_CONTINUE:
                            break;
                        case FIB_TABLE_WALK_SUB_TREE_STOP: {
                            fib_prefix_t pfx = {
                                .fp_proto = FIB_PROTOCOL_IP4,
                                .fp_len = i,
                                .fp_addr.ip4 = key,
                            };
                            vec_add1(sub_trees, pfx);
                            break;
                        }
                        case FIB_TABLE_WALK_STOP:
                            goto done;
                        }
                    }
                }
	    }));
	}
    }
done:
    vec_free(sub_trees);
    return;
}

