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

#include <vnet/lisp-cp/gid_dictionary.h>

static u32
ip4_lookup (gid_dictionary_t * db, u32 vni, ip_prefix_t *key)
{
  int i, len;
  int rv;
  BVT(clib_bihash_kv) kv, value;

  len = vec_len (db->ip4_prefix_lengths_in_search_order);

  for (i = 0; i < len; i++)
    {
      int dst_address_length = db->ip4_prefix_lengths_in_search_order[i];
      ip4_address_t * mask;

      ASSERT(dst_address_length >= 0 && dst_address_length <= 32);

      mask = &db->ip4_fib_masks[dst_address_length];

      kv.key[0] = ((u64) vni << 32) | (ip_prefix_v4(key).as_u32 & mask->as_u32);
      kv.key[1] = 0;
      kv.key[2] = 0;

      rv = BV(clib_bihash_search_inline_2)(&db->ip4_lookup_table, &kv, &value);
      if (rv == 0)
        return value.value;
    }

  return GID_LOOKUP_MISS;
}

static u32
ip6_lookup (gid_dictionary_t * db, u32 vni, ip_prefix_t *key)
{
  int i, len;
  int rv;
  BVT(clib_bihash_kv) kv, value;

  len = vec_len (db->ip6_prefix_lengths_in_search_order);

  for (i = 0; i < len; i++)
    {
      int dst_address_length = db->ip6_prefix_lengths_in_search_order[i];
      ip6_address_t * mask;

      ASSERT(dst_address_length >= 0 && dst_address_length <= 128);

      mask = &db->ip6_fib_masks[dst_address_length];

      kv.key[0] = ip_prefix_v6(key).as_u64[0] & mask->as_u64[0];
      kv.key[1] = ip_prefix_v6(key).as_u64[1] & mask->as_u64[1];
      kv.key[2] = (u64)vni;

      rv = BV(clib_bihash_search_inline_2)(&db->ip6_lookup_table, &kv, &value);
      if (rv == 0)
        return value.value;
    }

  return GID_LOOKUP_MISS;
}

static u32
ip_lookup (gid_dictionary_t * db, u32 vni, ip_prefix_t *key)
{
  /* XXX for now this only works with ip-prefixes, no lcafs */
  switch (ip_prefix_version (key))
    {
    case IP4:
      return ip4_lookup (db, vni, key);
      break;
    case IP6:
      return ip6_lookup (db, vni, key);
      break;
    default:
      clib_warning ("address type %d not supported!", ip_prefix_version(key));
      break;
    }
  return ~0;
}

u32
gid_dictionary_lookup (gid_dictionary_t * db, gid_address_t * key)
{
  /* XXX for now this only works with ip-prefixes, no lcafs */
  switch (gid_address_type (key))
    {
    case IP_PREFIX:
      return ip_lookup (db, 0, &gid_address_ippref(key));
      break;
    default:
      clib_warning ("address type %d not supported!", gid_address_type(key));
      break;
    }
  return ~0;
}

static void
ip4_compute_prefix_lengths_in_search_order (gid_dictionary_t * db)
{
  int i;
  vec_reset_length (db->ip4_prefix_lengths_in_search_order);
  /* Note: bitmap reversed so this is in fact a longest prefix match */
  clib_bitmap_foreach (i, db->ip4_non_empty_dst_address_length_bitmap,
  ({
    int dst_address_length = 32 - i;
    vec_add1 (db->ip4_prefix_lengths_in_search_order, dst_address_length);
  }));
}

static u32
add_del_ip4_key (gid_dictionary_t *db, u32 vni, ip_prefix_t * pref, u32 val,
                 u8 is_add)
{
  BVT(clib_bihash_kv) kv, value;
  u32 old_val = ~0;
  ip4_address_t key;
  u8 plen = ip_prefix_len (pref);

  clib_memcpy (&key, &ip_prefix_v4(pref), sizeof(key));
  key.as_u32 &= db->ip4_fib_masks[plen].as_u32;
  if (is_add)
    {
      db->ip4_non_empty_dst_address_length_bitmap = clib_bitmap_set (
          db->ip4_non_empty_dst_address_length_bitmap, 32 - plen,
          1);
      ip4_compute_prefix_lengths_in_search_order (db);

      db->ip4_prefix_len_refcount[plen]++;
    }
  else
    {
      ASSERT(db->ip4_prefix_len_refcount[plen] != 0);

      db->ip4_prefix_len_refcount[plen]--;

      if (db->ip4_prefix_len_refcount[plen] == 0)
        {
            db->ip4_non_empty_dst_address_length_bitmap = clib_bitmap_set (
                db->ip4_non_empty_dst_address_length_bitmap, 32 - plen,
                0);
            ip4_compute_prefix_lengths_in_search_order (db);
        }
    }

  kv.key[0] = ((u64) vni << 32) | key.as_u32;
  kv.key[1] = 0;
  kv.key[2] = 0;

  if (BV(clib_bihash_search)(&db->ip4_lookup_table, &kv, &value) == 0)
    old_val = value.value;

  if (!is_add)
    BV(clib_bihash_add_del) (&db->ip4_lookup_table, &kv, 0 /* is_add */);
  else
    {
      kv.value = val;
      BV(clib_bihash_add_del) (&db->ip4_lookup_table, &kv, 1 /* is_add */);
    }
  return old_val;
}

static void
ip6_compute_prefix_lengths_in_search_order (gid_dictionary_t * db)
{
  int i;
  vec_reset_length (db->ip6_prefix_lengths_in_search_order);
  /* Note: bitmap reversed so this is in fact a longest prefix match */
  clib_bitmap_foreach (i, db->ip6_non_empty_dst_address_length_bitmap,
  ({
    int dst_address_length = 128 - i;
    vec_add1 (db->ip6_prefix_lengths_in_search_order, dst_address_length);
  }));
}

static u32
add_del_ip6_key (gid_dictionary_t *db, u32 vni, ip_prefix_t *pref, u32 val,
                 u8 is_add)
{
  BVT(clib_bihash_kv) kv, value;
  u32 old_val = ~0;
  ip6_address_t key;
  u8 plen = ip_prefix_len (pref);

  clib_memcpy (&key, &ip_prefix_v6(pref), sizeof(key));
  ip6_address_mask (&key, &db->ip6_fib_masks[plen]);
  if (is_add)
    {
      db->ip6_non_empty_dst_address_length_bitmap = clib_bitmap_set (
          db->ip6_non_empty_dst_address_length_bitmap, 128 - plen, 1);
      ip6_compute_prefix_lengths_in_search_order (db);
      db->ip6_prefix_len_refcount[plen]++;
    }
  else
    {
      ASSERT(db->ip6_prefix_len_refcount[plen] != 0);

      db->ip6_prefix_len_refcount[plen]--;

      if (db->ip6_prefix_len_refcount[plen] == 0)
        {
          db->ip6_non_empty_dst_address_length_bitmap = clib_bitmap_set (
              db->ip6_non_empty_dst_address_length_bitmap, 128 - plen, 0);
          ip6_compute_prefix_lengths_in_search_order (db);
        }
    }

  kv.key[0] = key.as_u64[0];
  kv.key[1] = key.as_u64[1];
  kv.key[2] = (u64) vni;
//  kv.key[2] = ((u64)((fib - im->fibs))<<32) | ip_prefix_len(key);

  if (BV(clib_bihash_search)(&db->ip6_lookup_table, &kv, &value) == 0)
    old_val = value.value;

  if (!is_add)
    BV(clib_bihash_add_del) (&db->ip6_lookup_table, &kv, 0 /* is_add */);
  else
    {
      kv.value = val;
      BV(clib_bihash_add_del) (&db->ip6_lookup_table, &kv, 1 /* is_add */);
    }
  return old_val;
}

static u32
gid_dictionary_add_del_ip (gid_dictionary_t *db, u32 iid, ip_prefix_t *key,
                           u32 value, u8 is_add)
{
  switch (ip_prefix_version (key))
    {
    case IP4:
      return add_del_ip4_key (db, iid, key, value, is_add);
      break;
    case IP6:
      return add_del_ip6_key (db, iid, key, value, is_add);
      break;
    default:
      clib_warning("address type %d not supported!", ip_prefix_version (key));
      break;
    }
  return ~0;
}

u32
gid_dictionary_add_del (gid_dictionary_t *db, gid_address_t *key, u32 value,
                        u8 is_add)
{
  /* XXX for now this only works with ip-prefixes, no lcafs */
  switch (gid_address_type (key))
    {
    case IP_PREFIX:
      return gid_dictionary_add_del_ip (db, 0, &gid_address_ippref(key), value,
                                        is_add);
      break;
    default:
      clib_warning ("address type %d not supported!", gid_address_type (key));
      break;
    }
  return ~0;
}

static void
ip4_lookup_init (gid_dictionary_t * db)
{
  uword i;

  memset(db->ip4_prefix_len_refcount, 0, sizeof(db->ip4_prefix_len_refcount));

  for (i = 0; i < ARRAY_LEN (db->ip4_fib_masks); i++)
    {
      u32 m;

      if (i < 32)
        m = pow2_mask (i) << (32 - i);
      else
        m = ~0;
      db->ip4_fib_masks[i].as_u32 = clib_host_to_net_u32 (m);
    }
  if (db->ip4_lookup_table_nbuckets == 0)
    db->ip4_lookup_table_nbuckets = IP4_LOOKUP_DEFAULT_HASH_NUM_BUCKETS;

  db->ip4_lookup_table_nbuckets = 1 << max_log2 (db->ip4_lookup_table_nbuckets);

  if (db->ip4_lookup_table_size == 0)
    db->ip4_lookup_table_size = IP4_LOOKUP_DEFAULT_HASH_MEMORY_SIZE;

  BV(clib_bihash_init) (&db->ip4_lookup_table, "ip4 lookup table",
                         db->ip4_lookup_table_nbuckets, db->ip4_lookup_table_size);
}

static void
ip6_lookup_init (gid_dictionary_t * db)
{
  uword i;

  memset(db->ip6_prefix_len_refcount, 0, sizeof(db->ip6_prefix_len_refcount));

  for (i = 0; i < ARRAY_LEN(db->ip6_fib_masks); i++)
    {
      u32 j, i0, i1;

      i0 = i / 32;
      i1 = i % 32;

      for (j = 0; j < i0; j++)
        db->ip6_fib_masks[i].as_u32[j] = ~0;

      if (i1)
        db->ip6_fib_masks[i].as_u32[i0] = clib_host_to_net_u32 (
            pow2_mask (i1) << (32 - i1));
    }

  if (db->ip6_lookup_table_nbuckets == 0)
    db->ip6_lookup_table_nbuckets = IP6_LOOKUP_DEFAULT_HASH_NUM_BUCKETS;

  db->ip6_lookup_table_nbuckets = 1 << max_log2 (db->ip6_lookup_table_nbuckets);

  if (db->ip6_lookup_table_size == 0)
    db->ip6_lookup_table_size = IP6_LOOKUP_DEFAULT_HASH_MEMORY_SIZE;

  BV(clib_bihash_init) (&db->ip6_lookup_table, "ip6 lookup table",
                         db->ip6_lookup_table_nbuckets, db->ip6_lookup_table_size);
}

void
gid_dictionary_init (gid_dictionary_t * db)
{
  ip4_lookup_init (db);
  ip6_lookup_init (db);
}

