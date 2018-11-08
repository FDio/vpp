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

typedef struct
{
  void *arg;
  ip_prefix_t src;
  foreach_subprefix_match_cb_t cb;
  union
  {
    gid_ip4_table_t *ip4_table;
    gid_ip6_table_t *ip6_table;
  };
} sfib_entry_arg_t;

static u32 ip4_lookup (gid_ip4_table_t * db, u32 vni, ip_prefix_t * key);

static u32 ip6_lookup (gid_ip6_table_t * db, u32 vni, ip_prefix_t * key);

static void
foreach_sfib4_subprefix (BVT (clib_bihash_kv) * kvp, void *arg)
{
  sfib_entry_arg_t *a = arg;
  u32 ip = (u32) kvp->key[0];
  ip4_address_t *mask;
  u8 plen = ip_prefix_len (&a->src);

  ASSERT (plen <= 32);
  mask = &a->ip4_table->ip4_fib_masks[plen];

  u32 src_ip = ip_prefix_v4 (&a->src).as_u32;
  src_ip &= mask->as_u32;
  ip &= mask->as_u32;

  if (src_ip == ip)
    {
      /* found sub-prefix of src prefix */
      (a->cb) (kvp->value, a->arg);
    }
}

static void
gid_dict_foreach_ip4_subprefix (gid_dictionary_t * db, u32 vni,
				ip_prefix_t * src, ip_prefix_t * dst,
				foreach_subprefix_match_cb_t cb, void *arg)
{
  u32 sfi;
  gid_ip4_table_t *sfib4;
  sfib_entry_arg_t a;

  sfi = ip4_lookup (&db->dst_ip4_table, vni, dst);
  if (GID_LOOKUP_MISS == sfi)
    return;

  sfib4 = pool_elt_at_index (db->src_ip4_table_pool, sfi);

  a.arg = arg;
  a.cb = cb;
  a.src = src[0];
  a.ip4_table = sfib4;

  BV (clib_bihash_foreach_key_value_pair) (&sfib4->ip4_lookup_table,
					   foreach_sfib4_subprefix, &a);
}

static void
foreach_sfib6_subprefix (BVT (clib_bihash_kv) * kvp, void *arg)
{
  sfib_entry_arg_t *a = arg;
  ip6_address_t ip;
  ip6_address_t *mask;
  u8 plen = ip_prefix_len (&a->src);

  mask = &a->ip6_table->ip6_fib_masks[plen];
  ip.as_u64[0] = kvp->key[0];
  ip.as_u64[1] = kvp->key[1];

  if (ip6_address_is_equal_masked (&ip_prefix_v6 (&a->src), &ip, mask))
    {
      /* found sub-prefix of src prefix */
      (a->cb) (kvp->value, a->arg);
    }
}

static void
gid_dict_foreach_ip6_subprefix (gid_dictionary_t * db, u32 vni,
				ip_prefix_t * src, ip_prefix_t * dst,
				foreach_subprefix_match_cb_t cb, void *arg)
{
  u32 sfi;
  gid_ip6_table_t *sfib6;
  sfib_entry_arg_t a;

  sfi = ip6_lookup (&db->dst_ip6_table, vni, dst);
  if (GID_LOOKUP_MISS == sfi)
    return;

  sfib6 = pool_elt_at_index (db->src_ip6_table_pool, sfi);

  a.arg = arg;
  a.cb = cb;
  a.src = src[0];
  a.ip6_table = sfib6;

  BV (clib_bihash_foreach_key_value_pair) (&sfib6->ip6_lookup_table,
					   foreach_sfib6_subprefix, &a);
}

void
gid_dict_foreach_subprefix (gid_dictionary_t * db, gid_address_t * eid,
			    foreach_subprefix_match_cb_t cb, void *arg)
{
  ip_prefix_t *ippref = &gid_address_sd_dst_ippref (eid);

  if (IP4 == ip_prefix_version (ippref))
    gid_dict_foreach_ip4_subprefix (db, gid_address_vni (eid),
				    &gid_address_sd_src_ippref (eid),
				    &gid_address_sd_dst_ippref (eid), cb,
				    arg);
  else
    gid_dict_foreach_ip6_subprefix (db, gid_address_vni (eid),
				    &gid_address_sd_src_ippref (eid),
				    &gid_address_sd_dst_ippref (eid), cb,
				    arg);
}

void
gid_dict_foreach_l2_arp_ndp_entry (gid_dictionary_t * db, void (*cb)
				   (BVT (clib_bihash_kv) * kvp, void *arg),
				   void *ht)
{
  gid_l2_arp_ndp_table_t *tab = &db->arp_ndp_table;
  BV (clib_bihash_foreach_key_value_pair) (&tab->arp_ndp_lookup_table, cb,
					   ht);
}

static void
make_mac_sd_key (BVT (clib_bihash_kv) * kv, u32 vni, u8 src_mac[6],
		 u8 dst_mac[6])
{
  kv->key[0] = (u64) vni;
  kv->key[1] = mac_to_u64 (dst_mac);
  kv->key[2] = src_mac ? mac_to_u64 (src_mac) : (u64) 0;
}

static u32
mac_sd_lookup (gid_mac_table_t * db, u32 vni, u8 * dst, u8 * src)
{
  int rv;
  BVT (clib_bihash_kv) kv, value;

  make_mac_sd_key (&kv, vni, src, dst);
  rv = BV (clib_bihash_search_inline_2) (&db->mac_lookup_table, &kv, &value);

  /* no match, try with src 0, catch all for dst */
  if (rv != 0)
    {
      kv.key[2] = 0;
      rv = BV (clib_bihash_search_inline_2) (&db->mac_lookup_table, &kv,
					     &value);
      if (rv == 0)
	return value.value;
    }
  else
    return value.value;

  return GID_LOOKUP_MISS;
}

static u32
ip4_lookup_exact_match (gid_ip4_table_t * db, u32 vni, ip_prefix_t * key)
{
  int rv;
  BVT (clib_bihash_kv) kv, value;

  ip4_address_t *mask;

  mask = &db->ip4_fib_masks[ip_prefix_len (key)];

  kv.key[0] = ((u64) vni << 32) | (ip_prefix_v4 (key).as_u32 & mask->as_u32);
  kv.key[1] = 0;
  kv.key[2] = 0;

  rv = BV (clib_bihash_search_inline_2) (&db->ip4_lookup_table, &kv, &value);
  if (rv == 0)
    return value.value;

  return GID_LOOKUP_MISS;
}

static u32
ip4_lookup (gid_ip4_table_t * db, u32 vni, ip_prefix_t * key)
{
  int i, len;
  int rv;
  BVT (clib_bihash_kv) kv, value;

  len = vec_len (db->ip4_prefix_lengths_in_search_order);

  for (i = 0; i < len; i++)
    {
      int dst_address_length = db->ip4_prefix_lengths_in_search_order[i];
      ip4_address_t *mask;

      ASSERT (dst_address_length >= 0 && dst_address_length <= 32);

      mask = &db->ip4_fib_masks[dst_address_length];

      kv.key[0] =
	((u64) vni << 32) | (ip_prefix_v4 (key).as_u32 & mask->as_u32);
      kv.key[1] = 0;
      kv.key[2] = 0;

      rv =
	BV (clib_bihash_search_inline_2) (&db->ip4_lookup_table, &kv, &value);
      if (rv == 0)
	return value.value;
    }

  return GID_LOOKUP_MISS;
}

static u32
ip6_lookup_exact_match (gid_ip6_table_t * db, u32 vni, ip_prefix_t * key)
{
  int rv;
  BVT (clib_bihash_kv) kv, value;

  ip6_address_t *mask;
  mask = &db->ip6_fib_masks[ip_prefix_len (key)];

  kv.key[0] = ip_prefix_v6 (key).as_u64[0] & mask->as_u64[0];
  kv.key[1] = ip_prefix_v6 (key).as_u64[1] & mask->as_u64[1];
  kv.key[2] = (u64) vni;

  rv = BV (clib_bihash_search_inline_2) (&db->ip6_lookup_table, &kv, &value);
  if (rv == 0)
    return value.value;

  return GID_LOOKUP_MISS;
}

static u32
ip6_lookup (gid_ip6_table_t * db, u32 vni, ip_prefix_t * key)
{
  int i, len;
  int rv;
  BVT (clib_bihash_kv) kv, value;

  len = vec_len (db->ip6_prefix_lengths_in_search_order);

  for (i = 0; i < len; i++)
    {
      int dst_address_length = db->ip6_prefix_lengths_in_search_order[i];
      ip6_address_t *mask;

      ASSERT (dst_address_length >= 0 && dst_address_length <= 128);

      mask = &db->ip6_fib_masks[dst_address_length];

      kv.key[0] = ip_prefix_v6 (key).as_u64[0] & mask->as_u64[0];
      kv.key[1] = ip_prefix_v6 (key).as_u64[1] & mask->as_u64[1];
      kv.key[2] = (u64) vni;

      rv =
	BV (clib_bihash_search_inline_2) (&db->ip6_lookup_table, &kv, &value);
      if (rv == 0)
	return value.value;
    }

  return GID_LOOKUP_MISS;
}

static u32
ip_sd_lookup (gid_dictionary_t * db, u32 vni, ip_prefix_t * dst,
	      ip_prefix_t * src)
{
  u32 sfi;
  gid_ip4_table_t *sfib4;
  gid_ip6_table_t *sfib6;

  switch (ip_prefix_version (dst))
    {
    case IP4:
      sfi = ip4_lookup (&db->dst_ip4_table, vni, dst);
      if (GID_LOOKUP_MISS != sfi)
	sfib4 = pool_elt_at_index (db->src_ip4_table_pool, sfi);
      else
	return GID_LOOKUP_MISS;

      if (!src)
	{
	  ip_prefix_t sp;
	  clib_memset (&sp, 0, sizeof (sp));
	  return ip4_lookup_exact_match (sfib4, 0, &sp);
	}
      else
	return ip4_lookup (sfib4, 0, src);

      break;
    case IP6:
      sfi = ip6_lookup (&db->dst_ip6_table, vni, dst);
      if (GID_LOOKUP_MISS != sfi)
	sfib6 = pool_elt_at_index (db->src_ip6_table_pool, sfi);
      else
	return GID_LOOKUP_MISS;

      if (!src)
	{
	  ip_prefix_t sp;
	  clib_memset (&sp, 0, sizeof (sp));
	  ip_prefix_version (&sp) = IP6;
	  return ip6_lookup_exact_match (sfib6, 0, &sp);
	}
      else
	return ip6_lookup (sfib6, 0, src);

      break;
    default:
      clib_warning ("address type %d not supported!",
		    ip_prefix_version (dst));
      break;
    }
  return GID_LOOKUP_MISS;
}

static void
make_arp_ndp_key (BVT (clib_bihash_kv) * kv, u32 bd, ip_address_t * addr)
{
  kv->key[0] = ((u64) bd << 32) | (u32) ip_addr_version (addr);
  if (ip_addr_version (addr) == IP4)
    {
      kv->key[1] = (u64) addr->ip.v4.as_u32;
      kv->key[2] = (u64) 0;
    }
  else
    {
      kv->key[1] = (u64) addr->ip.v6.as_u64[0];
      kv->key[2] = (u64) addr->ip.v6.as_u64[1];
    }
}

static void
make_nsh_key (BVT (clib_bihash_kv) * kv, u32 vni, u32 spi, u8 si)
{
  kv->key[0] = (u64) vni;
  kv->key[1] = (u64) spi;
  kv->key[2] = (u64) si;
}

static u64
arp_ndp_lookup (gid_l2_arp_ndp_table_t * db, u32 bd, ip_address_t * key)
{
  int rv;
  BVT (clib_bihash_kv) kv, value;

  make_arp_ndp_key (&kv, bd, key);
  rv = BV (clib_bihash_search_inline_2) (&db->arp_ndp_lookup_table, &kv,
					 &value);

  if (rv == 0)
    return value.value;

  return GID_LOOKUP_MISS_L2;
}

static u32
nsh_lookup (gid_nsh_table_t * db, u32 vni, u32 spi, u8 si)
{
  int rv;
  BVT (clib_bihash_kv) kv, value;

  make_nsh_key (&kv, vni, spi, si);
  rv = BV (clib_bihash_search_inline_2) (&db->nsh_lookup_table, &kv, &value);

  if (rv == 0)
    return value.value;

  return GID_LOOKUP_MISS;
}

u64
gid_dictionary_lookup (gid_dictionary_t * db, gid_address_t * key)
{
  switch (gid_address_type (key))
    {
    case GID_ADDR_IP_PREFIX:
      return ip_sd_lookup (db, gid_address_vni (key),
			   &gid_address_ippref (key), 0);
    case GID_ADDR_MAC:
      return mac_sd_lookup (&db->sd_mac_table, gid_address_vni (key),
			    gid_address_mac (key), 0);
    case GID_ADDR_SRC_DST:
      switch (gid_address_sd_dst_type (key))
	{
	case FID_ADDR_IP_PREF:
	  return ip_sd_lookup (db, gid_address_vni (key),
			       &gid_address_sd_dst_ippref (key),
			       &gid_address_sd_src_ippref (key));
	  break;
	case FID_ADDR_MAC:
	  return mac_sd_lookup (&db->sd_mac_table, gid_address_vni (key),
				gid_address_sd_dst_mac (key),
				gid_address_sd_src_mac (key));
	  break;
	default:
	  clib_warning ("Source/Dest address type %d not supported!",
			gid_address_sd_dst_type (key));
	  break;
	}
      break;
    case GID_ADDR_ARP:
    case GID_ADDR_NDP:
      return arp_ndp_lookup (&db->arp_ndp_table, gid_address_arp_ndp_bd (key),
			     &gid_address_arp_ndp_ip (key));
    case GID_ADDR_NSH:
      return nsh_lookup (&db->nsh_table, gid_address_vni (key),
			 gid_address_nsh_spi (key), gid_address_nsh_si (key));
    default:
      clib_warning ("address type %d not supported!", gid_address_type (key));
      break;
    }
  return GID_LOOKUP_MISS;
}

u32
gid_dictionary_sd_lookup (gid_dictionary_t * db, gid_address_t * dst,
			  gid_address_t * src)
{
  switch (gid_address_type (dst))
    {
    case GID_ADDR_IP_PREFIX:
      return ip_sd_lookup (db, gid_address_vni (dst),
			   &gid_address_ippref (dst),
			   &gid_address_ippref (src));
    case GID_ADDR_MAC:
      return mac_sd_lookup (&db->sd_mac_table, gid_address_vni (dst),
			    gid_address_mac (dst), gid_address_mac (src));
    case GID_ADDR_SRC_DST:
      switch (gid_address_sd_dst_type (dst))
	{
	case FID_ADDR_IP_PREF:
	  return ip_sd_lookup (db, gid_address_vni (dst),
			       &gid_address_sd_dst_ippref (dst),
			       &gid_address_sd_src_ippref (dst));
	  break;
	case FID_ADDR_MAC:
	  return mac_sd_lookup (&db->sd_mac_table, gid_address_vni (dst),
				gid_address_sd_dst_mac (dst),
				gid_address_sd_src_mac (dst));
	  break;
	default:
	  clib_warning ("Source/Dest address type %d not supported!",
			gid_address_sd_dst_type (dst));
	  break;
	}
      break;
    case GID_ADDR_NSH:
      return gid_dictionary_lookup (db, dst);
      break;
    default:
      clib_warning ("address type %d not supported!", gid_address_type (dst));
      break;
    }
  return GID_LOOKUP_MISS;
}

static void
ip4_compute_prefix_lengths_in_search_order (gid_ip4_table_t * db)
{
  int i;
  vec_reset_length (db->ip4_prefix_lengths_in_search_order);
  /* Note: bitmap reversed so this is in fact a longest prefix match */

  /* *INDENT-OFF* */
  clib_bitmap_foreach (i, db->ip4_non_empty_dst_address_length_bitmap,
  ({
    int dst_address_length = 32 - i;
    vec_add1 (db->ip4_prefix_lengths_in_search_order, dst_address_length);
  }));
  /* *INDENT-ON* */

}

static u32
add_del_ip4_key (gid_ip4_table_t * db, u32 vni, ip_prefix_t * pref, u32 val,
		 u8 is_add)
{
  BVT (clib_bihash_kv) kv, value;
  u32 old_val = ~0;
  ip4_address_t key;
  u8 plen = ip_prefix_len (pref);

  clib_memcpy (&key, &ip_prefix_v4 (pref), sizeof (key));
  key.as_u32 &= db->ip4_fib_masks[plen].as_u32;
  if (is_add)
    {
      db->ip4_non_empty_dst_address_length_bitmap =
	clib_bitmap_set (db->ip4_non_empty_dst_address_length_bitmap,
			 32 - plen, 1);
      ip4_compute_prefix_lengths_in_search_order (db);

      db->ip4_prefix_len_refcount[plen]++;
    }
  else
    {
      ASSERT (db->ip4_prefix_len_refcount[plen] != 0);

      db->ip4_prefix_len_refcount[plen]--;

      if (db->ip4_prefix_len_refcount[plen] == 0)
	{
	  db->ip4_non_empty_dst_address_length_bitmap =
	    clib_bitmap_set (db->ip4_non_empty_dst_address_length_bitmap,
			     32 - plen, 0);
	  ip4_compute_prefix_lengths_in_search_order (db);
	}
    }

  kv.key[0] = ((u64) vni << 32) | key.as_u32;
  kv.key[1] = 0;
  kv.key[2] = 0;

  if (BV (clib_bihash_search) (&db->ip4_lookup_table, &kv, &value) == 0)
    old_val = value.value;

  if (!is_add)
    {
      BV (clib_bihash_add_del) (&db->ip4_lookup_table, &kv, 0 /* is_add */ );
      db->count--;
    }
  else
    {
      kv.value = val;
      BV (clib_bihash_add_del) (&db->ip4_lookup_table, &kv, 1 /* is_add */ );
      db->count++;
    }
  return old_val;
}

static void
ip4_lookup_init (gid_ip4_table_t * db)
{
  uword i;

  clib_memset (db->ip4_prefix_len_refcount, 0,
	       sizeof (db->ip4_prefix_len_refcount));

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

  db->ip4_lookup_table_nbuckets =
    1 << max_log2 (db->ip4_lookup_table_nbuckets);

  if (db->ip4_lookup_table_size == 0)
    db->ip4_lookup_table_size = IP4_LOOKUP_DEFAULT_HASH_MEMORY_SIZE;

  BV (clib_bihash_init) (&db->ip4_lookup_table, "ip4 lookup table",
			 db->ip4_lookup_table_nbuckets,
			 db->ip4_lookup_table_size);
}

static u32
add_del_sd_ip4_key (gid_dictionary_t * db, u32 vni, ip_prefix_t * dst_pref,
		    ip_prefix_t * src_pref, u32 val, u8 is_add)
{
  u32 sfi, old_val = ~0;
  gid_ip4_table_t *sfib;

  sfi = ip4_lookup_exact_match (&db->dst_ip4_table, vni, dst_pref);

  if (is_add)
    {
      if (GID_LOOKUP_MISS == sfi)
	{
	  pool_get (db->src_ip4_table_pool, sfib);
	  ip4_lookup_init (sfib);
	  add_del_ip4_key (&db->dst_ip4_table, vni, dst_pref,
			   sfib - db->src_ip4_table_pool, is_add);
	  if (src_pref)
	    add_del_ip4_key (sfib, 0 /* vni */ , src_pref, val, is_add);
	  else
	    {
	      ip_prefix_t sp;
	      clib_memset (&sp, 0, sizeof (sp));
	      add_del_ip4_key (sfib, 0 /* vni */ , &sp, val, is_add);
	    }
	}
      else
	{
	  ASSERT (!pool_is_free_index (db->src_ip4_table_pool, sfi));
	  sfib = pool_elt_at_index (db->src_ip4_table_pool, sfi);
	  if (src_pref)
	    {
	      old_val = ip4_lookup_exact_match (sfib, 0, src_pref);
	      add_del_ip4_key (sfib, 0 /* vni */ , src_pref, val, is_add);
	    }
	  else
	    {
	      ip_prefix_t sp;
	      clib_memset (&sp, 0, sizeof (sp));
	      old_val =
		add_del_ip4_key (sfib, 0 /* vni */ , &sp, val, is_add);
	    }
	}
    }
  else
    {
      if (GID_LOOKUP_MISS != sfi)
	{
	  sfib = pool_elt_at_index (db->src_ip4_table_pool, sfi);
	  if (src_pref)
	    old_val = add_del_ip4_key (sfib, 0, src_pref, 0, is_add);
	  else
	    {
	      ip_prefix_t sp;
	      clib_memset (&sp, 0, sizeof (sp));
	      old_val = add_del_ip4_key (sfib, 0, &sp, 0, is_add);
	    }

	  if (sfib->count == 0)
	    add_del_ip4_key (&db->dst_ip4_table, vni, dst_pref, 0, is_add);
	}
      else
	clib_warning ("cannot delete dst mapping %U!", format_ip_prefix,
		      dst_pref);
    }
  return old_val;
}

static void
ip6_compute_prefix_lengths_in_search_order (gid_ip6_table_t * db)
{
  int i;
  vec_reset_length (db->ip6_prefix_lengths_in_search_order);
  /* Note: bitmap reversed so this is in fact a longest prefix match */

  /* *INDENT-OFF* */
  clib_bitmap_foreach (i, db->ip6_non_empty_dst_address_length_bitmap,
  ({
    int dst_address_length = 128 - i;
    vec_add1 (db->ip6_prefix_lengths_in_search_order, dst_address_length);
  }));
  /* *INDENT-ON* */
}

static u32
add_del_ip6_key (gid_ip6_table_t * db, u32 vni, ip_prefix_t * pref, u32 val,
		 u8 is_add)
{
  BVT (clib_bihash_kv) kv, value;
  u32 old_val = ~0;
  ip6_address_t key;
  u8 plen = ip_prefix_len (pref);

  clib_memcpy (&key, &ip_prefix_v6 (pref), sizeof (key));
  ip6_address_mask (&key, &db->ip6_fib_masks[plen]);
  if (is_add)
    {
      db->ip6_non_empty_dst_address_length_bitmap =
	clib_bitmap_set (db->ip6_non_empty_dst_address_length_bitmap,
			 128 - plen, 1);
      ip6_compute_prefix_lengths_in_search_order (db);
      db->ip6_prefix_len_refcount[plen]++;
    }
  else
    {
      ASSERT (db->ip6_prefix_len_refcount[plen] != 0);

      db->ip6_prefix_len_refcount[plen]--;

      if (db->ip6_prefix_len_refcount[plen] == 0)
	{
	  db->ip6_non_empty_dst_address_length_bitmap =
	    clib_bitmap_set (db->ip6_non_empty_dst_address_length_bitmap,
			     128 - plen, 0);
	  ip6_compute_prefix_lengths_in_search_order (db);
	}
    }

  kv.key[0] = key.as_u64[0];
  kv.key[1] = key.as_u64[1];
  kv.key[2] = (u64) vni;
//  kv.key[2] = ((u64)((fib - im->fibs))<<32) | ip_prefix_len(key);

  if (BV (clib_bihash_search) (&db->ip6_lookup_table, &kv, &value) == 0)
    old_val = value.value;

  if (!is_add)
    {
      BV (clib_bihash_add_del) (&db->ip6_lookup_table, &kv, 0 /* is_add */ );
      db->count--;
    }
  else
    {
      kv.value = val;
      BV (clib_bihash_add_del) (&db->ip6_lookup_table, &kv, 1 /* is_add */ );
      db->count++;
    }
  return old_val;
}

static u32
add_del_mac (gid_mac_table_t * db, u32 vni, u8 * dst_mac, u8 * src_mac,
	     u32 val, u8 is_add)
{
  BVT (clib_bihash_kv) kv, value;
  u32 old_val = ~0;

  make_mac_sd_key (&kv, vni, src_mac, dst_mac);

  if (BV (clib_bihash_search) (&db->mac_lookup_table, &kv, &value) == 0)
    old_val = value.value;

  if (!is_add)
    {
      BV (clib_bihash_add_del) (&db->mac_lookup_table, &kv, 0 /* is_add */ );
      db->count--;
    }
  else
    {
      kv.value = val;
      BV (clib_bihash_add_del) (&db->mac_lookup_table, &kv, 1 /* is_add */ );
      db->count++;
    }
  return old_val;
}

static void
ip6_lookup_init (gid_ip6_table_t * db)
{
  uword i;

  clib_memset (db->ip6_prefix_len_refcount, 0,
	       sizeof (db->ip6_prefix_len_refcount));

  for (i = 0; i < ARRAY_LEN (db->ip6_fib_masks); i++)
    {
      u32 j, i0, i1;

      i0 = i / 32;
      i1 = i % 32;

      for (j = 0; j < i0; j++)
	db->ip6_fib_masks[i].as_u32[j] = ~0;

      if (i1)
	db->ip6_fib_masks[i].as_u32[i0] =
	  clib_host_to_net_u32 (pow2_mask (i1) << (32 - i1));
    }

  if (db->ip6_lookup_table_nbuckets == 0)
    db->ip6_lookup_table_nbuckets = IP6_LOOKUP_DEFAULT_HASH_NUM_BUCKETS;

  db->ip6_lookup_table_nbuckets =
    1 << max_log2 (db->ip6_lookup_table_nbuckets);

  if (db->ip6_lookup_table_size == 0)
    db->ip6_lookup_table_size = IP6_LOOKUP_DEFAULT_HASH_MEMORY_SIZE;

  BV (clib_bihash_init) (&db->ip6_lookup_table, "ip6 lookup table",
			 db->ip6_lookup_table_nbuckets,
			 db->ip6_lookup_table_size);
}

static u32
add_del_sd_ip6_key (gid_dictionary_t * db, u32 vni, ip_prefix_t * dst_pref,
		    ip_prefix_t * src_pref, u32 val, u8 is_add)
{
  u32 sfi, old_val = ~0;
  gid_ip6_table_t *sfib;

  sfi = ip6_lookup_exact_match (&db->dst_ip6_table, vni, dst_pref);

  if (is_add)
    {
      if (GID_LOOKUP_MISS == sfi)
	{
	  pool_get (db->src_ip6_table_pool, sfib);
	  ip6_lookup_init (sfib);
	  add_del_ip6_key (&db->dst_ip6_table, vni, dst_pref,
			   sfib - db->src_ip6_table_pool, is_add);
	  if (src_pref)
	    add_del_ip6_key (sfib, 0 /* vni */ , src_pref, val, is_add);
	  else
	    {
	      ip_prefix_t sp;
	      clib_memset (&sp, 0, sizeof (sp));
	      ip_prefix_version (&sp) = IP6;
	      add_del_ip6_key (sfib, 0 /* vni */ , &sp, val, is_add);
	    }
	}
      else
	{
	  ASSERT (!pool_is_free_index (db->src_ip6_table_pool, sfi));
	  sfib = pool_elt_at_index (db->src_ip6_table_pool, sfi);
	  if (src_pref)
	    {
	      old_val = ip6_lookup_exact_match (sfib, 0, src_pref);
	      add_del_ip6_key (sfib, 0 /* vni */ , src_pref, val, is_add);
	    }
	  else
	    {
	      ip_prefix_t sp;
	      clib_memset (&sp, 0, sizeof (sp));
	      ip_prefix_version (&sp) = IP6;
	      old_val =
		add_del_ip6_key (sfib, 0 /* vni */ , &sp, val, is_add);
	    }
	}
    }
  else
    {
      if (GID_LOOKUP_MISS != sfi)
	{
	  sfib = pool_elt_at_index (db->src_ip6_table_pool, sfi);
	  if (src_pref)
	    old_val = add_del_ip6_key (sfib, 0, src_pref, 0, is_add);
	  else
	    {
	      ip_prefix_t sp;
	      clib_memset (&sp, 0, sizeof (sp));
	      ip_prefix_version (&sp) = IP6;
	      old_val = add_del_ip6_key (sfib, 0, &sp, 0, is_add);
	    }

	  if (sfib->count == 0)
	    add_del_ip6_key (&db->dst_ip6_table, vni, dst_pref, 0, is_add);
	}
      else
	clib_warning ("cannot delete dst mapping %U!", format_ip_prefix,
		      dst_pref);
    }
  return old_val;
}

static u32
add_del_ip (gid_dictionary_t * db, u32 vni, ip_prefix_t * dst_key,
	    ip_prefix_t * src_key, u32 value, u8 is_add)
{
  switch (ip_prefix_version (dst_key))
    {
    case IP4:
      return add_del_sd_ip4_key (db, vni, dst_key, src_key, value, is_add);
      break;
    case IP6:
      return add_del_sd_ip6_key (db, vni, dst_key, src_key, value, is_add);
      break;
    default:
      clib_warning ("address type %d not supported!",
		    ip_prefix_version (dst_key));
      break;
    }
  return ~0;
}

static u32
add_del_sd (gid_dictionary_t * db, u32 vni, source_dest_t * key, u32 value,
	    u8 is_add)
{
  switch (sd_dst_type (key))
    {
    case FID_ADDR_IP_PREF:
      add_del_ip (db, vni, &sd_dst_ippref (key), &sd_src_ippref (key),
		  value, is_add);

    case FID_ADDR_MAC:
      return add_del_mac (&db->sd_mac_table, vni, sd_dst_mac (key),
			  sd_src_mac (key), value, is_add);

    default:
      clib_warning ("SD address type %d not supported!", sd_dst_type (key));
      break;
    }

  return ~0;
}

static u64
add_del_arp_ndp (gid_l2_arp_ndp_table_t * db, u32 bd, ip_address_t * key,
		 u64 value, u8 is_add)
{
  BVT (clib_bihash_kv) kv, result;
  u32 old_val = ~0;

  make_arp_ndp_key (&kv, bd, key);
  if (BV (clib_bihash_search) (&db->arp_ndp_lookup_table, &kv, &result) == 0)
    old_val = result.value;

  if (is_add)
    {
      kv.value = value;
      BV (clib_bihash_add_del) (&db->arp_ndp_lookup_table, &kv,
				1 /* is_add */ );
      db->count++;
    }
  else
    {
      BV (clib_bihash_add_del) (&db->arp_ndp_lookup_table, &kv,
				0 /* is_add */ );
      db->count--;
    }
  return old_val;
}

static u32
add_del_nsh (gid_nsh_table_t * db, u32 vni, u32 spi, u8 si, u32 value,
	     u8 is_add)
{
  BVT (clib_bihash_kv) kv, result;
  u32 old_val = ~0;

  make_nsh_key (&kv, vni, spi, si);
  if (BV (clib_bihash_search) (&db->nsh_lookup_table, &kv, &result) == 0)
    old_val = result.value;

  if (is_add)
    {
      kv.value = value;
      BV (clib_bihash_add_del) (&db->nsh_lookup_table, &kv, 1 /* is_add */ );
      db->count++;
    }
  else
    {
      BV (clib_bihash_add_del) (&db->nsh_lookup_table, &kv, 0 /* is_add */ );
      db->count--;
    }
  return old_val;
}

u32
gid_dictionary_add_del (gid_dictionary_t * db, gid_address_t * key, u64 value,
			u8 is_add)
{
  switch (gid_address_type (key))
    {
    case GID_ADDR_IP_PREFIX:
      return add_del_ip (db, gid_address_vni (key), &gid_address_ippref (key),
			 0, (u32) value, is_add);
    case GID_ADDR_MAC:
      return add_del_mac (&db->sd_mac_table, gid_address_vni (key),
			  gid_address_mac (key), 0, (u32) value, is_add);
    case GID_ADDR_SRC_DST:
      return add_del_sd (db, gid_address_vni (key), &gid_address_sd (key),
			 (u32) value, is_add);
    case GID_ADDR_ARP:
    case GID_ADDR_NDP:
      return add_del_arp_ndp (&db->arp_ndp_table,
			      gid_address_arp_ndp_bd (key),
			      &gid_address_arp_ndp_ip (key), value, is_add);
    case GID_ADDR_NSH:
      return add_del_nsh (&db->nsh_table, gid_address_vni (key),
			  gid_address_nsh_spi (key), gid_address_nsh_si (key),
			  value, is_add);

    default:
      clib_warning ("address type %d not supported!", gid_address_type (key));
      break;
    }
  return ~0;
}

static void
mac_lookup_init (gid_mac_table_t * db)
{
  if (db->mac_lookup_table_nbuckets == 0)
    db->mac_lookup_table_nbuckets = MAC_LOOKUP_DEFAULT_HASH_NUM_BUCKETS;

  db->mac_lookup_table_nbuckets =
    1 << max_log2 (db->mac_lookup_table_nbuckets);

  if (db->mac_lookup_table_size == 0)
    db->mac_lookup_table_size = MAC_LOOKUP_DEFAULT_HASH_MEMORY_SIZE;

  BV (clib_bihash_init) (&db->mac_lookup_table, "mac lookup table",
			 db->mac_lookup_table_nbuckets,
			 db->mac_lookup_table_size);
}

static void
arp_ndp_lookup_init (gid_l2_arp_ndp_table_t * db)
{
  if (db->arp_ndp_lookup_table_nbuckets == 0)
    db->arp_ndp_lookup_table_nbuckets =
      ARP_NDP_LOOKUP_DEFAULT_HASH_NUM_BUCKETS;

  db->arp_ndp_lookup_table_nbuckets =
    1 << max_log2 (db->arp_ndp_lookup_table_nbuckets);

  if (db->arp_ndp_lookup_table_size == 0)
    db->arp_ndp_lookup_table_size = ARP_NDP_LOOKUP_DEFAULT_HASH_MEMORY_SIZE;

  BV (clib_bihash_init) (&db->arp_ndp_lookup_table, "arp ndp lookup table",
			 db->arp_ndp_lookup_table_nbuckets,
			 db->arp_ndp_lookup_table_size);
}

static void
nsh_lookup_init (gid_nsh_table_t * db)
{
  if (db->nsh_lookup_table_nbuckets == 0)
    db->nsh_lookup_table_nbuckets = MAC_LOOKUP_DEFAULT_HASH_NUM_BUCKETS;

  db->nsh_lookup_table_nbuckets =
    1 << max_log2 (db->nsh_lookup_table_nbuckets);

  if (db->nsh_lookup_table_size == 0)
    db->nsh_lookup_table_size = MAC_LOOKUP_DEFAULT_HASH_MEMORY_SIZE;

  BV (clib_bihash_init) (&db->nsh_lookup_table, "nsh lookup table",
			 db->nsh_lookup_table_nbuckets,
			 db->nsh_lookup_table_size);
}

void
gid_dictionary_init (gid_dictionary_t * db)
{
  ip4_lookup_init (&db->dst_ip4_table);
  ip6_lookup_init (&db->dst_ip6_table);
  mac_lookup_init (&db->sd_mac_table);
  arp_ndp_lookup_init (&db->arp_ndp_table);
  nsh_lookup_init (&db->nsh_table);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
