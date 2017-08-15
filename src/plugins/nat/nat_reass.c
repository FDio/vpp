/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
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
 * @file
 * @brief NAT plugin virtual fragmentation reassembly
 */

#include <vnet/vnet.h>
#include <nat/nat_reass.h>

nat_reass_main_t nat_reass_main;

static u32
nat_reass_get_nbuckets (u8 is_ip6)
{
  nat_reass_main_t *srm = &nat_reass_main;
  u32 nbuckets;
  u8 i;

  if (is_ip6)
    nbuckets = (u32) (srm->ip6_max_reass / NAT_REASS_HT_LOAD_FACTOR);
  else
    nbuckets = (u32) (srm->ip4_max_reass / NAT_REASS_HT_LOAD_FACTOR);

  for (i = 0; i < 31; i++)
    if ((1 << i) >= nbuckets)
      break;
  nbuckets = 1 << i;

  return nbuckets;
}

static_always_inline void
nat_ip4_reass_get_frags_inline (nat_reass_ip4_t * reass, u32 ** bi)
{
  nat_reass_main_t *srm = &nat_reass_main;
  u32 elt_index;
  dlist_elt_t *elt;

  while ((elt_index =
	  clib_dlist_remove_head (srm->ip4_frags_list_pool,
				  reass->frags_per_reass_list_head_index)) !=
	 ~0)
    {
      elt = pool_elt_at_index (srm->ip4_frags_list_pool, elt_index);
      vec_add1 (*bi, elt->value);
      reass->frag_n--;
      pool_put_index (srm->ip4_frags_list_pool, elt_index);
    }
}

static_always_inline void
nat_ip6_reass_get_frags_inline (nat_reass_ip6_t * reass, u32 ** bi)
{
  nat_reass_main_t *srm = &nat_reass_main;
  u32 elt_index;
  dlist_elt_t *elt;

  while ((elt_index =
	  clib_dlist_remove_head (srm->ip6_frags_list_pool,
				  reass->frags_per_reass_list_head_index)) !=
	 ~0)
    {
      elt = pool_elt_at_index (srm->ip6_frags_list_pool, elt_index);
      vec_add1 (*bi, elt->value);
      reass->frag_n--;
      pool_put_index (srm->ip6_frags_list_pool, elt_index);
    }
}

int
nat_reass_set (u32 timeout, u16 max_reass, u8 max_frag, u8 drop_frag,
	       u8 is_ip6)
{
  nat_reass_main_t *srm = &nat_reass_main;
  u32 nbuckets;

  if (is_ip6)
    {
      if (srm->ip6_max_reass != max_reass)
	{
	  clib_spinlock_lock_if_init (&srm->ip6_reass_lock);

	  srm->ip6_max_reass = max_reass;
	  pool_free (srm->ip6_reass_pool);
	  pool_alloc (srm->ip6_reass_pool, srm->ip4_max_reass);
	  nbuckets = nat_reass_get_nbuckets (0);
	  clib_bihash_free_48_8 (&srm->ip6_reass_hash);
	  clib_bihash_init_48_8 (&srm->ip6_reass_hash, "nat-ip6-reass",
				 nbuckets, nbuckets * 1024);

	  clib_spinlock_unlock_if_init (&srm->ip6_reass_lock);
	}
      srm->ip6_timeout = timeout;
      srm->ip6_max_frag = max_frag;
      srm->ip6_drop_frag = drop_frag;
    }
  else
    {
      if (srm->ip4_max_reass != max_reass)
	{
	  clib_spinlock_lock_if_init (&srm->ip4_reass_lock);

	  srm->ip4_max_reass = max_reass;
	  pool_free (srm->ip4_reass_pool);
	  pool_alloc (srm->ip4_reass_pool, srm->ip4_max_reass);
	  nbuckets = nat_reass_get_nbuckets (0);
	  clib_bihash_free_16_8 (&srm->ip4_reass_hash);
	  clib_bihash_init_16_8 (&srm->ip4_reass_hash, "nat-ip4-reass",
				 nbuckets, nbuckets * 1024);
	  clib_spinlock_unlock_if_init (&srm->ip4_reass_lock);
	}
      srm->ip4_timeout = timeout;
      srm->ip4_max_frag = max_frag;
      srm->ip4_drop_frag = drop_frag;
    }

  return 0;
}

u32
nat_reass_get_timeout (u8 is_ip6)
{
  nat_reass_main_t *srm = &nat_reass_main;

  if (is_ip6)
    return srm->ip6_timeout;

  return srm->ip4_timeout;
}

u16
nat_reass_get_max_reass (u8 is_ip6)
{
  nat_reass_main_t *srm = &nat_reass_main;

  if (is_ip6)
    return srm->ip6_max_reass;

  return srm->ip4_max_reass;
}

u8
nat_reass_get_max_frag (u8 is_ip6)
{
  nat_reass_main_t *srm = &nat_reass_main;

  if (is_ip6)
    return srm->ip6_max_frag;

  return srm->ip4_max_frag;
}

u8
nat_reass_is_drop_frag (u8 is_ip6)
{
  nat_reass_main_t *srm = &nat_reass_main;

  if (is_ip6)
    return srm->ip6_drop_frag;

  return srm->ip4_drop_frag;
}

static_always_inline nat_reass_ip4_t *
nat_ip4_reass_lookup (nat_reass_ip4_key_t * k, f64 now)
{
  nat_reass_main_t *srm = &nat_reass_main;
  clib_bihash_kv_16_8_t kv, value;
  nat_reass_ip4_t *reass;

  kv.key[0] = k->as_u64[0];
  kv.key[1] = k->as_u64[1];

  if (clib_bihash_search_16_8 (&srm->ip4_reass_hash, &kv, &value))
    return 0;

  reass = pool_elt_at_index (srm->ip4_reass_pool, value.value);
  if (now < reass->last_heard + (f64) srm->ip4_timeout)
    return reass;

  return 0;
}

nat_reass_ip4_t *
nat_ip4_reass_find_or_create (ip4_address_t src, ip4_address_t dst,
			      u16 frag_id, u8 proto, u8 reset_timeout,
			      u32 ** bi_to_drop)
{
  nat_reass_main_t *srm = &nat_reass_main;
  nat_reass_ip4_t *reass = 0;
  nat_reass_ip4_key_t k;
  f64 now = vlib_time_now (srm->vlib_main);
  dlist_elt_t *oldest_elt, *elt;
  dlist_elt_t *per_reass_list_head_elt;
  u32 oldest_index, elt_index;
  clib_bihash_kv_16_8_t kv;

  k.src.as_u32 = src.as_u32;
  k.dst.as_u32 = dst.as_u32;
  k.frag_id = frag_id;
  k.proto = proto;

  clib_spinlock_lock_if_init (&srm->ip4_reass_lock);

  reass = nat_ip4_reass_lookup (&k, now);
  if (reass)
    {
      if (reset_timeout)
	{
	  reass->last_heard = now;
	  clib_dlist_remove (srm->ip4_reass_lru_list_pool,
			     reass->lru_list_index);
	  clib_dlist_addtail (srm->ip4_reass_lru_list_pool,
			      srm->ip4_reass_head_index,
			      reass->lru_list_index);
	}
      goto unlock;
    }

  if (srm->ip4_reass_n >= srm->ip4_max_reass)
    {
      oldest_index =
	clib_dlist_remove_head (srm->ip4_reass_lru_list_pool,
				srm->ip4_reass_head_index);
      ASSERT (oldest_index != ~0);
      oldest_elt =
	pool_elt_at_index (srm->ip4_reass_lru_list_pool, oldest_index);
      reass = pool_elt_at_index (srm->ip4_reass_pool, oldest_elt->value);
      if (now < reass->last_heard + (f64) srm->ip4_timeout)
	{
	  clib_dlist_addhead (srm->ip4_reass_lru_list_pool,
			      srm->ip4_reass_head_index, oldest_index);
	  clib_warning ("no free resassembly slot");
	  reass = 0;
	  goto unlock;
	}

      clib_dlist_addtail (srm->ip4_reass_lru_list_pool,
			  srm->ip4_reass_head_index, oldest_index);

      kv.key[0] = k.as_u64[0];
      kv.key[1] = k.as_u64[1];
      if (clib_bihash_add_del_16_8 (&srm->ip4_reass_hash, &kv, 0))
	{
	  reass = 0;
	  goto unlock;
	}

      nat_ip4_reass_get_frags_inline (reass, bi_to_drop);
    }
  else
    {
      pool_get (srm->ip4_reass_pool, reass);
      pool_get (srm->ip4_reass_lru_list_pool, elt);
      reass->lru_list_index = elt_index = elt - srm->ip4_reass_lru_list_pool;
      clib_dlist_init (srm->ip4_reass_lru_list_pool, elt_index);
      elt->value = reass - srm->ip4_reass_pool;
      clib_dlist_addtail (srm->ip4_reass_lru_list_pool,
			  srm->ip4_reass_head_index, elt_index);
      pool_get (srm->ip4_frags_list_pool, per_reass_list_head_elt);
      reass->frags_per_reass_list_head_index =
	per_reass_list_head_elt - srm->ip4_frags_list_pool;
      clib_dlist_init (srm->ip4_frags_list_pool,
		       reass->frags_per_reass_list_head_index);
      srm->ip4_reass_n++;
    }

  reass->key.as_u64[0] = kv.key[0] = k.as_u64[0];
  reass->key.as_u64[1] = kv.key[1] = k.as_u64[1];
  kv.value = reass - srm->ip4_reass_pool;
  reass->sess_index = (u32) ~ 0;
  reass->last_heard = now;

  if (clib_bihash_add_del_16_8 (&srm->ip4_reass_hash, &kv, 1))
    {
      reass = 0;
      goto unlock;
    }

unlock:
  clib_spinlock_unlock_if_init (&srm->ip4_reass_lock);
  return reass;
}

int
nat_ip4_reass_add_fragment (nat_reass_ip4_t * reass, u32 bi)
{
  nat_reass_main_t *srm = &nat_reass_main;
  dlist_elt_t *elt;
  u32 elt_index;

  if (reass->frag_n >= srm->ip4_max_frag)
    return -1;

  clib_spinlock_lock_if_init (&srm->ip4_reass_lock);

  pool_get (srm->ip4_frags_list_pool, elt);
  elt_index = elt - srm->ip4_frags_list_pool;
  clib_dlist_init (srm->ip4_frags_list_pool, elt_index);
  elt->value = bi;
  clib_dlist_addtail (srm->ip4_frags_list_pool,
		      reass->frags_per_reass_list_head_index, elt_index);
  reass->frag_n++;

  clib_spinlock_unlock_if_init (&srm->ip4_reass_lock);

  return 0;
}

void
nat_ip4_reass_get_frags (nat_reass_ip4_t * reass, u32 ** bi)
{
  nat_reass_main_t *srm = &nat_reass_main;

  clib_spinlock_lock_if_init (&srm->ip4_reass_lock);

  nat_ip4_reass_get_frags_inline (reass, bi);

  clib_spinlock_unlock_if_init (&srm->ip4_reass_lock);
}

void
nat_ip4_reass_walk (nat_ip4_reass_walk_fn_t fn, void *ctx)
{
  nat_reass_ip4_t *reass;
  nat_reass_main_t *srm = &nat_reass_main;
  f64 now = vlib_time_now (srm->vlib_main);

  /* *INDENT-OFF* */
  pool_foreach (reass, srm->ip4_reass_pool,
  ({
    if (now < reass->last_heard + (f64) srm->ip4_timeout)
      {
        if (fn (reass, ctx))
          return;
      }
  }));
  /* *INDENT-ON* */
}

static_always_inline nat_reass_ip6_t *
nat_ip6_reass_lookup (nat_reass_ip6_key_t * k, f64 now)
{
  nat_reass_main_t *srm = &nat_reass_main;
  clib_bihash_kv_48_8_t kv, value;
  nat_reass_ip6_t *reass;

  k->unused = 0;
  kv.key[0] = k->as_u64[0];
  kv.key[1] = k->as_u64[1];
  kv.key[2] = k->as_u64[2];
  kv.key[3] = k->as_u64[3];
  kv.key[4] = k->as_u64[4];
  kv.key[5] = k->as_u64[5];

  if (clib_bihash_search_48_8 (&srm->ip6_reass_hash, &kv, &value))
    return 0;

  reass = pool_elt_at_index (srm->ip6_reass_pool, value.value);
  if (now < reass->last_heard + (f64) srm->ip6_timeout)
    return reass;

  return 0;
}

nat_reass_ip6_t *
nat_ip6_reass_find_or_create (ip6_address_t src, ip6_address_t dst,
			      u32 frag_id, u8 proto, u8 reset_timeout,
			      u32 ** bi_to_drop)
{
  nat_reass_main_t *srm = &nat_reass_main;
  nat_reass_ip6_t *reass = 0;
  nat_reass_ip6_key_t k;
  f64 now = vlib_time_now (srm->vlib_main);
  dlist_elt_t *oldest_elt, *elt;
  dlist_elt_t *per_reass_list_head_elt;
  u32 oldest_index, elt_index;
  clib_bihash_kv_48_8_t kv;

  k.src.as_u64[0] = src.as_u64[0];
  k.src.as_u64[1] = src.as_u64[1];
  k.dst.as_u64[0] = dst.as_u64[0];
  k.dst.as_u64[1] = dst.as_u64[1];
  k.frag_id = frag_id;
  k.proto = proto;
  k.unused = 0;

  clib_spinlock_lock_if_init (&srm->ip6_reass_lock);

  reass = nat_ip6_reass_lookup (&k, now);
  if (reass)
    {
      if (reset_timeout)
	{
	  reass->last_heard = now;
	  clib_dlist_remove (srm->ip6_reass_lru_list_pool,
			     reass->lru_list_index);
	  clib_dlist_addtail (srm->ip6_reass_lru_list_pool,
			      srm->ip6_reass_head_index,
			      reass->lru_list_index);
	}
      goto unlock;
    }

  if (srm->ip6_reass_n >= srm->ip6_max_reass)
    {
      oldest_index =
	clib_dlist_remove_head (srm->ip6_reass_lru_list_pool,
				srm->ip6_reass_head_index);
      ASSERT (oldest_index != ~0);
      oldest_elt =
	pool_elt_at_index (srm->ip4_reass_lru_list_pool, oldest_index);
      reass = pool_elt_at_index (srm->ip6_reass_pool, oldest_elt->value);
      if (now < reass->last_heard + (f64) srm->ip6_timeout)
	{
	  clib_dlist_addhead (srm->ip6_reass_lru_list_pool,
			      srm->ip6_reass_head_index, oldest_index);
	  clib_warning ("no free resassembly slot");
	  reass = 0;
	  goto unlock;
	}

      clib_dlist_addtail (srm->ip6_reass_lru_list_pool,
			  srm->ip6_reass_head_index, oldest_index);

      kv.key[0] = k.as_u64[0];
      kv.key[1] = k.as_u64[1];
      kv.key[2] = k.as_u64[2];
      kv.key[3] = k.as_u64[4];
      kv.key[4] = k.as_u64[5];
      if (clib_bihash_add_del_48_8 (&srm->ip6_reass_hash, &kv, 0))
	{
	  reass = 0;
	  goto unlock;
	}

      nat_ip6_reass_get_frags_inline (reass, bi_to_drop);
    }
  else
    {
      pool_get (srm->ip6_reass_pool, reass);
      pool_get (srm->ip6_reass_lru_list_pool, elt);
      reass->lru_list_index = elt_index = elt - srm->ip6_reass_lru_list_pool;
      clib_dlist_init (srm->ip6_reass_lru_list_pool, elt_index);
      elt->value = reass - srm->ip6_reass_pool;
      clib_dlist_addtail (srm->ip6_reass_lru_list_pool,
			  srm->ip6_reass_head_index, elt_index);
      pool_get (srm->ip6_frags_list_pool, per_reass_list_head_elt);
      reass->frags_per_reass_list_head_index =
	per_reass_list_head_elt - srm->ip6_frags_list_pool;
      clib_dlist_init (srm->ip6_frags_list_pool,
		       reass->frags_per_reass_list_head_index);
      srm->ip6_reass_n++;
    }

  reass->key.as_u64[0] = kv.key[0] = k.as_u64[0];
  reass->key.as_u64[1] = kv.key[1] = k.as_u64[1];
  reass->key.as_u64[2] = kv.key[2] = k.as_u64[2];
  reass->key.as_u64[3] = kv.key[3] = k.as_u64[3];
  reass->key.as_u64[4] = kv.key[4] = k.as_u64[4];
  reass->key.as_u64[5] = kv.key[5] = k.as_u64[5];
  kv.value = reass - srm->ip6_reass_pool;
  reass->sess_index = (u32) ~ 0;
  reass->last_heard = now;

  if (clib_bihash_add_del_48_8 (&srm->ip6_reass_hash, &kv, 1))
    {
      reass = 0;
      goto unlock;
    }

unlock:
  clib_spinlock_unlock_if_init (&srm->ip6_reass_lock);
  return reass;
}

int
nat_ip6_reass_add_fragment (nat_reass_ip6_t * reass, u32 bi)
{
  nat_reass_main_t *srm = &nat_reass_main;
  dlist_elt_t *elt;
  u32 elt_index;

  if (reass->frag_n >= srm->ip6_max_frag)
    return -1;

  clib_spinlock_lock_if_init (&srm->ip6_reass_lock);

  pool_get (srm->ip6_frags_list_pool, elt);
  elt_index = elt - srm->ip6_frags_list_pool;
  clib_dlist_init (srm->ip6_frags_list_pool, elt_index);
  elt->value = bi;
  clib_dlist_addtail (srm->ip6_frags_list_pool,
		      reass->frags_per_reass_list_head_index, elt_index);
  reass->frag_n++;

  clib_spinlock_unlock_if_init (&srm->ip6_reass_lock);

  return 0;
}

void
nat_ip6_reass_get_frags (nat_reass_ip6_t * reass, u32 ** bi)
{
  nat_reass_main_t *srm = &nat_reass_main;

  clib_spinlock_lock_if_init (&srm->ip6_reass_lock);

  nat_ip6_reass_get_frags_inline (reass, bi);

  clib_spinlock_unlock_if_init (&srm->ip6_reass_lock);
}

void
nat_ip6_reass_walk (nat_ip6_reass_walk_fn_t fn, void *ctx)
{
  nat_reass_ip6_t *reass;
  nat_reass_main_t *srm = &nat_reass_main;
  f64 now = vlib_time_now (srm->vlib_main);

  /* *INDENT-OFF* */
  pool_foreach (reass, srm->ip6_reass_pool,
  ({
    if (now < reass->last_heard + (f64) srm->ip4_timeout)
      {
        if (fn (reass, ctx))
          return;
      }
  }));
  /* *INDENT-ON* */
}

clib_error_t *
nat_reass_init (vlib_main_t * vm)
{
  nat_reass_main_t *srm = &nat_reass_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  clib_error_t *error = 0;
  dlist_elt_t *head;
  u32 nbuckets, head_index;

  srm->vlib_main = vm;
  srm->vnet_main = vnet_get_main ();

  /* IPv4 */
  srm->ip4_timeout = NAT_REASS_TIMEOUT_DEFAULT;
  srm->ip4_max_reass = NAT_MAX_REASS_DEAFULT;
  srm->ip4_max_frag = NAT_MAX_FRAG_DEFAULT;
  srm->ip4_drop_frag = 0;
  srm->ip4_reass_n = 0;

  if (tm->n_vlib_mains > 1)
    clib_spinlock_init (&srm->ip4_reass_lock);

  pool_alloc (srm->ip4_reass_pool, srm->ip4_max_reass);

  nbuckets = nat_reass_get_nbuckets (0);
  clib_bihash_init_16_8 (&srm->ip4_reass_hash, "nat-ip4-reass", nbuckets,
			 nbuckets * 1024);

  pool_get (srm->ip4_reass_lru_list_pool, head);
  srm->ip4_reass_head_index = head_index =
    head - srm->ip4_reass_lru_list_pool;
  clib_dlist_init (srm->ip4_reass_lru_list_pool, head_index);

  /* IPv6 */
  srm->ip6_timeout = NAT_REASS_TIMEOUT_DEFAULT;
  srm->ip6_max_reass = NAT_MAX_REASS_DEAFULT;
  srm->ip6_max_frag = NAT_MAX_FRAG_DEFAULT;
  srm->ip6_drop_frag = 0;
  srm->ip6_reass_n = 0;

  if (tm->n_vlib_mains > 1)
    clib_spinlock_init (&srm->ip6_reass_lock);

  pool_alloc (srm->ip6_reass_pool, srm->ip6_max_reass);

  nbuckets = nat_reass_get_nbuckets (1);
  clib_bihash_init_48_8 (&srm->ip6_reass_hash, "nat-ip6-reass", nbuckets,
			 nbuckets * 1024);

  pool_get (srm->ip6_reass_lru_list_pool, head);
  srm->ip6_reass_head_index = head_index =
    head - srm->ip6_reass_lru_list_pool;
  clib_dlist_init (srm->ip6_reass_lru_list_pool, head_index);

  return error;
}

static clib_error_t *
nat_reass_command_fn (vlib_main_t * vm, unformat_input_t * input,
		      vlib_cli_command_t * cmd)
{
  clib_error_t *error = 0;
  unformat_input_t _line_input, *line_input = &_line_input;
  u32 timeout = 0, max_reass = 0, max_frag = 0;
  u8 drop_frag = (u8) ~ 0, is_ip6 = 0;
  int rv;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "max-reassemblies %u", &max_reass))
	;
      else if (unformat (line_input, "max-fragments %u", &max_frag))
	;
      else if (unformat (line_input, "timeout %u", &timeout))
	;
      else if (unformat (line_input, "enable"))
	drop_frag = 0;
      else if (unformat (line_input, "disable"))
	drop_frag = 1;
      else if (unformat (line_input, "ip4"))
	is_ip6 = 0;
      else if (unformat (line_input, "ip6"))
	is_ip6 = 1;
      else
	{
	  error = clib_error_return (0, "unknown input '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  if (!timeout)
    timeout = nat_reass_get_timeout (is_ip6);
  if (!max_reass)
    max_reass = nat_reass_get_max_reass (is_ip6);
  if (!max_frag)
    max_frag = nat_reass_get_max_frag (is_ip6);
  if (drop_frag == (u8) ~ 0)
    drop_frag = nat_reass_is_drop_frag (is_ip6);

  rv =
    nat_reass_set (timeout, (u16) max_reass, (u8) max_frag, drop_frag,
		   is_ip6);
  if (rv)
    {
      error = clib_error_return (0, "nat_set_reass return %d", rv);
      goto done;
    }

done:
  unformat_free (line_input);

  return error;
}

static int
nat_ip4_reass_walk_cli (nat_reass_ip4_t * reass, void *ctx)
{
  vlib_main_t *vm = ctx;

  vlib_cli_output (vm, "  src %U dst %U proto %u id 0x%04x cached %u",
		   format_ip4_address, &reass->key.src,
		   format_ip4_address, &reass->key.dst,
		   reass->key.proto,
		   clib_net_to_host_u16 (reass->key.frag_id), reass->frag_n);

  return 0;
}

static int
nat_ip6_reass_walk_cli (nat_reass_ip6_t * reass, void *ctx)
{
  vlib_main_t *vm = ctx;

  vlib_cli_output (vm, "  src %U dst %U proto %u id 0x%08x cached %u",
		   format_ip6_address, &reass->key.src,
		   format_ip6_address, &reass->key.dst,
		   reass->key.proto,
		   clib_net_to_host_u32 (reass->key.frag_id), reass->frag_n);

  return 0;
}

static clib_error_t *
show_nat_reass_command_fn (vlib_main_t * vm, unformat_input_t * input,
			   vlib_cli_command_t * cmd)
{
  vlib_cli_output (vm, "NAT IPv4 virtual fragmentation reassembly is %s",
		   nat_reass_is_drop_frag (0) ? "DISABLED" : "ENABLED");
  vlib_cli_output (vm, " max-reasssemblies %u", nat_reass_get_max_reass (0));
  vlib_cli_output (vm, " max-fragments %u", nat_reass_get_max_frag (0));
  vlib_cli_output (vm, " timeout %usec", nat_reass_get_timeout (0));
  vlib_cli_output (vm, " reassemblies:");
  nat_ip4_reass_walk (nat_ip4_reass_walk_cli, vm);

  vlib_cli_output (vm, "NAT IPv6 virtual fragmentation reassembly is %s",
		   nat_reass_is_drop_frag (1) ? "DISABLED" : "ENABLED");
  vlib_cli_output (vm, " max-reasssemblies %u", nat_reass_get_max_reass (1));
  vlib_cli_output (vm, " max-fragments %u", nat_reass_get_max_frag (1));
  vlib_cli_output (vm, " timeout %usec", nat_reass_get_timeout (1));
  vlib_cli_output (vm, " reassemblies:");
  nat_ip6_reass_walk (nat_ip6_reass_walk_cli, vm);

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (nat_reass_command, static) =
{
  .path = "nat virtual-reassembly",
  .short_help = "nat virtual-reassembly ip4|ip6 [max-reassemblies <n>] "
                "[max-fragments <n>] [timeout <sec>] [enable|disable]",
  .function = nat_reass_command_fn,
};

VLIB_CLI_COMMAND (show_nat_reass_command, static) =
{
  .path = "show nat virtual-reassembly",
  .short_help = "show nat virtual-reassembly",
  .function = show_nat_reass_command_fn,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
