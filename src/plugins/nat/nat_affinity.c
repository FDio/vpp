/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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
 * @brief NAT plugin client-IP based session affinity for load-balancing
 */

#include <nat/nat_affinity.h>
#include <nat/nat.h>

nat_affinity_main_t nat_affinity_main;

#define AFFINITY_HASH_BUCKETS 65536
#define AFFINITY_HASH_MEMORY (2 << 25)

u8 *
format_affinity_kvp (u8 * s, va_list * args)
{
  clib_bihash_kv_16_8_t *v = va_arg (*args, clib_bihash_kv_16_8_t *);
  nat_affinity_key_t k;

  k.as_u64[0] = v->key[0];
  k.as_u64[1] = v->key[1];

  s = format (s, "client %U backend %U:%d proto %U index %llu",
	      format_ip4_address, &k.client_addr,
	      format_ip4_address, &k.service_addr,
	      clib_net_to_host_u16 (k.service_port),
	      format_nat_protocol, k.proto);

  return s;
}

clib_error_t *
nat_affinity_init (vlib_main_t * vm)
{
  nat_affinity_main_t *nam = &nat_affinity_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  clib_error_t *error = 0;

  if (tm->n_vlib_mains > 1)
    clib_spinlock_init (&nam->affinity_lock);

  clib_bihash_init_16_8 (&nam->affinity_hash, "nat-affinity",
			 AFFINITY_HASH_BUCKETS, AFFINITY_HASH_MEMORY);
  clib_bihash_set_kvp_format_fn_16_8 (&nam->affinity_hash,
				      format_affinity_kvp);

  nam->vlib_main = vm;

  return error;
}

static_always_inline void
make_affinity_kv (clib_bihash_kv_16_8_t * kv, ip4_address_t client_addr,
		  ip4_address_t service_addr, u8 proto, u16 service_port)
{
  nat_affinity_key_t *key = (nat_affinity_key_t *) kv->key;

  key->client_addr = client_addr;
  key->service_addr = service_addr;
  key->proto = proto;
  key->service_port = service_port;

  kv->value = ~0ULL;
}

u32
nat_affinity_get_per_service_list_head_index (void)
{
  nat_affinity_main_t *nam = &nat_affinity_main;
  dlist_elt_t *head_elt;

  clib_spinlock_lock_if_init (&nam->affinity_lock);

  pool_get (nam->list_pool, head_elt);
  clib_dlist_init (nam->list_pool, head_elt - nam->list_pool);

  clib_spinlock_unlock_if_init (&nam->affinity_lock);

  return head_elt - nam->list_pool;
}

void
nat_affinity_flush_service (u32 affinity_per_service_list_head_index)
{
  nat_affinity_main_t *nam = &nat_affinity_main;
  u32 elt_index;
  dlist_elt_t *elt;
  nat_affinity_t *a;
  clib_bihash_kv_16_8_t kv;

  clib_spinlock_lock_if_init (&nam->affinity_lock);

  while ((elt_index =
	  clib_dlist_remove_head (nam->list_pool,
				  affinity_per_service_list_head_index)) !=
	 ~0)
    {
      elt = pool_elt_at_index (nam->list_pool, elt_index);
      a = pool_elt_at_index (nam->affinity_pool, elt->value);
      kv.key[0] = a->key.as_u64[0];
      kv.key[1] = a->key.as_u64[1];
      pool_put_index (nam->affinity_pool, elt->value);
      if (clib_bihash_add_del_16_8 (&nam->affinity_hash, &kv, 0))
	nat_elog_warn ("affinity key del failed");
      pool_put_index (nam->list_pool, elt_index);
    }
  pool_put_index (nam->list_pool, affinity_per_service_list_head_index);

  clib_spinlock_unlock_if_init (&nam->affinity_lock);
}

int
nat_affinity_find_and_lock (ip4_address_t client_addr,
			    ip4_address_t service_addr, u8 proto,
			    u16 service_port, u8 * backend_index)
{
  nat_affinity_main_t *nam = &nat_affinity_main;
  clib_bihash_kv_16_8_t kv, value;
  nat_affinity_t *a;
  int rv = 0;

  make_affinity_kv (&kv, client_addr, service_addr, proto, service_port);
  clib_spinlock_lock_if_init (&nam->affinity_lock);
  if (clib_bihash_search_16_8 (&nam->affinity_hash, &kv, &value))
    {
      rv = 1;
      goto unlock;
    }

  a = pool_elt_at_index (nam->affinity_pool, value.value);
  /* if already expired delete */
  if (a->ref_cnt == 0)
    {
      if (a->expire < vlib_time_now (nam->vlib_main))
	{
	  clib_dlist_remove (nam->list_pool, a->per_service_index);
	  pool_put_index (nam->list_pool, a->per_service_index);
	  pool_put_index (nam->affinity_pool, value.value);
	  if (clib_bihash_add_del_16_8 (&nam->affinity_hash, &kv, 0))
	    nat_elog_warn ("affinity key del failed");
	  rv = 1;
	  goto unlock;
	}
    }
  a->ref_cnt++;
  *backend_index = a->backend_index;

unlock:
  clib_spinlock_unlock_if_init (&nam->affinity_lock);
  return rv;
}

static int
affinity_is_expired_cb (clib_bihash_kv_16_8_t * kv, void *arg)
{
  nat_affinity_main_t *nam = &nat_affinity_main;
  nat_affinity_t *a;

  a = pool_elt_at_index (nam->affinity_pool, kv->value);
  if (a->ref_cnt == 0)
    {
      if (a->expire < vlib_time_now (nam->vlib_main))
	{
	  clib_dlist_remove (nam->list_pool, a->per_service_index);
	  pool_put_index (nam->list_pool, a->per_service_index);
	  pool_put_index (nam->affinity_pool, kv->value);
	  if (clib_bihash_add_del_16_8 (&nam->affinity_hash, kv, 0))
	    nat_elog_warn ("affinity key del failed");
	  return 1;
	}
    }

  return 0;
}

int
nat_affinity_create_and_lock (ip4_address_t client_addr,
			      ip4_address_t service_addr, u8 proto,
			      u16 service_port, u8 backend_index,
			      u32 sticky_time,
			      u32 affinity_per_service_list_head_index)
{
  nat_affinity_main_t *nam = &nat_affinity_main;
  clib_bihash_kv_16_8_t kv, value;
  nat_affinity_t *a;
  dlist_elt_t *list_elt;
  int rv = 0;

  make_affinity_kv (&kv, client_addr, service_addr, proto, service_port);
  clib_spinlock_lock_if_init (&nam->affinity_lock);
  if (!clib_bihash_search_16_8 (&nam->affinity_hash, &kv, &value))
    {
      rv = 1;
      nat_elog_notice ("affinity key already exist");
      goto unlock;
    }

  pool_get (nam->affinity_pool, a);
  kv.value = a - nam->affinity_pool;
  rv =
    clib_bihash_add_or_overwrite_stale_16_8 (&nam->affinity_hash, &kv,
					     affinity_is_expired_cb, NULL);
  if (rv)
    {
      nat_elog_notice ("affinity key add failed");
      pool_put (nam->affinity_pool, a);
      goto unlock;
    }

  pool_get (nam->list_pool, list_elt);
  clib_dlist_init (nam->list_pool, list_elt - nam->list_pool);
  list_elt->value = a - nam->affinity_pool;
  a->per_service_index = list_elt - nam->list_pool;
  a->backend_index = backend_index;
  a->ref_cnt = 1;
  a->sticky_time = sticky_time;
  a->key.as_u64[0] = kv.key[0];
  a->key.as_u64[1] = kv.key[1];
  clib_dlist_addtail (nam->list_pool, affinity_per_service_list_head_index,
		      a->per_service_index);

unlock:
  clib_spinlock_unlock_if_init (&nam->affinity_lock);
  return rv;
}

void
nat_affinity_unlock (ip4_address_t client_addr, ip4_address_t service_addr,
		     u8 proto, u16 service_port)
{
  nat_affinity_main_t *nam = &nat_affinity_main;
  clib_bihash_kv_16_8_t kv, value;
  nat_affinity_t *a;

  make_affinity_kv (&kv, client_addr, service_addr, proto, service_port);
  clib_spinlock_lock_if_init (&nam->affinity_lock);
  if (clib_bihash_search_16_8 (&nam->affinity_hash, &kv, &value))
    goto unlock;

  a = pool_elt_at_index (nam->affinity_pool, value.value);
  a->ref_cnt--;
  if (a->ref_cnt == 0)
    a->expire = (u64) a->sticky_time + vlib_time_now (nam->vlib_main);

unlock:
  clib_spinlock_unlock_if_init (&nam->affinity_lock);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
