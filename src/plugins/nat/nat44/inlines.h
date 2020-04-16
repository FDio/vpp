/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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
 * @brief The NAT44 inline functions
 */

#ifndef included_nat44_inlines_h__
#define included_nat44_inlines_h__

#include <vnet/fib/ip4_fib.h>
#include <nat/nat.h>

static_always_inline u8
nat44_maximum_sessions_exceeded (snat_main_t * sm, u32 thread_index)
{
  if (pool_elts (sm->per_thread_data[thread_index].sessions) >=
      sm->max_translations)
    return 1;
  return 0;
}

static_always_inline f64
nat44_minimal_timeout (snat_main_t * sm)
{
  f64 min_timeout;

  min_timeout = clib_min (sm->udp_timeout, sm->icmp_timeout);
  min_timeout = clib_min (min_timeout, sm->icmp_timeout);
  min_timeout = clib_min (min_timeout, sm->tcp_transitory_timeout);
  min_timeout = clib_min (min_timeout, sm->tcp_established_timeout);

  return min_timeout;
}

static_always_inline snat_session_t *
nat44_session_reuse_old (snat_main_t * sm, snat_user_t * u,
			 snat_session_t * s, u32 thread_index, f64 now)
{
  nat44_free_session_data (sm, s, thread_index, 0);
  if (snat_is_session_static (s))
    u->nstaticsessions--;
  else
    u->nsessions--;
  s->flags = 0;
  s->total_bytes = 0;
  s->total_pkts = 0;
  s->state = 0;
  s->ext_host_addr.as_u32 = 0;
  s->ext_host_port = 0;
  s->ext_host_nat_addr.as_u32 = 0;
  s->ext_host_nat_port = 0;
  s->tcp_close_timestamp = 0;
  s->ha_last_refreshed = now;
  return s;
}


static_always_inline snat_session_t *
nat44_session_alloc_new (snat_main_per_thread_data_t * tsm, snat_user_t * u,
			 f64 now)
{
  snat_session_t *s;
  dlist_elt_t *per_user_translation_list_elt;

  pool_get (tsm->sessions, s);
  clib_memset (s, 0, sizeof (*s));
  /* Create list elts */
  pool_get (tsm->list_pool, per_user_translation_list_elt);
  clib_dlist_init (tsm->list_pool,
		   per_user_translation_list_elt - tsm->list_pool);

  per_user_translation_list_elt->value = s - tsm->sessions;
  s->per_user_index = per_user_translation_list_elt - tsm->list_pool;
  s->per_user_list_head_index = u->sessions_per_user_list_head_index;

  clib_dlist_addtail (tsm->list_pool,
		      s->per_user_list_head_index,
		      per_user_translation_list_elt - tsm->list_pool);

  dlist_elt_t *lru_list_elt;
  pool_get (tsm->global_lru_pool, lru_list_elt);
  s->global_lru_index = lru_list_elt - tsm->global_lru_pool;
  clib_dlist_addtail (tsm->global_lru_pool, tsm->global_lru_head_index,
		      s->global_lru_index);
  lru_list_elt->value = s - tsm->sessions;
  s->last_lru_update = now;

  s->ha_last_refreshed = now;
  return s;
}

static_always_inline void
nat44_user_del_sessions (snat_user_t * u, u32 thread_index)
{
  dlist_elt_t *elt;
  snat_session_t *s;

  snat_main_t *sm = &snat_main;
  snat_main_per_thread_data_t *tsm = &sm->per_thread_data[thread_index];

  // get head
  elt = pool_elt_at_index (tsm->list_pool,
			   u->sessions_per_user_list_head_index);
  // get first element
  elt = pool_elt_at_index (tsm->list_pool, elt->next);

  while (elt->value != ~0)
    {
      s = pool_elt_at_index (tsm->sessions, elt->value);
      elt = pool_elt_at_index (tsm->list_pool, elt->next);

      nat44_free_session_data (sm, s, thread_index, 0);
      // TODO: needs refactoring as in nat44_user_session_cleanup
      nat44_delete_session (sm, s, thread_index);
    }
}

static_always_inline int
nat44_user_del (ip4_address_t * addr, u32 fib_index)
{
  int rv = 1;

  snat_main_t *sm = &snat_main;
  snat_main_per_thread_data_t *tsm;

  snat_user_key_t user_key;
  clib_bihash_kv_8_8_t kv, value;

  user_key.addr.as_u32 = addr->as_u32;
  user_key.fib_index = fib_index;
  kv.key = user_key.as_u64;

  if (sm->num_workers > 1)
    {
      /* *INDENT-OFF* */
      vec_foreach (tsm, sm->per_thread_data)
        {
          if (!clib_bihash_search_8_8 (&tsm->user_hash, &kv, &value))
            {
              nat44_user_del_sessions (
                  pool_elt_at_index (tsm->users, value.value),
                  tsm->thread_index);
              rv = 0;
              break;
            }
        }
      /* *INDENT-ON* */
    }
  else
    {
      tsm = vec_elt_at_index (sm->per_thread_data, sm->num_workers);
      if (!clib_bihash_search_8_8 (&tsm->user_hash, &kv, &value))
	{
	  nat44_user_del_sessions (pool_elt_at_index
				   (tsm->users, value.value),
				   tsm->thread_index);
	  rv = 0;
	}
    }
  return rv;
}

static_always_inline u32
nat44_user_session_cleanup (snat_user_t * u, u32 thread_index, f64 now)
{
  u32 cleared = 0;
  dlist_elt_t *elt;
  snat_session_t *s;
  u64 sess_timeout_time;

  snat_main_t *sm = &snat_main;
  snat_main_per_thread_data_t *tsm = &sm->per_thread_data[thread_index];

  if (now < u->min_session_timeout)
    goto done;
  u->min_session_timeout = now + sm->min_timeout;

  // get head
  elt = pool_elt_at_index (tsm->list_pool,
			   u->sessions_per_user_list_head_index);
  // get first element
  elt = pool_elt_at_index (tsm->list_pool, elt->next);

  while (elt->value != ~0)
    {
      s = pool_elt_at_index (tsm->sessions, elt->value);
      elt = pool_elt_at_index (tsm->list_pool, elt->next);

      sess_timeout_time = s->last_heard +
	(f64) nat44_session_get_timeout (sm, s);

      if (s->tcp_close_timestamp)
	{
	  sess_timeout_time =
	    clib_min (sess_timeout_time, s->tcp_close_timestamp);
	}

      if (now < sess_timeout_time)
	continue;

      // do cleanup of this call (refactor for ED NAT44 only)
      nat44_free_session_data (sm, s, thread_index, 0);

      if (snat_is_session_static (s))
	u->nstaticsessions--;
      else
	u->nsessions--;

      clib_dlist_remove (tsm->list_pool, s->per_user_index);
      pool_put_index (tsm->list_pool, s->per_user_index);
      clib_dlist_remove (tsm->global_lru_pool, s->global_lru_index);
      pool_put_index (tsm->global_lru_pool, s->global_lru_index);
      pool_put (tsm->sessions, s);
      vlib_set_simple_counter (&sm->total_sessions, thread_index, 0,
			       pool_elts (tsm->sessions));

      cleared++;
    }
done:
  return cleared;
}

static_always_inline u32
nat44_users_cleanup (u32 thread_index, f64 now)
{
  snat_main_t *sm = &snat_main;
  snat_main_per_thread_data_t *tsm;

  u32 cleared = 0;

  snat_user_key_t u_key;
  clib_bihash_kv_8_8_t kv;

  snat_user_t *u = 0;
  u32 pool_index;

  tsm = vec_elt_at_index (sm->per_thread_data, thread_index);

  if (now < tsm->min_session_timeout)
    goto done;
  tsm->min_session_timeout = now + sm->min_timeout;
  // consider
  tsm->cleanup_timeout = tsm->min_session_timeout;

  pool_index = ~0;
  do
    {
      pool_index = pool_next_index (tsm->users, pool_index);
      if (pool_index == ~0)
	break;
      u = pool_elt_at_index (tsm->users, pool_index);

      cleared += nat44_user_session_cleanup (u, thread_index, now);

      if (u->nstaticsessions == 0 && u->nsessions == 0)
	{
	  u_key.addr.as_u32 = u->addr.as_u32;
	  u_key.fib_index = u->fib_index;
	  kv.key = u_key.as_u64;

	  // delete user
	  pool_put_index (tsm->list_pool,
			  u->sessions_per_user_list_head_index);
	  pool_put (tsm->users, u);
	  clib_bihash_add_del_8_8 (&tsm->user_hash, &kv, 0);

	  // update total users counter
	  vlib_set_simple_counter (&sm->total_users, thread_index, 0,
				   pool_elts (tsm->users));
	}
    }
  while (1);
  tsm->cleared += cleared;
  tsm->cleanup_runs++;
done:
  return cleared;
}

static_always_inline u32
nat44_out_of_ports_cleanup (u32 thread_index, f64 now)
{
  return nat44_users_cleanup (thread_index, now);
}

static_always_inline u32
nat44_max_translations_per_user_cleanup (snat_user_t * u, u32 thread_index,
					 f64 now)
{
  return nat44_user_session_cleanup (u, thread_index, now);
}

static_always_inline u32
nat44_force_users_cleanup (void)
{
  snat_main_t *sm = &snat_main;
  snat_main_per_thread_data_t *tsm;

  f64 now = vlib_time_now (vlib_get_main ());
  u32 cleared = 0;

  if (sm->num_workers > 1)
    {
      /* *INDENT-OFF* */
      vec_foreach (tsm, sm->per_thread_data)
        {
          cleared += nat44_users_cleanup (tsm->thread_index, now);
        }
      /* *INDENT-ON* */
    }
  else
    {
      tsm = vec_elt_at_index (sm->per_thread_data, sm->num_workers);
      cleared += nat44_users_cleanup (tsm->thread_index, now);
    }
  return cleared;
}

#endif /* included_nat44_inlines_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
