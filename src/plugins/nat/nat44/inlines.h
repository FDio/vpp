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

      nat_free_session_data (sm, s, thread_index, 0);
      // needs refactoring as in nat44_user_session_cleanup
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
nat44_user_session_cleanup_v2 (snat_user_t * u, u32 thread_index, f64 now,
			       snat_session_t ** out)
{
  u32 cleared = 0;
  dlist_elt_t *elt;
  snat_session_t *s, *sl = 0;
  u64 sess_timeout_time, idle_timeout_time;

  snat_main_t *sm = &snat_main;
  snat_main_per_thread_data_t *tsm = &sm->per_thread_data[thread_index];

  *out = 0;

  if (now < u->min_session_timeout && now < u->min_idle_timeout)
    goto done;

  u->min_session_timeout = ~0;
  u->min_idle_timeout = ~0;

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

      if (now < sess_timeout_time)
	{
	  idle_timeout_time = s->last_heard + sm->idle_timeout;

	  // pickup first idle session
	  if (PREDICT_FALSE (!sl && (now >= idle_timeout_time)))
	    {
	      sl = s;
	      break;
	    }

	  u->min_idle_timeout =
	    clib_min (idle_timeout_time, u->min_idle_timeout);
	  u->min_session_timeout =
	    clib_min (sess_timeout_time, u->min_session_timeout);
	  tsm->min_session_timeout =
	    clib_min (sess_timeout_time, tsm->min_session_timeout);
	  continue;
	}

      // do cleanup of this call (refactor for ED NAT44 only)
      nat_free_session_data (sm, s, thread_index, 0);

      clib_dlist_remove (tsm->list_pool, s->per_user_index);
      pool_put_index (tsm->list_pool, s->per_user_index);
      pool_put (tsm->sessions, s);
      vlib_set_simple_counter (&sm->total_sessions, thread_index, 0,
			       pool_elts (tsm->sessions));

      if (snat_is_session_static (s))
	u->nstaticsessions--;
      else
	u->nsessions--;

      cleared++;
    }
  if (~0 == u->min_session_timeout)
    u->min_session_timeout = 0;
  if (~0 == u->min_idle_timeout)
    u->min_idle_timeout = 0;

  // session not yet expired but idle time out reached
  if (sl)
    *out = sl;
done:
  return cleared;
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
  u->min_session_timeout = ~0;

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

      if (now < sess_timeout_time)
	{
	  u->min_session_timeout =
	    clib_min (sess_timeout_time, u->min_session_timeout);
	  tsm->min_session_timeout =
	    clib_min (sess_timeout_time, tsm->min_session_timeout);
	  continue;
	}

      // do cleanup of this call (refactor for ED NAT44 only)
      nat_free_session_data (sm, s, thread_index, 0);

      clib_dlist_remove (tsm->list_pool, s->per_user_index);
      pool_put_index (tsm->list_pool, s->per_user_index);
      pool_put (tsm->sessions, s);
      vlib_set_simple_counter (&sm->total_sessions, thread_index, 0,
			       pool_elts (tsm->sessions));

      if (snat_is_session_static (s))
	u->nstaticsessions--;
      else
	u->nsessions--;

      cleared++;
    }
  if (~0 == u->min_session_timeout)
    u->min_session_timeout = 0;
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
  u32 pool_index = 0;

  tsm = vec_elt_at_index (sm->per_thread_data, thread_index);

  if (now < tsm->min_session_timeout)
    goto done;
  tsm->min_session_timeout = ~0;

  tsm->cleanup_runs++;

  do
    {
      if (pool_index >= pool_elts (tsm->users))
	break;

      // pool_is_free
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
	  continue;
	}
      pool_index++;
    }
  while (1);

  if (~0 == tsm->min_session_timeout)
    tsm->min_session_timeout = 0;

  tsm->cleanup_timeout = tsm->min_session_timeout;
  tsm->cleared += cleared;

done:
  return cleared;
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
