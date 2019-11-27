/*
 * Copyright (c) 2019 Cisco and/or its affiliates.
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
#ifndef __included_nat44_inlines_h__
#define __included_nat44_inlines_h__

#include <vnet/fib/ip4_fib.h>
#include <nat/nat.h>

static_always_inline void
nat44_session_cleanup (snat_session_t * s, u32 thread_index)
{
  snat_main_t *sm = &snat_main;

  nat_free_session_data (sm, s, thread_index, 0);
  nat44_delete_session (sm, s, thread_index);
}

static_always_inline void
nat44_user_try_cleanup (snat_user_t * u, u32 thread_index, f64 now)
{
  dlist_elt_t *elt;
  snat_session_t *s;
  u64 sess_timeout_time;

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

      sess_timeout_time = s->last_heard +
	(f64) nat44_session_get_timeout (sm, s);

      if (now < sess_timeout_time)
	continue;

      nat44_session_cleanup (s, thread_index);
    }
}

static_always_inline void
nat44_session_try_cleanup (ip4_address_t * addr,
			   u32 fib_index, u32 thread_index, f64 now)
{
  snat_user_t *u = 0;
  snat_user_key_t user_key;
  clib_bihash_kv_8_8_t kv, value;

  snat_main_t *sm = &snat_main;
  snat_main_per_thread_data_t *tsm = &sm->per_thread_data[thread_index];

  user_key.addr.as_u32 = addr->as_u32;
  user_key.fib_index = fib_index;
  kv.key = user_key.as_u64;

  // lookup user for this traffic
  if (PREDICT_FALSE (clib_bihash_search_8_8 (&tsm->user_hash, &kv, &value)))
    {
      // there is still place and a new user can be created
      if (PREDICT_TRUE (pool_elts (tsm->sessions) < sm->max_translations))
	return;

      // there is no place so we try to cleanup all users in this thread
      /* *INDENT-OFF* */
      pool_foreach (u, tsm->users,
      ({
        nat44_user_try_cleanup (u, thread_index, now);
      }));
      /* *INDENT-ON* */
      return;
    }

  // each time user creates a new session we try to cleanup expired sessions
  nat44_user_try_cleanup (pool_elt_at_index (tsm->users, value.value),
			  thread_index, now);
}

#endif /* __included_nat44_inlines_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
