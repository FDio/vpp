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

static_always_inline u8
nat44_ed_maximum_sessions_exceeded (snat_main_t * sm,
				    u32 fib_index, u32 thread_index)
{
  u32 translations;
  translations = pool_elts (sm->per_thread_data[thread_index].sessions);
  if (vec_len (sm->max_translations_per_fib) <= fib_index)
    fib_index = 0;
  return translations >= sm->max_translations_per_fib[fib_index];
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
  s->tcp_closed_timestamp = 0;
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

  if (sm->deterministic || sm->endpoint_dependent)
    return rv;

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

#endif /* included_nat44_inlines_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
