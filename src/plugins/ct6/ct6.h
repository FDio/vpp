
/*
 * ct6.h - skeleton vpp engine plug-in header file
 *
 * Copyright (c) <current-year> <your-organization>
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
#ifndef __included_ct6_h__
#define __included_ct6_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>
#include <vppinfra/bihash_48_8.h>

#include <vppinfra/hash.h>
#include <vppinfra/error.h>

typedef CLIB_PACKED (struct
{
  union
  {
    struct
    {
      /* out2in */
      ip6_address_t src;
      ip6_address_t dst;
      u16 sport;
      u16 dport;
      u8 proto; /* byte 37 */
    };
    u64 as_u64[6];
  };
}) ct6_session_key_t;

typedef struct
{
  ct6_session_key_t key;
  clib_thread_index_t thread_index;
  u32 next_index;
  u32 prev_index;
  u32 hits;
  f64 expires;
} ct6_session_t;

typedef struct
{
  /* API message ID base */
  u16 msg_id_base;

  /* session lookup table */
  clib_bihash_48_8_t session_hash;
  u8 feature_initialized;

  /* per_thread session pools */
  ct6_session_t **sessions;
  u32 *first_index;
  u32 *last_index;

  /* Config parameters */
  f64 session_timeout_interval;
  uword session_hash_memory;
  u32 session_hash_buckets;
  u32 max_sessions_per_worker;

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
  ethernet_main_t *ethernet_main;
} ct6_main_t;

extern ct6_main_t ct6_main;

extern vlib_node_registration_t ct6_out2in_node;
extern vlib_node_registration_t ct6_in2out_node;

format_function_t format_ct6_session;

ct6_session_t *ct6_create_or_recycle_session (ct6_main_t * cmp,
					      clib_bihash_kv_48_8_t * kvpp,
					      f64 now, u32 my_thread_index,
					      u32 * recyclep, u32 * createp);

static inline void
ct6_lru_remove (ct6_main_t * cmp, ct6_session_t * s0)
{
  ct6_session_t *next_sess, *prev_sess;
  clib_thread_index_t thread_index;
  u32 s0_index;

  thread_index = s0->thread_index;

  s0_index = s0 - cmp->sessions[thread_index];

  /* Deal with list heads */
  if (s0_index == cmp->first_index[thread_index])
    cmp->first_index[thread_index] = s0->next_index;
  if (s0_index == cmp->last_index[thread_index])
    cmp->last_index[thread_index] = s0->prev_index;

  /* Fix next->prev */
  if (s0->next_index != ~0)
    {
      next_sess = pool_elt_at_index (cmp->sessions[thread_index],
				     s0->next_index);
      next_sess->prev_index = s0->prev_index;
    }
  /* Fix prev->next */
  if (s0->prev_index != ~0)
    {
      prev_sess = pool_elt_at_index (cmp->sessions[thread_index],
				     s0->prev_index);
      prev_sess->next_index = s0->next_index;
    }
}

static inline void
ct6_lru_add (ct6_main_t * cmp, ct6_session_t * s0, f64 now)
{
  ct6_session_t *next_sess;
  clib_thread_index_t thread_index;
  u32 s0_index;

  s0->hits++;
  s0->expires = now + cmp->session_timeout_interval;
  thread_index = s0->thread_index;

  s0_index = s0 - cmp->sessions[thread_index];

  /*
   * Re-add at the head of the forward LRU list,
   * tail of the reverse LRU list
   */
  if (cmp->first_index[thread_index] != ~0)
    {
      next_sess = pool_elt_at_index (cmp->sessions[thread_index],
				     cmp->first_index[thread_index]);
      next_sess->prev_index = s0_index;
    }

  s0->prev_index = ~0;

  /* s0 now the new head of the LRU forward list */
  s0->next_index = cmp->first_index[thread_index];
  cmp->first_index[thread_index] = s0_index;

  /* single session case: also the tail of the reverse LRU list */
  if (cmp->last_index[thread_index] == ~0)
    cmp->last_index[thread_index] = s0_index;
}

static inline void
ct6_update_session_hit (ct6_main_t * cmp, ct6_session_t * s0, f64 now)
{
  ct6_lru_remove (cmp, s0);
  ct6_lru_add (cmp, s0, now);
}

#endif /* __included_ct6_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
