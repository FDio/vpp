/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
 * Copyright (c) 2020 Doc.ai and/or its affiliates.
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

#ifndef __WG_ITF_H__
#define __WG_ITF_H__

#include <wireguard/wireguard_index_table.h>
#include <wireguard/wireguard_messages.h>

typedef struct wg_if_t_
{
  int user_instance;
  u32 sw_if_index;

  // Interface params
  /* noise_local_pool elt index */
  u32 local_idx;
  cookie_checker_t cookie_checker;
  u16 port;

  /* Source IP address for originated packets */
  ip_address_t src_ip;

  /* hash table of peers on this link */
  uword *peers;

  /* Under load params */
  f64 handshake_counting_end;
  u32 handshake_num;
} wg_if_t;


int wg_if_create (u32 user_instance,
		  const u8 private_key_64[NOISE_PUBLIC_KEY_LEN],
		  u16 port, const ip_address_t * src_ip, u32 * sw_if_indexp);
int wg_if_delete (u32 sw_if_index);
index_t wg_if_find_by_sw_if_index (u32 sw_if_index);

u8 *format_wg_if (u8 * s, va_list * va);

typedef walk_rc_t (*wg_if_walk_cb_t) (index_t wgi, void *data);
void wg_if_walk (wg_if_walk_cb_t fn, void *data);

typedef walk_rc_t (*wg_if_peer_walk_cb_t) (index_t peeri, void *data);
index_t wg_if_peer_walk (wg_if_t * wgi, wg_if_peer_walk_cb_t fn, void *data);

void wg_if_peer_add (wg_if_t * wgi, index_t peeri);
void wg_if_peer_remove (wg_if_t * wgi, index_t peeri);

/**
 * Data-plane exposed functions
 */
extern wg_if_t *wg_if_pool;

static_always_inline wg_if_t *
wg_if_get (index_t wgii)
{
  if (INDEX_INVALID == wgii)
    return (NULL);
  return (pool_elt_at_index (wg_if_pool, wgii));
}

extern index_t **wg_if_indexes_by_port;

static_always_inline index_t *
wg_if_indexes_get_by_port (u16 port)
{
  if (vec_len (wg_if_indexes_by_port) == 0)
    return (NULL);
  if (vec_len (wg_if_indexes_by_port[port]) == 0)
    return (NULL);
  return (wg_if_indexes_by_port[port]);
}

#define HANDSHAKE_COUNTING_INTERVAL		0.5
#define UNDER_LOAD_INTERVAL			1.0
#define HANDSHAKE_NUM_PER_PEER_UNTIL_UNDER_LOAD 40

static_always_inline bool
wg_if_is_under_load (vlib_main_t *vm, wg_if_t *wgi, u32 inflight,
		     f64 max_handshake_cookie)
{
  static f64 wg_under_load_end;
  static f64 inflight_handshake_counting_end;
  f64 now = vlib_time_now (vm);
  u32 num_until_under_load =
    hash_elts (wgi->peers) * HANDSHAKE_NUM_PER_PEER_UNTIL_UNDER_LOAD;

  if (wgi->handshake_counting_end < now)
    {
      wgi->handshake_counting_end = now + HANDSHAKE_COUNTING_INTERVAL;
      wgi->handshake_num = 0;
    }

  if (inflight_handshake_counting_end < now)
    {
      /* count REKEY_TIMEOUT time - because want to finished all handshake
       * process before each REKEY_TIMEOUT time
       */
      inflight_handshake_counting_end = now + REKEY_TIMEOUT;
    }
  wgi->handshake_num++;

  f64 diff = inflight_handshake_counting_end - now;

  /* check if vpp will be able to do handshake process before each
   * REKEY_TIMEOUT time, if not then under load state is activate
   */
  if ((wgi->handshake_num >= num_until_under_load) ||
      ((f64) inflight - (max_handshake_cookie * diff) > 40))
    {
      wg_under_load_end = now + UNDER_LOAD_INTERVAL;
      return true;
    }

  if (wg_under_load_end > now)
    {
      return true;
    }

  return false;
}

static_always_inline void
wg_if_dec_handshake_num (wg_if_t *wgi)
{
  wgi->handshake_num--;
}

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
