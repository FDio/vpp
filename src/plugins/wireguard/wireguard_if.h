/*
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
  noise_local_t local;
  cookie_checker_t cookie_checker;
  u16 port;

  wg_index_table_t index_table;

  /* Source IP address for originated packets */
  ip_address_t src_ip;

  /* hash table of peers on this link */
  uword *peers;
} wg_if_t;


int wg_if_create (u32 user_instance,
		  const u8 private_key_64[NOISE_PUBLIC_KEY_LEN],
		  u16 port, const ip_address_t * src_ip, u32 * sw_if_indexp);
int wg_if_delete (u32 sw_if_index);
index_t wg_if_find_by_sw_if_index (u32 sw_if_index);

u8 *format_wg_if (u8 * s, va_list * va);

typedef walk_rc_t (*wg_if_walk_cb_t) (index_t wgi, void *data);
void wg_if_walk (wg_if_walk_cb_t fn, void *data);

typedef walk_rc_t (*wg_if_peer_walk_cb_t) (wg_if_t * wgi, index_t peeri,
					   void *data);
void wg_if_peer_walk (wg_if_t * wgi, wg_if_peer_walk_cb_t fn, void *data);

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

extern index_t *wg_if_index_by_port;

static_always_inline wg_if_t *
wg_if_get_by_port (u16 port)
{
  if (vec_len (wg_if_index_by_port) < port)
    return (NULL);
  if (INDEX_INVALID == wg_if_index_by_port[port])
    return (NULL);
  return (wg_if_get (wg_if_index_by_port[port]));
}


#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
