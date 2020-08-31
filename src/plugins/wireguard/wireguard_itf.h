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
#include <wireguard/wireguard_peer.h>

typedef struct wg_itf_t_
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
} wg_itf_t;


int wg_itf_create (u32 user_instance,
		   const u8 private_key_64[NOISE_KEY_LEN_BASE64],
		   u16 port, const ip_address_t * src_ip, u32 * sw_if_indexp);
int wg_itf_delete (u32 sw_if_index);
wg_itf_t *wg_itf_find_by_sw_if_index (u32 sw_if_index);

wg_itf_t *wg_itf_get (index_t wgi);
u8 *format_wg_itf (u8 * s, va_list * va);

typedef walk_rc_t (*wg_itf_walk_cb_t) (index_t wgi, void *data);
void wg_itf_walk (wg_itf_walk_cb_t fn, void *data);

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
