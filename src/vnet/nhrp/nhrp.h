/*
 * nhrp.h: next-hop resolution
 *
 * Copyright (c) 2016 Cisco and/or its affiliates.
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

#ifndef __NHRP_H__
#define __NHRP_H__

#include <vnet/ip/ip.h>

typedef struct nhrp_key_t_
{
  ip46_address_t nk_peer;
  u32 nk_sw_if_index;
} nhrp_key_t;

typedef struct nhrp_entry_t_
{
  nhrp_key_t *ne_key;
  fib_prefix_t ne_nh;
  u32 ne_fib_index;
} nhrp_entry_t;

extern u8 *format_nhrp_entry (u8 * s, va_list * args);

extern int nhrp_entry_add (u32 sw_if_index,
			   const ip46_address_t * peer,
			   u32 nh_table_id, const ip46_address_t * nh);

extern int nhrp_entry_del (u32 sw_if_index, const ip46_address_t * peer);

extern nhrp_entry_t *nhrp_entry_find (u32 sw_if_index,
				      const ip46_address_t * peer);
extern nhrp_entry_t *nhrp_entry_get (index_t nei);

extern void nhrp_entry_adj_stack (const nhrp_entry_t * ne, adj_index_t ai);

typedef walk_rc_t (*nhrp_walk_cb_t) (index_t nei, void *ctx);

extern void nhrp_walk (nhrp_walk_cb_t fn, void *ctx);

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
