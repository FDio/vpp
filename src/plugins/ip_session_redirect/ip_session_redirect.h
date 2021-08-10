/*
 * Copyright (c) 2021 Cisco and/or its affiliates.
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

#ifndef IP_SESSION_REDIRECT_H_
#define IP_SESSION_REDIRECT_H_

#include <vnet/fib/fib_node.h>

typedef struct
{
  fib_node_t node; /* linkage into the FIB graph */

  fib_forward_chain_type_t payload_type;
  fib_node_index_t pl;
  u32 sibling;
  u32 table_index;
  const u8 *match;

  dpo_id_t dpo; /* forwarding dpo */
} ip_session_redirect_t;

typedef struct
{
  ip_session_redirect_t *pool;
  fib_node_type_t fib_node_type;
  u16 msg_id_base;
} ip_session_redirect_main_t;

extern ip_session_redirect_main_t ip_session_redirect_main;

u32 ip_session_redirect_add (const u32 table_index, const u8 *match,
			     const fib_route_path_t *rpaths);
void ip_session_redirect_del (u32 index);

void ip_session_redirect_punt_add_del (vlib_main_t *vm, u32 sw_if_index,
				       u32 table_index, int is_add,
				       int is_ip4);

#endif /* IP_SESSION_REDIRECT_H_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
