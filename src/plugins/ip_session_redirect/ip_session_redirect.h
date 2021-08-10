/* Copyright (c) 2021 Cisco and/or its affiliates.
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
 * limitations under the License. */

#ifndef IP_SESSION_REDIRECT_H_
#define IP_SESSION_REDIRECT_H_

#include <vnet/fib/fib_node.h>

typedef enum
{
  IP_SESSION_REDIRECT_IP4 = 0,
  IP_SESSION_REDIRECT_IP6,
  IP_SESSION_REDIRECT_PUNT4,
  IP_SESSION_REDIRECT_PUNT6,
#define IP_SESSION_REDIRECT_MAX IP_SESSION_REDIRECT_PUNT6
} ip_session_redirect_type_t;

typedef struct
{
  fib_node_t node; /* linkage into the FIB graph */

  fib_forward_chain_type_t payload_type;
  fib_node_index_t pl;
  u32 sibling;
  u32 parent_node_index;

  const u8 *match;
  u32 sw_if_index;
  u32 table_index;
  ip_session_redirect_type_t type;

  dpo_id_t dpo; /* forwarding dpo */
} ip_session_redirect_t;

typedef struct
{
  ip_session_redirect_t *pool;
  fib_node_type_t fib_node_type;
  int refcount[IP_SESSION_REDIRECT_MAX + 1];
  u16 msg_id_base;
} ip_session_redirect_main_t;

extern ip_session_redirect_main_t ip_session_redirect_main;

int ip_session_redirect_add (vlib_main_t *vm, const u32 sw_if_index,
			     const u32 table_index, const u8 *match,
			     const fib_route_path_t *rpaths, int is_punt);
int ip_session_redirect_del (vlib_main_t *vm, const u32 table_index,
			     const u8 *match);

#endif /* IP_SESSION_REDIRECT_H_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
