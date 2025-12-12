/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021-2022 Cisco and/or its affiliates.
 */

#ifndef IP_SESSION_REDIRECT_H_
#define IP_SESSION_REDIRECT_H_

#include <vnet/fib/fib_node.h>

typedef struct
{
  u8 *match_and_table_index;
  dpo_id_t dpo;	   /* forwarding dpo */
  fib_node_t node; /* linkage into the FIB graph */
  fib_node_index_t pl;
  u32 sibling;
  u32 parent_node_index;
  u32 opaque_index;
  u32 table_index;
  fib_forward_chain_type_t payload_type;
  u8 is_punt : 1;
  u8 is_ip6 : 1;
} ip_session_redirect_t;

typedef struct
{
  ip_session_redirect_t *pool;
  u32 *session_by_match_and_table_index;
  fib_node_type_t fib_node_type;
} ip_session_redirect_main_t;

extern ip_session_redirect_main_t ip_session_redirect_main;

int ip_session_redirect_add (vlib_main_t *vm, u32 table_index,
			     u32 opaque_index, dpo_proto_t proto, int is_punt,
			     const u8 *match, const fib_route_path_t *rpaths);
int ip_session_redirect_del (vlib_main_t *vm, u32 table_index,
			     const u8 *match);

#endif /* IP_SESSION_REDIRECT_H_ */
