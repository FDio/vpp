/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
#ifndef __included_l2_xcrw_h__
#define __included_l2_xcrw_h__

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vppinfra/error.h>
#include <vnet/ip/ip.h>
#include <vnet/l2/l2_input.h>
#include <vnet/l2/l2_output.h>
#include <vnet/api_errno.h>
#include <vnet/ethernet/ethernet.h>

typedef struct
{
  /*
   * Let: rewrite_header.sw_if_index = tx_fib_index or ~0.
   *      rewrite_header.next_index = L2_XCRW_NEXT_XXX
   */
  vnet_declare_rewrite (VLIB_BUFFER_PRE_DATA_SIZE);
} l2_xcrw_adjacency_t;

typedef struct
{
  /* L2 interface */
  u32 l2_sw_if_index;

  /* Tunnel interface */
  u32 tunnel_sw_if_index;	/* This field remains set in freed pool elts */

} l2_xcrw_tunnel_t;

typedef struct
{
  u32 cached_next_index;

  /* Vector of cross-connect rewrites */
  l2_xcrw_adjacency_t *adj_by_sw_if_index;

  /* Pool of xcrw tunnels */
  l2_xcrw_tunnel_t *tunnels;

  /* Tunnel index by tunnel sw_if_index */
  uword *tunnel_index_by_l2_sw_if_index;

  /* convenience variables */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
} l2_xcrw_main_t;

typedef enum
{
  L2_XCRW_NEXT_DROP,
  L2_XCRW_N_NEXT,
} l2_xcrw_next_t;

#define foreach_l2_xcrw_error                   \
_(DROP, "Packets dropped")                      \
_(FWD, "Packets forwarded")

typedef enum
{
#define _(sym,str) L2_XCRW_ERROR_##sym,
  foreach_l2_xcrw_error
#undef _
    L2_XCRW_N_ERROR,
} l2_xcrw_error_t;

#endif /* __included_l2_xcrw_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
