/*
 * Copyright (c) 2019 Cisco and/or its affiliates.
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

#include <vlib/vlib.h>

#include <netlink/route/link.h>
#include <netlink/route/route.h>
#include <netlink/route/neighbour.h>
#include <netlink/route/addr.h>

typedef void (*nl_rt_link_cb_t) (struct rtnl_link * rl);
typedef void (*nl_rt_addr_cb_t) (struct rtnl_addr * ra);
typedef void (*nl_rt_neigh_cb_t) (struct rtnl_neigh * rr);
typedef void (*nl_rt_route_cb_t) (struct rtnl_route * rn);

#define NL_RT_COMMON 		\
  uword is_mp_safe

typedef struct nl_rt_link_t_
{
  NL_RT_COMMON;

  nl_rt_link_cb_t cb;
} nl_rt_link_t;

typedef struct nl_rt_addr_t_
{
  NL_RT_COMMON;

  nl_rt_addr_cb_t cb;
} nl_rt_addr_t;

typedef struct nl_rt_neigh_t_
{
  NL_RT_COMMON;

  nl_rt_neigh_cb_t cb;
} nl_rt_neigh_t;

typedef struct nl_rt_route_t_
{
  NL_RT_COMMON;

  nl_rt_route_cb_t cb;
} nl_rt_route_t;

#undef NL_RT_COMMON

typedef struct nl_vft_t_
{
  nl_rt_link_t nvl_rt_link_add;
  nl_rt_link_t nvl_rt_link_del;
  nl_rt_addr_t nvl_rt_addr_add;
  nl_rt_addr_t nvl_rt_addr_del;
  nl_rt_neigh_t nvl_rt_neigh_add;
  nl_rt_neigh_t nvl_rt_neigh_del;
  nl_rt_route_t nvl_rt_route_add;
  nl_rt_route_t nvl_rt_route_del;
} nl_vft_t;

extern void nl_register_vft (const nl_vft_t * nv);


typedef enum lcp_nl_obj_t_
{
  LCP_NL_LINK,
  LCP_NL_ADDR,
  LCP_NL_NEIGH,
  LCP_NL_ROUTE,
} lcp_nl_obj_t;

#define LCP_NL_N_OBJS (LCP_NL_ROUTE+1)

extern struct nl_cache *lcp_nl_get_cache (lcp_nl_obj_t t);
extern int lcp_nl_drain_messages (void);


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
