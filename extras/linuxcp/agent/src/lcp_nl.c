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

#define _GNU_SOURCE
#include <sched.h>
#include <fcntl.h>

#include <lcp_nl.h>
#include <lcp_ns.h>
#include <lcp_log.h>

#include <netlink/route/rule.h>
#include <netlink/msg.h>
#include <netlink/netlink.h>
#include <netlink/socket.h>
#include <netlink/route/link.h>
#include <netlink/route/route.h>
#include <netlink/route/neighbour.h>
#include <netlink/route/addr.h>

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vppinfra/error.h>

#include <vnet/fib/fib_table.h>

#include <libmnl/libmnl.h>


static struct nl_sock *sk_route;

static nl_vft_t *nl_vfts;

static struct nl_cache *nl_caches[LCP_NL_N_OBJS];

#define FOREACH_VFT(__func, __arg)              \
  {                                             \
    nl_vft_t *__nv;                             \
    vec_foreach(__nv, nl_vfts)                  \
      {                                         \
        if (__nv->__func)                       \
          __nv->__func(__arg);                  \
      }                                         \
    }

void
lcp_nl_register_vft (const nl_vft_t * nv)
{
  vec_add1 (nl_vfts, *nv);
}


static void
nl_route_del (struct rtnl_route *rr, void *arg)
{
  FOREACH_VFT (nvl_rt_route_del, rr);
}

static void
nl_route_add (struct rtnl_route *rr, void *arg)
{
  FOREACH_VFT (nvl_rt_route_add, rr);
}

static void
nl_obj_route_add (struct nl_object *a, void *arg)
{
  nl_route_add ((struct rtnl_route *) a, arg);
}

static void
nl_neigh_del (struct rtnl_neigh *rn, void *arg)
{
  FOREACH_VFT (nvl_rt_neigh_del, rn);
}

static void
nl_neigh_add (struct rtnl_neigh *rn, void *arg)
{
  FOREACH_VFT (nvl_rt_neigh_add, rn);
}

static void
nl_obj_neigh_add (struct nl_object *a, void *arg)
{
  nl_neigh_add ((struct rtnl_neigh *) a, arg);
}

static void
nl_link_addr_del (struct rtnl_addr *rla, void *arg)
{
  FOREACH_VFT (nvl_rt_addr_del, rla);
}

static void
nl_link_addr_add (struct rtnl_addr *rla, void *arg)
{
  FOREACH_VFT (nvl_rt_addr_add, rla);
}

static void
nl_obj_link_addr_add (struct nl_object *a, void *arg)
{
  nl_link_addr_add ((struct rtnl_addr *) a, arg);
}

static void
nl_link_del (struct rtnl_link *rl, void *arg)
{
  FOREACH_VFT (nvl_rt_link_del, rl);
}

static void
nl_link_add (struct rtnl_link *rl, void *arg)
{
  FOREACH_VFT (nvl_rt_link_add, rl);
}

static void
nl_obj_link_add (struct nl_object *o, void *arg)
{
  nl_link_add ((struct rtnl_link *) o, arg);
}

static void
nl_route_dispatch (struct nl_object *obj, void *arg)
{
  switch (nl_object_get_msgtype (obj))
    {
    case RTM_NEWROUTE:
      nl_route_add ((struct rtnl_route *) obj, arg);
      break;
    case RTM_DELROUTE:
      nl_route_del ((struct rtnl_route *) obj, arg);
      break;
    case RTM_NEWNEIGH:
      nl_neigh_add ((struct rtnl_neigh *) obj, arg);
      break;
    case RTM_DELNEIGH:
      nl_neigh_del ((struct rtnl_neigh *) obj, arg);
      break;
    case RTM_NEWADDR:
      nl_link_addr_add ((struct rtnl_addr *) obj, arg);
      break;
    case RTM_DELADDR:
      nl_link_addr_del ((struct rtnl_addr *) obj, arg);
      break;
    case RTM_NEWLINK:
      nl_link_add ((struct rtnl_link *) obj, arg);
      break;
    case RTM_DELLINK:
      nl_link_del ((struct rtnl_link *) obj, arg);
      break;
    default:
      LCP_INFO ("unhandled: %s", nl_object_get_type (obj));
      break;
    }
}

static int
nl_route_cb (struct nl_msg *msg, void *arg)
{
  int err;

  if ((err = nl_msg_parse (msg, nl_route_dispatch, NULL)) < 0)
    LCP_ERROR ("Unable to parse object: %s", nl_geterror (err));

  return 0;
}

int
lcp_nl_read (void)
{
  int err;
  if ((err = nl_recvmsgs_default (sk_route)) < 0)
    LCP_ERROR ("recv: %s", nl_geterror (err));

  return (err);
}

int
lcp_nl_connect (void)
{
  int err;
  int dest_ns_fd, curr_ns_fd;


  /* Allocate a new socket for both routes and acls
   * Notifications do not use sequence numbers, disable sequence number
   * checking.
   * Define a callback function, which will be called for each notification
   * received
   */
  sk_route = nl_socket_alloc ();
  nl_socket_disable_seq_check (sk_route);

  dest_ns_fd = lcp_get_default_ns_fd ();
  if (dest_ns_fd)
    {
      curr_ns_fd = open ("/proc/self/ns/net", O_RDONLY);
      setns (dest_ns_fd, CLONE_NEWNET);
    }

  nl_connect (sk_route, NETLINK_ROUTE);

  if (dest_ns_fd)
    {
      setns (curr_ns_fd, CLONE_NEWNET);
      close (curr_ns_fd);
    }

  /* Subscribe to all the 'routing' notifications on the route socket */
  nl_socket_add_memberships (sk_route,
			     RTNLGRP_LINK,
			     RTNLGRP_IPV6_IFADDR,
			     RTNLGRP_IPV4_IFADDR,
			     RTNLGRP_IPV4_ROUTE,
			     RTNLGRP_IPV6_ROUTE,
			     RTNLGRP_NEIGH, RTNLGRP_NOTIFY,
#ifdef RTNLGRP_MPLS_ROUTE	/* not defined on CentOS/RHEL 7 */
			     RTNLGRP_MPLS_ROUTE,
#endif
			     RTNLGRP_IPV4_RULE, RTNLGRP_IPV6_RULE, 0);

  nl_socket_modify_cb (sk_route, NL_CB_VALID, NL_CB_CUSTOM, nl_route_cb,
		       NULL);


  if ((err = rtnl_link_alloc_cache (sk_route, AF_UNSPEC,
				    &nl_caches[LCP_NL_LINK])) < 0)
    {
      LCP_ERROR ("link cache build fail");
    }
  else
    {
      nl_cache_mngt_provide (nl_caches[LCP_NL_LINK]);
      nl_cache_foreach (nl_caches[LCP_NL_LINK], nl_obj_link_add, NULL);
    }
  if ((err = rtnl_addr_alloc_cache (sk_route, &nl_caches[LCP_NL_ADDR])) < 0)
    {
      LCP_ERROR ("link-address cache build fail: %s", strerror (err));
    }
  else
    {
      nl_cache_mngt_provide (nl_caches[LCP_NL_ADDR]);
      nl_cache_foreach (nl_caches[LCP_NL_ADDR], nl_obj_link_addr_add, NULL);
    }
  if ((err = rtnl_neigh_alloc_cache (sk_route, &nl_caches[LCP_NL_NEIGH])) < 0)
    {
      LCP_ERROR ("neighbour cache build fail");
    }
  else
    {
      nl_cache_mngt_provide (nl_caches[LCP_NL_NEIGH]);
      nl_cache_foreach (nl_caches[LCP_NL_NEIGH], nl_obj_neigh_add, NULL);
    }
  if ((err = rtnl_route_alloc_cache (sk_route, AF_UNSPEC, 0,
				     &nl_caches[LCP_NL_ROUTE])) < 0)
    {
      LCP_ERROR ("route cache build fail");
    }
  else
    {
      nl_cache_mngt_provide (nl_caches[LCP_NL_ROUTE]);
      nl_cache_foreach (nl_caches[LCP_NL_ROUTE], nl_obj_route_add, NULL);
    }

  return (nl_socket_get_fd (sk_route));
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
