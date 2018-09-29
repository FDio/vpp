/*
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

#include <netlink/mapper.h>
#include <netlink/netns.h>

#include <vnet/ip/ip.h>
#include <vnet/ip/lookup.h>
#include <vnet/fib/fib.h>

typedef struct {
  int linux_ifindex;
  u32 sw_if_index;
} mapper_map_t;

typedef struct {
  char nsname[RTNL_NETNS_NAMELEN + 1];
  mapper_map_t *mappings;
  u32 netns_handle; //Used to receive notifications
  u32 v4fib_index; //One fib index for the namespace
  u32 v6fib_index;
} mapper_ns_t;

typedef struct {
  mapper_ns_t *namespaces;
} mapper_main_t;

static mapper_main_t mapper_main;

mapper_map_t *mapper_get_by_ifindex(mapper_ns_t *ns, int ifindex)
{
  mapper_map_t *map;
  pool_foreach(map, ns->mappings, {
      if (ifindex == map->linux_ifindex)
        return map;
  });
  return NULL;
}

int mapper_add_del_route(mapper_ns_t *ns, ns_route_t *route, int del)
{
  mapper_main_t *mm = &mapper_main;
  clib_warning("NS %d %s %U", ns - mm->namespaces, del?"del":"add", format_ns_route, route);

  mapper_map_t *map = mapper_get_by_ifindex(ns, route->oif);
  if (!map)
    return 0;

  if (route->rtm.rtm_family == AF_INET6) {

    //Filter-out multicast
    if (route->rtm.rtm_dst_len >= 8 && route->dst[0] == 0xff)
      return 0;

    fib_prefix_t prefix;
    ip46_address_t nh;

    memset (&prefix, 0, sizeof (prefix));
    prefix.fp_len = route->rtm.rtm_dst_len;
    prefix.fp_proto = FIB_PROTOCOL_IP6;
    clib_memcpy (&prefix.fp_addr.ip6, route->dst, sizeof (prefix.fp_addr.ip6));

    memset (&nh, 0, sizeof (nh));
    clib_memcpy (&nh.ip6, route->gateway, sizeof (nh.ip6));

    fib_table_entry_path_add (ns->v6fib_index, &prefix, FIB_SOURCE_API,
                              FIB_ENTRY_FLAG_NONE, prefix.fp_proto,
                              &nh, map->sw_if_index, ns->v6fib_index,
                              0 /* weight */,
                              (fib_mpls_label_t *) MPLS_LABEL_INVALID,
                              FIB_ROUTE_PATH_FLAG_NONE);
  } else {
    fib_prefix_t prefix;
    ip46_address_t nh;

    memset (&prefix, 0, sizeof (prefix));
    prefix.fp_len = route->rtm.rtm_dst_len;
    prefix.fp_proto = FIB_PROTOCOL_IP4;
    clib_memcpy (&prefix.fp_addr.ip4, route->dst, sizeof (prefix.fp_addr.ip4));

    memset (&nh, 0, sizeof (nh));
    clib_memcpy (&nh.ip4, route->gateway, sizeof (nh.ip4));

    fib_table_entry_path_add (ns->v4fib_index, &prefix, FIB_SOURCE_API,
                              FIB_ENTRY_FLAG_NONE, prefix.fp_proto,
                              &nh, map->sw_if_index, ns->v4fib_index,
                              0 /* weight */,
                              (fib_mpls_label_t *) MPLS_LABEL_INVALID,
                              FIB_ROUTE_PATH_FLAG_NONE);
  }

  return 0;
}

static void
mapper_netns_notify_cb(void *obj, netns_type_t type,
                       u32 flags, uword opaque)
{
  mapper_main_t *mm = &mapper_main;
  mapper_ns_t *ns = &mm->namespaces[(u32) opaque];
  ASSERT(!pool_is_free_index(mm->namespaces, (u32) opaque));
  if (type != NETNS_TYPE_ROUTE)
    return; //For now...

  ns_route_t *route = obj;
  if (flags & NETNS_F_DEL) {
    mapper_add_del_route(ns, route, 1);
  } else if (flags & NETNS_F_ADD) {
    mapper_add_del_route(ns, route, 0);
  }
}

void
mapper_delmap(mapper_ns_t*ns, mapper_map_t *map)
{
  ns_route_t *route;
  netns_t *netns = netns_getns(ns->netns_handle);
  pool_foreach(route, netns->routes, {
      if (route->oif == map->linux_ifindex)
        mapper_add_del_route(ns, route, 1);
  });
  pool_put(ns->mappings, map);
}

mapper_map_t *
mapper_getmap(mapper_ns_t*ns, u32 sw_if_index,
              int linux_ifindex, int create)
{
  mapper_map_t *map;
  pool_foreach(map, ns->mappings, {
      if (linux_ifindex == map->linux_ifindex) {
        if (sw_if_index != map->sw_if_index)
          return NULL; //Cannot have multiple mapping with the same ifindex
        else
          return map;
      }
  });

  if (!create)
    return NULL;

  pool_get(ns->mappings, map);
  map->linux_ifindex = linux_ifindex;
  map->sw_if_index = sw_if_index;
  ip6_main.fib_index_by_sw_if_index[sw_if_index] = ns->v6fib_index;
  ip4_main.fib_index_by_sw_if_index[sw_if_index] = ns->v4fib_index;

  //Load available routes
  ns_route_t *route;
  netns_t *netns = netns_getns(ns->netns_handle);
  pool_foreach(route, netns->routes, {
      if (route->oif == map->linux_ifindex)
        mapper_add_del_route(ns, route, 0);
  });
  return map;
}

u32
mapper_get_ns(char *nsname)
{
  mapper_main_t *mm = &mapper_main;
  mapper_ns_t *ns;
  pool_foreach(ns, mm->namespaces, {
      if (!strcmp(nsname, ns->nsname))
        return ns - mm->namespaces;
  });
  return ~0;
}

int
mapper_add_del(u32 nsindex, int linux_ifindex,
               u32 sw_if_index, int del)
{
  mapper_main_t *mm = &mapper_main;
  //ip6_main_t *im6 = &ip6_main;
  mapper_ns_t *ns = &mm->namespaces[nsindex];
  mapper_map_t *map;
  //vnet_sw_interface_t *iface = vnet_get_sw_interface(vnet_get_main(), sw_if_index);

  if (pool_is_free(mm->namespaces, ns))
    return -1;

  /*if (!del) {
    if ((iface->flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) &&
        im6->fib_index_by_sw_if_index[sw_if_index] != ~0) {
      //A custom fib index will be used...
      clib_warning("Cannot add interface with a custom fib index (current is %d)",
                   im6->fib_index_by_sw_if_index[sw_if_index]);
      return -1;
    }
  }*/

  if (!(map = mapper_getmap(ns, sw_if_index, linux_ifindex, !del)))
    return -1;

  if (del)
    mapper_delmap(ns, map);

  return 0;
}

int
mapper_add_ns(char *nsname, u32 v4fib_index, u32 v6fib_index, u32 *nsindex)
{
  mapper_main_t *mm = &mapper_main;
  mapper_ns_t *ns;
  if (mapper_get_ns(nsname) != ~0)
    return -1; //Already exists

  pool_get(mm->namespaces, ns);
  strcpy(ns->nsname, nsname);
  ns->v4fib_index = v4fib_index;
  ns->v6fib_index = v6fib_index;
  ns->mappings = 0;

  netns_sub_t sub;
  sub.notify = mapper_netns_notify_cb;
  sub.opaque = (uword)(ns - mm->namespaces);
  if ((ns->netns_handle = netns_open(ns->nsname, &sub)) == ~0) {
    pool_put(mm->namespaces, ns);
    return -1;
  }
  *nsindex = ns - mm->namespaces;
  return 0;
}

int
mapper_del_ns(u32 nsindex)
{
  mapper_main_t *mm = &mapper_main;
  mapper_ns_t *ns = &mm->namespaces[nsindex];
  if (pool_is_free(mm->namespaces, ns))
    return -1;

  //Remove all existing mappings
  int i, *indexes = 0;
  pool_foreach_index(i, ns->mappings, {
    vec_add1(indexes, i);
  });
  vec_foreach_index(i, indexes) {
    mapper_delmap(ns, &ns->mappings[indexes[i]]);
  }
  vec_free(indexes);

  netns_close(ns->netns_handle);
  pool_put(mm->namespaces, ns);
  return 0;
}

clib_error_t *
mapper_init (vlib_main_t * vm)
{
  mapper_main_t *mm = &mapper_main;
  mm->namespaces = 0;
  return 0;
}

VLIB_INIT_FUNCTION (mapper_init);
