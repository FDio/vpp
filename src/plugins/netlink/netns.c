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

#include <netlink/netns.h>

#include <vnet/ip/format.h>
#include <vnet/ethernet/ethernet.h>

#include <stddef.h>

/* Enable some RTA values debug */
//#define RTNL_CHECK

#define is_nonzero(x)                           \
  ({                                            \
    u8 __is_zero_zero[sizeof(x)] = {};          \
    memcmp(__is_zero_zero, &x, sizeof(x));      \
  })

typedef struct {
  u8 type;      //Attribute identifier
  u8 unique;    //Part of the values uniquely identifying an entry
  u16 offset;   //Offset where stored in struct
  u16 size;     //Length of the attribute
} rtnl_mapping_t;

#define ns_foreach_ifla                         \
  _(IFLA_ADDRESS, hwaddr)                       \
  _(IFLA_BROADCAST, broadcast)                  \
  _(IFLA_IFNAME, ifname)                        \
  _(IFLA_MASTER, master)                        \
  _(IFLA_MTU, mtu)                              \
  _(IFLA_QDISC, qdisc)

static rtnl_mapping_t ns_ifmap[] = {
#define _(t, e)                                 \
  {                                             \
    .type = t,                                  \
    .offset = offsetof(ns_link_t, e),           \
    .size = sizeof(((ns_link_t*)0)->e)          \
  },
  ns_foreach_ifla
#undef _
  { .type = 0 }
};

u8 *format_ns_link (u8 *s, va_list *args)
{
  ns_link_t *l = va_arg(*args, ns_link_t *);
  s = format(s, "%s index %u", l->ifname, l->ifi.ifi_index);
  return s;
}

#define ns_foreach_rta                          \
  _(RTA_DST, dst, 1)                            \
  _(RTA_SRC, src, 1)                            \
  _(RTA_VIA, via, 1)                            \
  _(RTA_GATEWAY, gateway, 1)                    \
  _(RTA_IIF, iif, 1)                            \
  _(RTA_OIF, oif, 1)                            \
  _(RTA_PREFSRC, prefsrc, 0)                    \
  _(RTA_TABLE, table, 0)                        \
  _(RTA_PRIORITY, priority, 0)                  \
  _(RTA_CACHEINFO, cacheinfo, 0)                \
  _(RTA_ENCAP, encap, 1)

static rtnl_mapping_t ns_routemap[] = {
#define _(t, e, u)                              \
  {                                             \
    .type = t, .unique = u,                     \
    .offset = offsetof(ns_route_t, e),          \
    .size = sizeof(((ns_route_t*)0)->e)         \
  },
  ns_foreach_rta
#undef _
  { .type = 0 }
};

u8 *format_ns_route (u8 *s, va_list *args)
{
  ns_route_t *r = va_arg(*args, ns_route_t *);
  void *format_ip = r->rtm.rtm_family == AF_INET ? format_ip4_address : format_ip6_address;
  s = format(s, "%U/%d", format_ip, r->dst, r->rtm.rtm_dst_len);
  if (r->rtm.rtm_src_len)
    s = format(s, " from %U/%d", format_ip, r->src, r->rtm.rtm_src_len);
  if (is_nonzero(r->gateway))
    s = format(s, " via %U", format_ip, r->gateway);
  if (r->iif)
    s = format(s, " iif %d", r->iif);
  if (r->oif)
    s = format(s, " oif %d", r->oif);
  if (is_nonzero(r->prefsrc))
    s = format(s, " src %U", format_ip, r->prefsrc);
  if (r->table)
    s = format(s, " table %d", r->table);
  if (r->priority)
    s = format(s, " priority %u", r->priority);
  return s;
}

#define ns_foreach_ifaddr                       \
  _(IFA_ADDRESS, addr, 1)                       \
  _(IFA_LOCAL, local, 1)                        \
  _(IFA_LABEL, label, 0)                        \
  _(IFA_BROADCAST, broadcast, 0)                \
  _(IFA_ANYCAST, anycast, 0)                    \
  _(IFA_CACHEINFO, cacheinfo, 0)

static rtnl_mapping_t ns_addrmap[] = {
#define _(t, e, u)                              \
  {                                             \
    .type = t, .unique = u,                     \
    .offset = offsetof(ns_addr_t, e),           \
    .size = sizeof(((ns_addr_t*)0)->e)          \
  },
  ns_foreach_ifaddr
#undef _
  { .type = 0 }
};

u8 *format_ns_addr (u8 *s, va_list *args)
{
  ns_addr_t *a = va_arg(*args, ns_addr_t *);
  void *format_ip = a->ifaddr.ifa_family == AF_INET ? format_ip4_address : format_ip6_address;
  s = format(s, "%U/%d", format_ip, a->addr, a->ifaddr.ifa_prefixlen);
  if (is_nonzero(a->label))
    s = format(s, " dev %s", a->label);
  if (is_nonzero(a->broadcast))
    s = format(s, " broadcast %U", format_ip, a->broadcast);
  if (is_nonzero(a->anycast))
    s = format(s, " anycast %U", format_ip, a->anycast);
  if (is_nonzero(a->local))
    s = format(s, " local %U", format_ip, a->local);
  return s;
}

#ifndef NDA_RTA
#define NDA_RTA(r)  ((struct rtattr*)(((char*)(r)) + NLMSG_ALIGN(sizeof(struct ndmsg))))
#define NDA_PAYLOAD(n) NLMSG_PAYLOAD(n,sizeof(struct ndmsg))
#endif

#define ns_foreach_neigh                        \
  _(NDA_DST, dst, 1)                            \
  _(NDA_LLADDR, lladdr, 0)                      \
  _(NDA_PROBES, probes, 0)                      \
  _(NDA_CACHEINFO, cacheinfo, 0)

static rtnl_mapping_t ns_neighmap[] = {
#define _(t, e, u)                              \
  {                                             \
    .type = t, .unique = u,                     \
    .offset = offsetof(ns_neigh_t, e),          \
    .size = sizeof(((ns_neigh_t*)0)->e)         \
  },
  ns_foreach_neigh
#undef _
  { .type = 0 }
};

u8 *format_ns_neigh (u8 *s, va_list *args)
{
  ns_neigh_t *n = va_arg(*args, ns_neigh_t *);
  void *format_ip = n->nd.ndm_family == AF_INET ? format_ip4_address : format_ip6_address;
  s = format(s, "%U", format_ip, n->dst);
  if (is_nonzero(n->lladdr))
    s = format(s, " lladdr %U", format_ethernet_address, n->lladdr);
  if (n->probes)
    s = format(s, " probes %d", n->probes);
  return s;
}

typedef struct {
  void (*notify)(void *obj, netns_type_t type, u32 flags, uword opaque);
  uword opaque;
  u32 netns_index;
} netns_handle_t;

typedef struct {
  netns_t netns;
  u32 rtnl_handle;
  u32 subscriber_count;
} netns_p;

typedef struct {
  netns_p *netnss;
  netns_handle_t *handles;
} netns_main_t;

netns_main_t netns_main;

static int
rtnl_parse_rtattr(struct rtattr *db[], size_t max,
                  struct rtattr *rta, size_t len) {
  for(; RTA_OK(rta, len); rta = RTA_NEXT(rta, len)) {
    if (rta->rta_type <= max)
      db[rta->rta_type] = rta;
#ifdef RTNL_CHECK
    else
      clib_warning("RTA type too high: %d", rta->rta_type);
#endif
  }

  if(len) {
    clib_warning("rattr lenght mistmatch %d %d len",
                 (int) len, (int) rta->rta_len);
    return -1;
  }
  return 0;
}

/*
 * Debug function to display when
 * we receive an RTA that I forgot in
 * the mapping table (there are so many of them).
 */
#ifdef RTNL_CHECK
static void
rtnl_entry_check(struct rtattr *rtas[],
                 size_t rta_len,
                 rtnl_mapping_t map[],
                 char *logstr)
{
  int i;
  for (i=0; i<rta_len; i++) {
    if (!rtas[i])
      continue;

    rtnl_mapping_t *m = map;
    for (m = map; m->type; m++) {
      if (m->type == rtas[i]->rta_type)
        break;
    }
    if (!m->type)
      clib_warning("Unknown RTA type %d (%s)", rtas[i]->rta_type, logstr);
  }
}
#endif

/*
 * Check if the provided entry matches the parsed and unique rtas
 */
static int
rtnl_entry_match(void *entry,
                 struct rtattr *rtas[],
                 rtnl_mapping_t map[])
{
  u8 zero[1024] = {};
  for ( ;map->type != 0; map++) {
    struct rtattr *rta = rtas[map->type];
    size_t rta_len = rta?RTA_PAYLOAD(rta):0;
    if (!map->unique)
      continue;

    if (rta && RTA_PAYLOAD(rta) > map->size) {
      clib_warning("rta (type=%d len=%d) too long (max %d)",
                   rta->rta_type, rta->rta_len, map->size);
      return -1;
    }

    if ((rta && memcmp(RTA_DATA(rta), entry + map->offset, rta_len)) ||
        memcmp(entry + map->offset + rta_len, zero, map->size - rta_len)) {
      return 0;
    }
  }
  return 1;
}

static int
rtnl_entry_set(void *entry,
               struct rtattr *rtas[],
               rtnl_mapping_t map[],
               int init)
{
  for (; map->type != 0; map++) {

    struct rtattr *rta = rtas[map->type];

    if(map->type == RTA_ENCAP && rta) {
      /*Data of RTA_ENCAP is a pointer to rta attributes for MPLS*/
      rta = (struct rtattr*)RTA_DATA(rta);
      if (RTA_PAYLOAD(rta) > map->size) {
        clib_warning("rta (type=%d len=%d) too long (max %d)", rta->rta_type, rta->rta_len, map->size);
        return -1;
      }
      memcpy(entry + map->offset, RTA_DATA(rta), map->size);
      memset(entry + map->offset + map->size, 0, 0);
    } else if (rta) {
      if (RTA_PAYLOAD(rta) > map->size) {
        clib_warning("rta (type=%d len=%d) too long (max %d)", rta->rta_type, rta->rta_len, map->size);
        return -1;
      }
      memcpy(entry + map->offset, RTA_DATA(rta), RTA_PAYLOAD(rta));
      memset(entry + map->offset + RTA_PAYLOAD(rta), 0, map->size - RTA_PAYLOAD(rta));
    } else if (init) {
      memset(entry + map->offset, 0, map->size);
    }
  }
  return 0;
}

void
netns_notify(netns_p *ns, void *obj, netns_type_t type, u32 flags)
{
  netns_main_t *nm = &netns_main;
  netns_handle_t *h;
  pool_foreach(h, nm->handles, {
      if (h->netns_index == (ns - nm->netnss) &&  h->notify)
        h->notify(obj, type, flags, h->opaque);
    });
}

static_always_inline int
mask_match(void *a, void *b, void *mask, size_t len)
{
  u8 *va = (u8 *) a;
  u8 *vb = (u8 *) b;
  u8 *vm = (u8 *) mask;
  while (len--) {
    if ((va[len] ^ vb[len]) & vm[len])
      return 0;
  }
  return 1;
}

static ns_link_t *
ns_get_link(netns_p *ns, struct ifinfomsg *ifi, struct rtattr *rtas[])
{
  ns_link_t *link;
  pool_foreach(link, ns->netns.links, {
      if(ifi->ifi_index == link->ifi.ifi_index)
        return link;
    });
  return NULL;
}

static int
ns_rcv_link(netns_p *ns, struct nlmsghdr *hdr)
{
  ns_link_t *link;
  struct ifinfomsg *ifi;
  struct rtattr *rtas[IFLA_MAX + 1] = {};
  size_t datalen = hdr->nlmsg_len - NLMSG_ALIGN(sizeof(*hdr));

  if(datalen < sizeof(*ifi))
    return -1;

  ifi = NLMSG_DATA(hdr);
  if((datalen > NLMSG_ALIGN(sizeof(*ifi))) &&
     rtnl_parse_rtattr(rtas, IFLA_MAX, IFLA_RTA(ifi),
                       IFLA_PAYLOAD(hdr))) {
    return -1;
  }
#ifdef RTNL_CHECK
  rtnl_entry_check(rtas, IFLA_MAX + 1, ns_ifmap, "link");
#endif

  link = ns_get_link(ns, ifi, rtas);

  if (hdr->nlmsg_type == RTM_DELLINK) {
    if (!link)
      return -1;
    pool_put(ns->netns.links, link);
    netns_notify(ns, link, NETNS_TYPE_LINK, NETNS_F_DEL);
    return 0;
  }

  if (!link) {
    pool_get(ns->netns.links, link);
    rtnl_entry_set(link, rtas, ns_ifmap, 1);
  } else {
    rtnl_entry_set(link, rtas, ns_ifmap, 0);
  }

  link->ifi = *ifi;
  link->last_updated = vlib_time_now(vlib_get_main());
  netns_notify(ns, link, NETNS_TYPE_LINK, NETNS_F_ADD);
  return 0;
}

static ns_route_t *
ns_get_route(netns_p *ns, struct rtmsg *rtm, struct rtattr *rtas[])
{
  ns_route_t *route;

  //This describes the values which uniquely identify a route
  struct rtmsg msg = {
    .rtm_family = 0xff,
    .rtm_dst_len = 0xff,
    .rtm_src_len = 0xff,
    .rtm_table = 0xff,
    .rtm_protocol = 0xff,
    .rtm_type = 0xff
  };

  pool_foreach(route, ns->netns.routes, {
      if(mask_match(&route->rtm, rtm, &msg, sizeof(struct rtmsg)) &&
         rtnl_entry_match(route, rtas, ns_routemap))
        return route;
    });
  return NULL;
}

static int
ns_rcv_route(netns_p *ns, struct nlmsghdr *hdr)
{
  ns_route_t *route;
  struct rtmsg *rtm;
  struct rtattr *rtas[RTA_MAX + 1] = {};
  size_t datalen = hdr->nlmsg_len - NLMSG_ALIGN(sizeof(*hdr));

  if(datalen < sizeof(*rtm))
    return -1;

  rtm = NLMSG_DATA(hdr);
  if((datalen > NLMSG_ALIGN(sizeof(*rtm))) &&
     rtnl_parse_rtattr(rtas, RTA_MAX, RTM_RTA(rtm),
                       RTM_PAYLOAD(hdr))) {
    return -1;
  }
#ifdef RTNL_CHECK
  rtnl_entry_check(rtas, RTA_MAX + 1, ns_routemap, "route");
#endif
  route = ns_get_route(ns, rtm, rtas);

  if (hdr->nlmsg_type == RTM_DELROUTE) {
    if (!route)
      return -1;
    pool_put(ns->netns.routes, route);
    netns_notify(ns, route, NETNS_TYPE_ROUTE, NETNS_F_DEL);
    return 0;
  }

  if (!route) {
    pool_get(ns->netns.routes, route);
    memset(route, 0, sizeof(*route));
    rtnl_entry_set(route, rtas, ns_routemap, 1);
  } else {
    rtnl_entry_set(route, rtas, ns_routemap, 0);
  }

  route->rtm = *rtm;
  route->last_updated = vlib_time_now(vlib_get_main());
  netns_notify(ns, route, NETNS_TYPE_ROUTE, NETNS_F_ADD);
  return 0;
}

static ns_addr_t *
ns_get_addr(netns_p *ns, struct ifaddrmsg *ifaddr, struct rtattr *rtas[])
{
  ns_addr_t *addr;

  //This describes the values which uniquely identify a route
  struct ifaddrmsg msg = {
    .ifa_family = 0xff,
    .ifa_prefixlen = 0xff,
  };

  pool_foreach(addr, ns->netns.addresses, {
      if(mask_match(&addr->ifaddr, ifaddr, &msg, sizeof(struct ifaddrmsg)) &&
         rtnl_entry_match(addr, rtas, ns_addrmap))
        return addr;
    });
  return NULL;
}

static int
ns_rcv_addr(netns_p *ns, struct nlmsghdr *hdr)
{
  ns_addr_t *addr;
  struct ifaddrmsg *ifaddr;
  struct rtattr *rtas[IFA_MAX + 1] = {};
  size_t datalen = hdr->nlmsg_len - NLMSG_ALIGN(sizeof(*hdr));

  if(datalen < sizeof(*ifaddr))
    return -1;

  ifaddr = NLMSG_DATA(hdr);
  if((datalen > NLMSG_ALIGN(sizeof(*ifaddr))) &&
     rtnl_parse_rtattr(rtas, IFA_MAX, IFA_RTA(ifaddr),
                       IFA_PAYLOAD(hdr))) {
    return -1;
  }
#ifdef RTNL_CHECK
  rtnl_entry_check(rtas, IFA_MAX + 1, ns_addrmap, "addr");
#endif
  addr = ns_get_addr(ns, ifaddr, rtas);

  if (hdr->nlmsg_type == RTM_DELADDR) {
    if (!addr)
      return -1;
    pool_put(ns->netns.addresses, addr);
    netns_notify(ns, addr, NETNS_TYPE_ADDR, NETNS_F_DEL);
    return 0;
  }

  if (!addr) {
    pool_get(ns->netns.addresses, addr);
    memset(addr, 0, sizeof(*addr));
    rtnl_entry_set(addr, rtas, ns_addrmap, 1);
  } else {
    rtnl_entry_set(addr, rtas, ns_addrmap, 0);
  }

  addr->ifaddr = *ifaddr;
  addr->last_updated = vlib_time_now(vlib_get_main());
  netns_notify(ns, addr, NETNS_TYPE_ADDR, NETNS_F_ADD);
  return 0;
}

static ns_neigh_t *
ns_get_neigh(netns_p *ns, struct ndmsg *nd, struct rtattr *rtas[])
{
  ns_neigh_t *neigh;

  //This describes the values which uniquely identify a route
  struct ndmsg msg = {
    .ndm_family = 0xff,
    .ndm_ifindex = 0xff,
  };

  pool_foreach(neigh, ns->netns.neighbors, {
      if(mask_match(&neigh->nd, nd, &msg, sizeof(&msg)) &&
         rtnl_entry_match(neigh, rtas, ns_neighmap))
        return neigh;
    });
  return NULL;
}

static int
ns_rcv_neigh(netns_p *ns, struct nlmsghdr *hdr)
{
  ns_neigh_t *neigh;
  struct ndmsg *nd;
  struct rtattr *rtas[NDA_MAX + 1] = {};
  size_t datalen = hdr->nlmsg_len - NLMSG_ALIGN(sizeof(*hdr));

  if(datalen < sizeof(*nd))
    return -1;

  nd = NLMSG_DATA(hdr);
  if((datalen > NLMSG_ALIGN(sizeof(*nd))) &&
     rtnl_parse_rtattr(rtas, NDA_MAX, NDA_RTA(nd),
                       NDA_PAYLOAD(hdr))) {
    return -1;
  }
#ifdef RTNL_CHECK
  rtnl_entry_check(rtas, NDA_MAX + 1, ns_neighmap, "nd");
#endif
  neigh = ns_get_neigh(ns, nd, rtas);

  if (hdr->nlmsg_type == RTM_DELNEIGH) {
    if (!neigh)
      return -1;
    pool_put(ns->netns.neighbors, neigh);
    netns_notify(ns, neigh, NETNS_TYPE_NEIGH, NETNS_F_DEL);
    return 0;
  }

  if (!neigh) {
    pool_get(ns->netns.neighbors, neigh);
    memset(neigh, 0, sizeof(*neigh));
    rtnl_entry_set(neigh, rtas, ns_neighmap, 1);
  } else {
    rtnl_entry_set(neigh, rtas, ns_neighmap, 0);
  }

  neigh->nd = *nd;
  neigh->last_updated = vlib_time_now(vlib_get_main());
  netns_notify(ns, neigh, NETNS_TYPE_NEIGH, NETNS_F_ADD);
  return 0;
}

#define ns_object_foreach                       \
  _(neighbors, NETNS_TYPE_NEIGH)                \
  _(routes, NETNS_TYPE_ROUTE)                   \
  _(addresses, NETNS_TYPE_ADDR)                 \
  _(links, NETNS_TYPE_LINK)

static void
ns_recv_error(rtnl_error_t err, uword o)
{
  //An error was received. Reset everything.
  netns_p *ns = &netns_main.netnss[o];
  u32 *indexes = 0;
  u32 *i = 0;

#define _(pool, type)                                           \
  pool_foreach_index(*i, ns->netns.pool, {                      \
      vec_add1(indexes, *i);                                    \
    })                                                          \
    vec_foreach(i, indexes) {                                   \
    pool_put_index(ns->netns.pool, *i);                         \
    netns_notify(ns, &ns->netns.pool[*i], type, NETNS_F_DEL);   \
  }                                                             \
  vec_reset_length(indexes);

  ns_object_foreach

#undef _
    vec_free(indexes);
}

static void
ns_recv_rtnl(struct nlmsghdr *hdr, uword o)
{
  netns_p *ns = &netns_main.netnss[o];
  switch (hdr->nlmsg_type) {
  case RTM_NEWROUTE:
  case RTM_DELROUTE:
    ns_rcv_route(ns, hdr);
    break;
  case RTM_NEWLINK:
  case RTM_DELLINK:
    ns_rcv_link(ns, hdr);
    break;
  case RTM_NEWADDR:
  case RTM_DELADDR:
    ns_rcv_addr(ns, hdr);
    break;
  case RTM_NEWNEIGH:
  case RTM_DELNEIGH:
    ns_rcv_neigh(ns, hdr);
    break;
  default:
    clib_warning("unknown rtnl type %d", hdr->nlmsg_type);
    break;
  }
}

static void
netns_destroy(netns_p *ns)
{
  netns_main_t *nm = &netns_main;
  rtnl_stream_close(ns->rtnl_handle);
  pool_put(nm->netnss, ns);
  pool_free(ns->netns.links);
  pool_free(ns->netns.addresses);
  pool_free(ns->netns.routes);
  pool_free(ns->netns.neighbors);
}

static netns_p *
netns_get(char *name)
{
  netns_main_t *nm = &netns_main;
  netns_p *ns;
  pool_foreach(ns, nm->netnss, {
      if (!strcmp(name, ns->netns.name))
        return ns;
    });

  if (strlen(name) > RTNL_NETNS_NAMELEN)
    return NULL;

  pool_get(nm->netnss, ns);
  rtnl_stream_t s = {
    .recv_message = ns_recv_rtnl,
    .error = ns_recv_error,
    .opaque = (uword)(ns - nm->netnss),
  };
  strcpy(s.name, name);

  u32 handle;
  if ((handle = rtnl_stream_open(&s)) == ~0) {
    pool_put(nm->netnss, ns);
    return NULL;
  }

  strcpy(ns->netns.name, name);
  ns->netns.addresses = 0;
  ns->netns.links = 0;
  ns->netns.neighbors = 0;
  ns->netns.routes = 0;
  ns->subscriber_count = 0;
  ns->rtnl_handle = handle;
  return ns;
}

u32 netns_open(char *name, netns_sub_t *sub)
{
  netns_main_t *nm = &netns_main;
  netns_p *ns;
  netns_handle_t *p;
  if (!(ns = netns_get(name)))
    return ~0;

  pool_get(nm->handles, p);
  p->netns_index = ns - nm->netnss;
  p->notify = sub->notify;
  p->opaque = sub->opaque;
  ns->subscriber_count++;
  return p - nm->handles;
}

netns_t *netns_getns(u32 handle)
{
  netns_main_t *nm = &netns_main;
  netns_handle_t *h = pool_elt_at_index(nm->handles, handle);
  netns_p *ns = pool_elt_at_index(nm->netnss, h->netns_index);
  return &ns->netns;
}

void netns_close(u32 handle)
{
  netns_main_t *nm = &netns_main;
  netns_handle_t *h = pool_elt_at_index(nm->handles, handle);
  netns_p *ns = pool_elt_at_index(nm->netnss, h->netns_index);
  pool_put(h, nm->handles);
  ns->subscriber_count--;
  if (!ns->subscriber_count)
    netns_destroy(ns);
}

void netns_callme(u32 handle, char del)
{
  netns_main_t *nm = &netns_main;
  netns_handle_t *h = pool_elt_at_index(nm->handles, handle);
  netns_p *ns = pool_elt_at_index(nm->netnss, h->netns_index);
  u32 i = 0;
  if (!h->notify)
    return;

#define _(pool, type)                                           \
  pool_foreach_index(i, ns->netns.pool, {                       \
      h->notify(&ns->netns.pool[i], type,                       \
                del?NETNS_F_DEL:NETNS_F_ADD, h->opaque);        \
    });

  ns_object_foreach
#undef _

    }

u8 *format_ns_object(u8 *s, va_list *args)
{
  netns_type_t t = va_arg(*args, netns_type_t);
  void *o = va_arg(*args, void *);
  switch (t) {
  case NETNS_TYPE_ADDR:
    return format(s, "addr %U", format_ns_addr, o);
  case NETNS_TYPE_ROUTE:
    return format(s, "route %U", format_ns_route, o);
  case NETNS_TYPE_LINK:
    return format(s, "link %U", format_ns_link, o);
  case NETNS_TYPE_NEIGH:
    return format(s, "neigh %U", format_ns_neigh, o);
  }
  return s;
}

u8 *format_ns_flags(u8 *s, va_list *args)
{
  u32 flags = va_arg(*args, u32);
  if (flags & NETNS_F_ADD)
    s = format(s, "add");
  else if (flags & NETNS_F_DEL)
    s = format(s, "del");
  else
    s = format(s, "mod");
  return s;
}

clib_error_t *
netns_init (vlib_main_t * vm)
{
  netns_main_t *nm = &netns_main;
  nm->netnss = 0;
  nm->handles = 0;
  return 0;
}

VLIB_INIT_FUNCTION (netns_init);
