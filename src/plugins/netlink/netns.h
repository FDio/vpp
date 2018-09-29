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

#ifndef NETNS_H_
#define NETNS_H_

#include <vlib/vlib.h>

#include <sys/socket.h>
#include <linux/rtnetlink.h>
#include <linux/netlink.h>
#include <net/if.h>

#include <netlink/rtnl.h>

/*include it for 'struct mpls_label'*/
#include <linux/mpls.h>
/*so far depth is fixed, looking into ways to be dynamic*/
#define MPLS_STACK_DEPTH 7

typedef struct {
  struct ifinfomsg ifi;
  u8 hwaddr[IFHWADDRLEN];
  u8 broadcast[IFHWADDRLEN];
  u8 ifname[IFNAMSIZ];
  u32 mtu;
  u32 master;
  u8 qdisc[IFNAMSIZ];
  struct rtnl_link_stats stats; //This struct is big and only comes as a response to a request
  f64 last_updated;
} ns_link_t;

typedef struct {
  struct rtmsg rtm;
  u8 dst[16];
  u8 src[16];
  u8 via[16];
  u8 prefsrc[16];
  u32 iif;
  u32 oif;
  u32 table;
  u8 gateway[16];
  u32 priority;
  struct rta_cacheinfo cacheinfo;
  struct mpls_label encap[MPLS_STACK_DEPTH];
  f64 last_updated;
} ns_route_t;

typedef struct {
  struct ifaddrmsg ifaddr;
  u8 addr[16];
  u8 local[16];
  u8 label[IFNAMSIZ];
  u8 broadcast[16];
  u8 anycast[16];
  struct ifa_cacheinfo cacheinfo;
  f64 last_updated;
} ns_addr_t;

typedef struct {
  struct ndmsg nd;
  u8 dst[16];
  u8 lladdr[IFHWADDRLEN];
  u32 probes;
  struct nda_cacheinfo cacheinfo;
  f64 last_updated;
} ns_neigh_t;

typedef struct {
  char name[RTNL_NETNS_NAMELEN + 1];
  ns_link_t  *links;
  ns_route_t *routes;
  ns_addr_t  *addresses;
  ns_neigh_t *neighbors;
} netns_t;


typedef enum {
  NETNS_TYPE_LINK,
  NETNS_TYPE_ROUTE,
  NETNS_TYPE_ADDR,
  NETNS_TYPE_NEIGH,
} netns_type_t;

//Flags used in notification functions call
#define NETNS_F_ADD    0x01
#define NETNS_F_DEL    0x02

typedef struct {
  void (*notify)(void *obj, netns_type_t type, u32 flags, uword opaque);
  uword opaque;
} netns_sub_t;

/*
 * Subscribe for events related to the given namespace.
 * When another subscriber already uses the namespace,
 * this call will not trigger updates for already
 * existing routes (This is to protect against
 * synch. Vs asynch. issues).
 */
u32 netns_open(char *name, netns_sub_t *sub);

/*
 * Retrieves the namespace structure associated with a
 * given namespace handler.
 */
netns_t *netns_getns(u32 handle);

/*
 * Terminates a subscriber session.
 */
void netns_close(u32 handle);

/*
 * Calls the callback associated with the handle
 * for all existing objects with the flags
 * set to (del?NETNS_F_DEL:NETNS_F_ADD).
 */
void netns_callme(u32 handle, char del);

/*
 * netns struct format functions.
 * Taking the struct as single argument.
 */
u8 *format_ns_neigh(u8 *s, va_list *args);
u8 *format_ns_addr(u8 *s, va_list *args);
u8 *format_ns_route(u8 *s, va_list *args);
u8 *format_ns_link(u8 *s, va_list *args);

u8 *format_ns_object(u8 *s, va_list *args);
u8 *format_ns_flags(u8 *s, va_list *args);

#endif
