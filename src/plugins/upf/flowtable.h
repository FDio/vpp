/*---------------------------------------------------------------------------
 * Copyright (c) 2016 Qosmos and/or its affiliates.
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
 *---------------------------------------------------------------------------
 */

#ifndef __flowtable_h__
#define __flowtable_h__

#include <pthread.h>
#include <stdbool.h>
#include <vppinfra/error.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vppinfra/bihash_48_8.h>
#include <vppinfra/dlist.h>
#include <vppinfra/pool.h>
#include <vppinfra/vec.h>

#include "flowtable_tcp.h"

#define foreach_flowtable_error				\
  _(HIT, "packets with an existing flow")		\
  _(THRU, "packets gone through")			\
  _(CREATED, "packets which created a new flow")	\
  _(UNHANDLED, "unhandled (non-ip)  packet")		\
  _(TIMER_EXPIRE, "flows that have expired")		\
  _(COLLISION, "hashtable collisions")			\
  _(RECYCLE, "flow recycled")

typedef enum {
#define _(sym, str) FLOWTABLE_ERROR_ ## sym,
  foreach_flowtable_error
#undef _
  FLOWTABLE_N_ERROR
} flowtable_error_t;

typedef enum {
  FT_NEXT_DROP,
  FT_NEXT_CLASSIFY,
  FT_NEXT_PROCESS,
  FT_NEXT_N_NEXT
} flowtable_next_t;

/* key */
typedef struct {
  union {
    struct {
      struct {
	ip46_address_t src;
	ip46_address_t dst;
      } ip;
      u32 session_id;
      struct {
	u16 src;
	u16 dst;
      } port;
      u8 proto;
    };
    u64 key[6];
  };
} flow_key_t;

/* dlist helpers */
#define dlist_is_empty(pool, head_index)				\
  ({									\
    dlist_elt_t * head = pool_elt_at_index((pool), (head_index));	\
    (head->next == (u32) ~0 || head->next == (head_index));		\
  })

typedef struct {
  u32 pkts;
  u64 bytes;
} flow_stats_t;

typedef enum {
  FT_FORWARD = 0,
  FT_REVERSE,
  FT_DIRECTION_MAX
} flow_direction_t;

typedef enum {
  FT_TIMEOUT_TYPE_UNKNOWN,
  FT_TIMEOUT_TYPE_IPV4,
  FT_TIMEOUT_TYPE_IPV6,
  FT_TIMEOUT_TYPE_ICMP,
  FT_TIMEOUT_TYPE_UDP,
  FT_TIMEOUT_TYPE_TCP,
  FT_TIMEOUT_TYPE_MAX
} flowtable_timeout_type_t;

typedef struct flow_entry {
  /* Required for pool_get_aligned  */
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  /* flow signature */
  flow_key_t key;
  u16 tcp_state;

  /* stats */
  flow_stats_t stats[FT_DIRECTION_MAX];

  /* timers */
  u32 expire;  /* in seconds */
  u16 lifetime;  /* in seconds */
  u32 timer_index;  /* index in the timer pool */

  /* UPF data */
  u8 src_intf;                        /* UPF source interface type */
  u32 application_id;                 /* L7 app index */
  u32 pdr_id[FT_DIRECTION_MAX];       /* PDRs */
  u32 next[FT_DIRECTION_MAX];
} flow_entry_t;

/* Timers (in seconds) */
#define TIMER_DEFAULT_LIFETIME (60)
#define TIMER_MAX_LIFETIME (300)

/* Default max number of flows to expire during one run.
 * 256 is the max number of packets in a vector, so this is a minimum
 * if all packets create a flow. */
#define TIMER_MAX_EXPIRE (1 << 8)

typedef struct {
  /* hashtable */
  BVT(clib_bihash) flows_ht;

  /* timers */
  dlist_elt_t * timers;
  u32 * timer_wheel;
  u32 time_index;

  /* flow cache
   * set cache size to 256 so that the worst node run fills the cache at most once */
#define FLOW_CACHE_SZ 256
  u32 * flow_cache;
} flowtable_main_per_cpu_t;

/*
 * As advised in the thread below :
 * https://lists.fd.io/pipermail/vpp-dev/2016-October/002787.html
 * hashtable is configured to alloc (NUM_BUCKETS * CLIB_CACHE_LINE_BYTES) Bytes
 * with (flow_count / (BIHASH_KVP_PER_PAGE / 2)) Buckets
 */
#define FM_POOL_COUNT_LOG2 22
#define FM_POOL_COUNT (1 << FM_POOL_COUNT_LOG2)
#define FM_NUM_BUCKETS (1 << (FM_POOL_COUNT_LOG2 - (BIHASH_KVP_PER_PAGE / 2)))
#define FM_MEMORY_SIZE (FM_NUM_BUCKETS * CLIB_CACHE_LINE_BYTES * 6)

typedef struct {
  /* flow entry pool */
  u32 flows_max;
  flow_entry_t * flows;
  pthread_spinlock_t flows_lock;
  u64 flows_cpt;

  u16 timer_lifetime[FT_TIMEOUT_TYPE_MAX];
  u16 timer_max_lifetime;

  /* per cpu */
  flowtable_main_per_cpu_t * per_cpu;

  /* convenience */
  vlib_main_t * vlib_main;
  vnet_main_t * vnet_main;
} flowtable_main_t;

extern flowtable_main_t flowtable_main;

u8 * format_flow_key(u8 *, va_list *);
u8 * format_flow(u8 *, va_list *);

clib_error_t * flowtable_lifetime_update(flowtable_timeout_type_t type, u16 value);
clib_error_t * flowtable_max_lifetime_update(u16 value);
clib_error_t * flowtable_init(vlib_main_t * vm);

void foreach_upf_flows (BVT (clib_bihash_kv) * kvp, void * arg);

static inline u16 flowtable_lifetime_get(flowtable_timeout_type_t type)
{
  flowtable_main_t * fm = &flowtable_main;

  return (type >= FT_TIMEOUT_TYPE_MAX) ? ~0 : fm->timer_lifetime[type];
}

int
flowtable_update(ip46_address_t ip_src, ip46_address_t ip_dst, u8 ip_upper_proto,
		 u16 port_src, u16 port_dst, u16 lifetime);

flow_entry_t *
flowtable_entry_lookup_create(flowtable_main_t * fm, flowtable_main_per_cpu_t * fmt,
			      BVT(clib_bihash_kv) * kv, u32 const now, int * created);

void
timer_wheel_index_update(flowtable_main_t * fm, flowtable_main_per_cpu_t * fmt, u32 now);

u64
flowtable_timer_expire(flowtable_main_t * fm, flowtable_main_per_cpu_t * fmt, u32 now);

static inline void
parse_packet_protocol(udp_header_t * udp, uword is_reverse, flow_key_t * key)
{
  if (key->proto == IP_PROTOCOL_UDP || key->proto == IP_PROTOCOL_TCP)
    {
      /* tcp and udp ports have the same offset */
      if (is_reverse)
	{
	  key->port.src = udp->src_port;
	  key->port.dst = udp->dst_port;
	}
      else
	{
	  key->port.src = udp->dst_port;
	  key->port.dst = udp->src_port;
	}
    }
  else
    {
      key->port.src = 0;
      key->port.dst = 0;
    }
}

static inline void
parse_ip4_packet(ip4_header_t * ip4, uword * is_reverse, flow_key_t * key)
{
  key->proto = ip4->protocol;

  if (ip4_address_compare(&ip4->src_address, &ip4->dst_address) < 0)
    {
      ip46_address_set_ip4(&key->ip.src, &ip4->src_address);
      ip46_address_set_ip4(&key->ip.dst, &ip4->dst_address);
      *is_reverse = 1;
    }
  else
    {
      ip46_address_set_ip4(&key->ip.src, &ip4->dst_address);
      ip46_address_set_ip4(&key->ip.dst, &ip4->src_address);
    }

  parse_packet_protocol((udp_header_t *) ip4_next_header(ip4), *is_reverse, key);
}

static inline void
parse_ip6_packet(ip6_header_t * ip6, uword * is_reverse, flow_key_t * key)
{
  key->proto = ip6->protocol;

  if (ip6_address_compare(&ip6->src_address, &ip6->dst_address) < 0)
    {
      ip46_address_set_ip6(&key->ip.src, &ip6->src_address);
      ip46_address_set_ip6(&key->ip.dst, &ip6->dst_address);
      *is_reverse = 1;
    }
  else
    {
      ip46_address_set_ip6(&key->ip.src, &ip6->dst_address);
      ip46_address_set_ip6(&key->ip.dst, &ip6->src_address);
    }

  parse_packet_protocol((udp_header_t *) ip6_next_header(ip6), *is_reverse, key);
}

static inline void
flow_mk_key(u32 id, vlib_buffer_t * buffer, u16 offset, u8 is_ip4,
	    uword * is_reverse, BVT(clib_bihash_kv) * kv)
{
  flow_key_t * key = (flow_key_t *)&kv->key;

  memset(key, 0, sizeof(*key));

  key->session_id = id;

  /* compute 5 tuple key so that 2 half connections
   * get into the same flow */
  if (is_ip4)
    {
      parse_ip4_packet(vlib_buffer_get_current(buffer) + offset, is_reverse, key);
    }
  else
    {
      parse_ip6_packet(vlib_buffer_get_current(buffer) + offset, is_reverse, key);
    }
}

always_inline int
flow_tcp_update_lifetime(flow_entry_t * f, tcp_header_t * hdr)
{
  tcp_state_t old_state, new_state;

  ASSERT(f->tcp_state < TCP_STATE_MAX);

  old_state = f->tcp_state;
  new_state = tcp_trans[old_state][tcp_event(hdr)];

  if (new_state && old_state != new_state)
    {
      f->tcp_state = new_state;
      f->lifetime = tcp_lifetime[new_state];
      return 1;
    }

  return 0;
}

always_inline int
flow_update_lifetime(flow_entry_t * f, vlib_buffer_t * b, u8 is_ip4)
{
  /*
   * CHECK-ME: assert we have enough wellformed data to read the tcp header.
   */
  if (f->key.proto == IP_PROTOCOL_TCP)
    {
      tcp_header_t * hdr =
	(tcp_header_t *)(vlib_buffer_get_current (b) +
			 (is_ip4 ? sizeof(ip4_header_t) : sizeof(ip6_header_t)));

      return flow_tcp_update_lifetime(f, hdr);
    }

  return 0;
}

always_inline void
timer_wheel_insert_flow(flowtable_main_t * fm, flowtable_main_per_cpu_t * fmt,
			flow_entry_t * f)
{
  u32 timer_slot_head_index;

  timer_slot_head_index = (fmt->time_index + f->lifetime) % fm->timer_max_lifetime;
  clib_dlist_addtail(fmt->timers, timer_slot_head_index, f->timer_index);
}

always_inline void
timer_wheel_resched_flow(flowtable_main_t * fm, flowtable_main_per_cpu_t * fmt,
			 flow_entry_t * f, u32 now)
{
  clib_dlist_remove(fmt->timers, f->timer_index);
  f->expire = now + f->lifetime;
  timer_wheel_insert_flow(fm, fmt, f);

  return;
}

#endif  /* __flowtable_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
