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
#include <stdbool.h>
#include <vppinfra/error.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vlib/vlib.h>
#include <vnet/fib/fib_types.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/adj/adj.h>
#include <vnet/dpo/load_balance.h>
#include "lpm.h"

#define MAP_SKIP_IP6_LOOKUP 1

#define MAP_ERR_GOOD			0
#define MAP_ERR_BAD_POOL_SIZE		-1
#define MAP_ERR_BAD_HT_RATIO		-2
#define MAP_ERR_BAD_LIFETIME		-3
#define MAP_ERR_BAD_BUFFERS		-4
#define MAP_ERR_BAD_BUFFERS_TOO_LARGE	-5

int map_create_domain (ip4_address_t * ip4_prefix, u8 ip4_prefix_len,
		       ip6_address_t * ip6_prefix, u8 ip6_prefix_len,
		       ip6_address_t * ip6_src, u8 ip6_src_len,
		       u8 ea_bits_len, u8 psid_offset, u8 psid_length,
		       u32 * map_domain_index, u16 mtu, u8 flags, char *tag);
int map_delete_domain (u32 map_domain_index);
int map_add_del_psid (u32 map_domain_index, u16 psid, ip6_address_t * tep,
		      bool is_add);
int map_if_enable_disable (bool is_enable, u32 sw_if_index,
			   bool is_translation);
u8 *format_map_trace (u8 * s, va_list * args);

int map_param_set_fragmentation (bool inner, bool ignore_df);
int map_param_set_icmp (ip4_address_t * ip4_err_relay_src);
int map_param_set_icmp6 (u8 enable_unreachable);
void map_pre_resolve (ip4_address_t * ip4, ip6_address_t * ip6, bool is_del);
int map_param_set_reassembly (bool is_ipv6, u16 lifetime_ms,
			      u16 pool_size, u32 buffers, f64 ht_ratio,
			      u32 * reass, u32 * packets);
int map_param_set_security_check (bool enable, bool fragments);
int map_param_set_traffic_class (bool copy, u8 tc);
int map_param_set_tcp (u16 tcp_mss);


typedef enum
{
  MAP_DOMAIN_PREFIX = 1 << 0,
  MAP_DOMAIN_TRANSLATION = 1 << 1,	// The domain uses MAP-T
  MAP_DOMAIN_RFC6052 = 1 << 2,
} __attribute__ ((__packed__)) map_domain_flags_e;

/**
 * IP4 reassembly logic:
 * One virtually reassembled flow requires a map_ip4_reass_t structure in order
 * to keep the first-fragment port number and, optionally, cache out of sequence
 * packets.
 * There are up to MAP_IP4_REASS_MAX_REASSEMBLY such structures.
 * When in use, those structures are stored in a hash table of MAP_IP4_REASS_BUCKETS buckets.
 * When a new structure needs to be used, it is allocated from available ones.
 * If there is no structure available, the oldest in use is selected and used if and
 * only if it was first allocated more than MAP_IP4_REASS_LIFETIME seconds ago.
 * In case no structure can be allocated, the fragment is dropped.
 */

#define MAP_IP4_REASS_LIFETIME_DEFAULT (100)	/* ms */
#define MAP_IP4_REASS_HT_RATIO_DEFAULT (1.0)
#define MAP_IP4_REASS_POOL_SIZE_DEFAULT 1024	// Number of reassembly structures
#define MAP_IP4_REASS_BUFFERS_DEFAULT 2048

#define MAP_IP4_REASS_MAX_FRAGMENTS_PER_REASSEMBLY 5	// Number of fragment per reassembly

#define MAP_IP6_REASS_LIFETIME_DEFAULT (100)	/* ms */
#define MAP_IP6_REASS_HT_RATIO_DEFAULT (1.0)
#define MAP_IP6_REASS_POOL_SIZE_DEFAULT 1024	// Number of reassembly structures
#define MAP_IP6_REASS_BUFFERS_DEFAULT 2048

#define MAP_IP6_REASS_MAX_FRAGMENTS_PER_REASSEMBLY 5

#define MAP_IP6_REASS_COUNT_BYTES
#define MAP_IP4_REASS_COUNT_BYTES

//#define IP6_MAP_T_OVERRIDE_TOS 0

/*
 * This structure _MUST_ be no larger than a single cache line (64 bytes).
 * If more space is needed make a union of ip6_prefix and *rules, as
 * those are mutually exclusive.
 */
typedef struct
{
  /* Required for pool_get_aligned */
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  ip6_address_t ip6_src;
  ip6_address_t ip6_prefix;
  ip6_address_t *rules;
  u32 suffix_mask;
  ip4_address_t ip4_prefix;
  u16 psid_mask;
  u16 mtu;
  map_domain_flags_e flags;
  u8 ip6_prefix_len;
  u8 ip6_src_len;
  u8 ea_bits_len;
  u8 psid_offset;
  u8 psid_length;

  /* helpers */
  u8 psid_shift;
  u8 suffix_shift;
  u8 ea_shift;

  /* not used by forwarding */
  u8 ip4_prefix_len;
} map_domain_t;

STATIC_ASSERT ((sizeof (map_domain_t) <= CLIB_CACHE_LINE_BYTES),
	       "MAP domain fits in one cacheline");

/*
 * Extra data about a domain that doesn't need to be time/space critical.
 * This structure is in a vector parallel to the main map_domain_t,
 * and indexed by the same map-domain-index values.
 */
typedef struct
{
  char *tag;			/* Probably a user-assigned domain name. */
} map_domain_extra_t;

#define MAP_REASS_INDEX_NONE ((u16)0xffff)

/*
 * Hash key, padded out to 16 bytes for fast compare
 */
/* *INDENT-OFF* */
typedef union {
  CLIB_PACKED (struct {
    ip4_address_t src;
    ip4_address_t dst;
    u16 fragment_id;
    u8 protocol;
  });
  u64 as_u64[2];
  u32 as_u32[4];
} map_ip4_reass_key_t;
/* *INDENT-ON* */

typedef struct
{
  map_ip4_reass_key_t key;
  f64 ts;
#ifdef MAP_IP4_REASS_COUNT_BYTES
  u16 expected_total;
  u16 forwarded;
#endif
  i32 port;
  u16 bucket;
  u16 bucket_next;
  u16 fifo_prev;
  u16 fifo_next;
  u32 fragments[MAP_IP4_REASS_MAX_FRAGMENTS_PER_REASSEMBLY];
} map_ip4_reass_t;

/*
 * MAP domain counters
 */
typedef enum
{
  /* Simple counters */
  MAP_DOMAIN_IPV4_FRAGMENT = 0,
  /* Combined counters */
  MAP_DOMAIN_COUNTER_RX = 0,
  MAP_DOMAIN_COUNTER_TX,
  MAP_N_DOMAIN_COUNTER
} map_domain_counter_t;

/*
 * main_main_t
 */
/* *INDENT-OFF* */
typedef union {
  CLIB_PACKED (struct {
    ip6_address_t src;
    ip6_address_t dst;
    u32 fragment_id;
    u8 protocol;
  });
  u64 as_u64[5];
  u32 as_u32[10];
} map_ip6_reass_key_t;
/* *INDENT-OFF* */

typedef struct {
  u32 pi; //Cached packet or ~0
  u16 next_data_offset; //The data offset of the additional 20 bytes or ~0
  u8 next_data_len; //Number of bytes ready to be copied (20 if not last fragment)
  u8 next_data[20]; //The 20 additional bytes
} map_ip6_fragment_t;

typedef struct {
  map_ip6_reass_key_t key;
  f64 ts;
#ifdef MAP_IP6_REASS_COUNT_BYTES
  u16 expected_total;
  u16 forwarded;
#endif
  u16 bucket; //What hash bucket this element is linked in
  u16 bucket_next;
  u16 fifo_prev;
  u16 fifo_next;
  ip4_header_t ip4_header;
  map_ip6_fragment_t fragments[MAP_IP6_REASS_MAX_FRAGMENTS_PER_REASSEMBLY];
} map_ip6_reass_t;

#ifdef MAP_SKIP_IP6_LOOKUP
/**
 * A pre-resolved next-hop
 */
typedef struct map_main_pre_resolved_t_
{
  /**
   * Linkage into the FIB graph
   */
  fib_node_t node;

  /**
   * The FIB entry index of the next-hop
   */
  fib_node_index_t fei;

  /**
   * This object sibling index on the FIB entry's child dependency list
   */
  u32 sibling;

  /**
   * The Load-balance object index to use to forward
   */
  dpo_id_t dpo;
} map_main_pre_resolved_t;

/**
 * Pre-resolved next hops for v4 and v6. Why these are global and not
 * per-domain is beyond me.
 */
extern map_main_pre_resolved_t pre_resolved[FIB_PROTOCOL_MAX];
#endif

typedef struct {
  /* pool of MAP domains */
  map_domain_t *domains;
  map_domain_extra_t *domain_extras;

  /* MAP Domain packet/byte counters indexed by map domain index */
  vlib_simple_counter_main_t *simple_domain_counters;
  vlib_combined_counter_main_t *domain_counters;
  volatile u32 *counter_lock;

  /* API message id base */
  u16 msg_id_base;

  /* Traffic class: zero, copy (~0) or fixed value */
  u8 tc;
  bool tc_copy;

  bool sec_check;		/* Inbound security check */
  bool sec_check_frag;		/* Inbound security check for (subsequent) fragments */
  bool icmp6_enabled;		/* Send destination unreachable for security check failure */

  u16 tcp_mss;			/* TCP MSS clamp value */

  /* ICMPv6 -> ICMPv4 relay parameters */
  ip4_address_t icmp4_src_address;
  vlib_simple_counter_main_t icmp_relayed;

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;

  /*
   * IPv4 encap and decap reassembly
   */
  /* Configuration */
  f32 ip4_reass_conf_ht_ratio; //Size of ht is 2^ceil(log2(ratio*pool_size))
  u16 ip4_reass_conf_pool_size; //Max number of allocated reass structures
  u16 ip4_reass_conf_lifetime_ms; //Time a reassembly struct is considered valid in ms
  u32 ip4_reass_conf_buffers; //Maximum number of buffers used by ip4 reassembly

  /* Runtime */
  map_ip4_reass_t *ip4_reass_pool;
  u8 ip4_reass_ht_log2len; //Hash table size is 2^log2len
  u16 ip4_reass_allocated;
  u16 *ip4_reass_hash_table;
  u16 ip4_reass_fifo_last;
  volatile u32 *ip4_reass_lock;

  /* Counters */
  u32 ip4_reass_buffered_counter;

  bool frag_inner;		/* Inner or outer fragmentation */
  bool frag_ignore_df;		/* Fragment (outer) packet even if DF is set */

  /*
   * IPv6 decap reassembly
   */
  /* Configuration */
  f32 ip6_reass_conf_ht_ratio; //Size of ht is 2^ceil(log2(ratio*pool_size))
  u16 ip6_reass_conf_pool_size; //Max number of allocated reass structures
  u16 ip6_reass_conf_lifetime_ms; //Time a reassembly struct is considered valid in ms
  u32 ip6_reass_conf_buffers; //Maximum number of buffers used by ip6 reassembly

  /* Runtime */
  map_ip6_reass_t *ip6_reass_pool;
  u8 ip6_reass_ht_log2len; //Hash table size is 2^log2len
  u16 ip6_reass_allocated;
  u16 *ip6_reass_hash_table;
  u16 ip6_reass_fifo_last;
  volatile u32 *ip6_reass_lock;

  /* Counters */
  u32 ip6_reass_buffered_counter;

  /* Graph node state */
  uword *bm_trans_enabled_by_sw_if;
  uword *bm_encap_enabled_by_sw_if;

  /* Lookup tables */
  lpm_t *ip4_prefix_tbl;
  lpm_t *ip6_prefix_tbl;
  lpm_t *ip6_src_prefix_tbl;
} map_main_t;

/*
 * MAP Error counters/messages
 */
#define foreach_map_error				\
  /* Must be first. */					\
 _(NONE, "valid MAP packets")				\
 _(BAD_PROTOCOL, "bad protocol")			\
 _(SEC_CHECK, "security check failed")			\
 _(ENCAP_SEC_CHECK, "encap security check failed")	\
 _(DECAP_SEC_CHECK, "decap security check failed")	\
 _(ICMP, "unable to translate ICMP")			\
 _(ICMP_RELAY, "unable to relay ICMP")			\
 _(UNKNOWN, "unknown")					\
 _(NO_BINDING, "no binding")				\
 _(NO_DOMAIN, "no domain")				\
 _(FRAGMENTED, "packet is a fragment")                  \
 _(FRAGMENT_MEMORY, "could not cache fragment")	        \
 _(FRAGMENT_MALFORMED, "fragment has unexpected format")\
 _(FRAGMENT_DROPPED, "dropped cached fragment")         \
 _(MALFORMED, "malformed packet")			\
 _(DF_SET, "can't fragment, DF set")

typedef enum {
#define _(sym,str) MAP_ERROR_##sym,
   foreach_map_error
#undef _
   MAP_N_ERROR,
 } map_error_t;

u64 map_error_counter_get(u32 node_index, map_error_t map_error);

typedef struct {
  u32 map_domain_index;
  u16 port;
} map_trace_t;

extern map_main_t map_main;

extern vlib_node_registration_t ip4_map_node;
extern vlib_node_registration_t ip6_map_node;

extern vlib_node_registration_t ip4_map_t_node;
extern vlib_node_registration_t ip4_map_t_fragmented_node;
extern vlib_node_registration_t ip4_map_t_tcp_udp_node;
extern vlib_node_registration_t ip4_map_t_icmp_node;

extern vlib_node_registration_t ip6_map_t_node;
extern vlib_node_registration_t ip6_map_t_fragmented_node;
extern vlib_node_registration_t ip6_map_t_tcp_udp_node;
extern vlib_node_registration_t ip6_map_t_icmp_node;

/*
 * map_get_pfx
 */
static_always_inline u64
map_get_pfx (map_domain_t *d, u32 addr, u16 port)
{
  u16 psid = (port >> d->psid_shift) & d->psid_mask;

  if (d->ea_bits_len == 0 && d->rules)
    return clib_net_to_host_u64(d->rules[psid].as_u64[0]);

  u32 suffix = (addr >> d->suffix_shift) & d->suffix_mask;
  u64 ea = d->ea_bits_len == 0 ? 0 : (((u64) suffix << d->psid_length)) | psid;

  return clib_net_to_host_u64(d->ip6_prefix.as_u64[0]) | ea << d->ea_shift;
}

static_always_inline u64
map_get_pfx_net (map_domain_t *d, u32 addr, u16 port)
{
  return clib_host_to_net_u64(map_get_pfx(d, clib_net_to_host_u32(addr),
                                          clib_net_to_host_u16(port)));
}

/*
 * map_get_sfx
 */
static_always_inline u64
map_get_sfx (map_domain_t *d, u32 addr, u16 port)
{
  u16 psid = (port >> d->psid_shift) & d->psid_mask;

  /* Shared 1:1 mode. */
  if (d->ea_bits_len == 0 && d->rules)
    return clib_net_to_host_u64(d->rules[psid].as_u64[1]);
  if (d->ip6_prefix_len == 128)
    return clib_net_to_host_u64(d->ip6_prefix.as_u64[1]);

  if (d->ip6_src_len == 96)
    return (clib_net_to_host_u64(d->ip6_prefix.as_u64[1]) | addr);

  /* IPv4 prefix */
  if (d->flags & MAP_DOMAIN_PREFIX)
    return (u64) (addr & (0xFFFFFFFF << d->suffix_shift)) << 16;

  /* Shared or full IPv4 address */
  return ((u64) addr << 16) | psid;
}

static_always_inline u64
map_get_sfx_net (map_domain_t *d, u32 addr, u16 port)
{
  return clib_host_to_net_u64(map_get_sfx(d, clib_net_to_host_u32(addr),
                                          clib_net_to_host_u16(port)));
}

static_always_inline u32
map_get_ip4 (ip6_address_t *addr, u16 prefix_len)
{
  ASSERT(prefix_len == 64 || prefix_len == 96);
  if (prefix_len == 96)
    return clib_host_to_net_u32(clib_net_to_host_u64(addr->as_u64[1]));
  else
    return clib_host_to_net_u32(clib_net_to_host_u64(addr->as_u64[1]) >> 16);
}

static_always_inline map_domain_t *
ip4_map_get_domain (ip4_address_t *addr, u32 *map_domain_index, u8 *error)
{
  map_main_t *mm = &map_main;

  u32 mdi = mm->ip4_prefix_tbl->lookup(mm->ip4_prefix_tbl, addr, 32);
  if (mdi == ~0) {
    *error = MAP_ERROR_NO_DOMAIN;
    return 0;
  }
  *map_domain_index = mdi;
  return pool_elt_at_index(mm->domains, mdi);
}

/*
 * Get the MAP domain from an IPv6 address.
 * If the IPv6 address or
 * prefix is shared the IPv4 address must be used.
 */
static_always_inline map_domain_t *
ip6_map_get_domain (ip6_address_t *addr,
                    u32 *map_domain_index,
                    u8 *error)
{
  map_main_t *mm = &map_main;
  u32 mdi = mm->ip6_src_prefix_tbl->lookup(mm->ip6_src_prefix_tbl, addr, 128);
  if (mdi == ~0) {
    *error = MAP_ERROR_NO_DOMAIN;
    return 0;
  }

  *map_domain_index = mdi;
  return pool_elt_at_index(mm->domains, mdi);
}

map_ip4_reass_t *
map_ip4_reass_get(u32 src, u32 dst, u16 fragment_id,
                  u8 protocol, u32 **pi_to_drop);
void
map_ip4_reass_free(map_ip4_reass_t *r, u32 **pi_to_drop);

#define map_ip4_reass_lock() while (clib_atomic_test_and_set (map_main.ip4_reass_lock)) {}
#define map_ip4_reass_unlock() do {CLIB_MEMORY_BARRIER(); *map_main.ip4_reass_lock = 0;} while(0)

static_always_inline void
map_ip4_reass_get_fragments(map_ip4_reass_t *r, u32 **pi)
{
  int i;
  for (i=0; i<MAP_IP4_REASS_MAX_FRAGMENTS_PER_REASSEMBLY; i++)
    if(r->fragments[i] != ~0) {
      vec_add1(*pi, r->fragments[i]);
      r->fragments[i] = ~0;
      map_main.ip4_reass_buffered_counter--;
    }
}

clib_error_t * map_plugin_api_hookup (vlib_main_t * vm);

int map_ip4_reass_add_fragment(map_ip4_reass_t *r, u32 pi);

map_ip6_reass_t *
map_ip6_reass_get(ip6_address_t *src, ip6_address_t *dst, u32 fragment_id,
                  u8 protocol, u32 **pi_to_drop);
void
map_ip6_reass_free(map_ip6_reass_t *r, u32 **pi_to_drop);

#define map_ip6_reass_lock() while (clib_atomic_test_and_set (map_main.ip6_reass_lock)) {}
#define map_ip6_reass_unlock() do {CLIB_MEMORY_BARRIER(); *map_main.ip6_reass_lock = 0;} while(0)

int
map_ip6_reass_add_fragment(map_ip6_reass_t *r, u32 pi,
                           u16 data_offset, u16 next_data_offset,
                           u8 *data_start, u16 data_len);

void map_ip4_drop_pi(u32 pi);

int map_ip4_reass_conf_ht_ratio(f32 ht_ratio, u32 *trashed_reass, u32 *dropped_packets);
#define MAP_IP4_REASS_CONF_HT_RATIO_MAX 100
int map_ip4_reass_conf_pool_size(u16 pool_size, u32 *trashed_reass, u32 *dropped_packets);
#define MAP_IP4_REASS_CONF_POOL_SIZE_MAX (0xfeff)
int map_ip4_reass_conf_lifetime(u16 lifetime_ms);
#define MAP_IP4_REASS_CONF_LIFETIME_MAX 0xffff
int map_ip4_reass_conf_buffers(u32 buffers);
#define MAP_IP4_REASS_CONF_BUFFERS_MAX (0xffffffff)

void map_ip6_drop_pi(u32 pi);


int map_ip6_reass_conf_ht_ratio(f32 ht_ratio, u32 *trashed_reass, u32 *dropped_packets);
#define MAP_IP6_REASS_CONF_HT_RATIO_MAX 100
int map_ip6_reass_conf_pool_size(u16 pool_size, u32 *trashed_reass, u32 *dropped_packets);
#define MAP_IP6_REASS_CONF_POOL_SIZE_MAX (0xfeff)
int map_ip6_reass_conf_lifetime(u16 lifetime_ms);
#define MAP_IP6_REASS_CONF_LIFETIME_MAX 0xffff
int map_ip6_reass_conf_buffers(u32 buffers);
#define MAP_IP6_REASS_CONF_BUFFERS_MAX (0xffffffff)

/*
 * Supports prefix of 96 or 64 (with u-octet)
 */
static_always_inline void
ip4_map_t_embedded_address (map_domain_t *d,
			    ip6_address_t *ip6, const ip4_address_t *ip4)
{
  ASSERT(d->ip6_src_len == 96 || d->ip6_src_len == 64); //No support for other lengths for now
  u8 offset = d->ip6_src_len == 64 ? 9 : 12;
  ip6->as_u64[0] = d->ip6_src.as_u64[0];
  ip6->as_u64[1] = d->ip6_src.as_u64[1];
  clib_memcpy_fast(&ip6->as_u8[offset], ip4, 4);
}

static_always_inline u32
ip6_map_t_embedded_address (map_domain_t *d, ip6_address_t *addr)
{
  ASSERT(d->ip6_src_len == 64 || d->ip6_src_len == 96);
  u32 x;
  u8 offset = d->ip6_src_len == 64 ? 9 : 12;
  clib_memcpy(&x, &addr->as_u8[offset], 4);
  return x;
}

static inline void
map_domain_counter_lock (map_main_t *mm)
{
  if (mm->counter_lock)
    while (clib_atomic_test_and_set (mm->counter_lock))
      /* zzzz */ ;
}
static inline void
map_domain_counter_unlock (map_main_t *mm)
{
  if (mm->counter_lock)
    clib_atomic_release (mm->counter_lock);
}


static_always_inline void
map_send_all_to_node(vlib_main_t *vm, u32 *pi_vector,
                     vlib_node_runtime_t *node, vlib_error_t *error,
                     u32 next)
{
  u32 n_left_from, *from, next_index, *to_next, n_left_to_next;
  //Deal with fragments that are ready
  from = pi_vector;
  n_left_from = vec_len(pi_vector);
  next_index = node->cached_next_index;
  while (n_left_from > 0) {
    vlib_get_next_frame(vm, node, next_index, to_next, n_left_to_next);
    while (n_left_from > 0 && n_left_to_next > 0) {
      u32 pi0 = to_next[0] = from[0];
      from += 1;
      n_left_from -= 1;
      to_next += 1;
      n_left_to_next -= 1;
      vlib_buffer_t *p0 = vlib_get_buffer(vm, pi0);
      p0->error = *error;
      vlib_validate_buffer_enqueue_x1(vm, node, next_index, to_next, n_left_to_next, pi0, next);
    }
    vlib_put_next_frame(vm, node, next_index, n_left_to_next);
  }
}

static_always_inline void
map_mss_clamping (tcp_header_t * tcp, ip_csum_t * sum, u16 mss_clamping)
{
  u8 *data;
  u8 opt_len, opts_len, kind;
  u16 mss;
  u16 mss_value_net = clib_host_to_net_u16(mss_clamping);

  if (!tcp_syn (tcp))
    return;

  opts_len = (tcp_doff (tcp) << 2) - sizeof (tcp_header_t);
  data = (u8 *) (tcp + 1);
  for (; opts_len > 0; opts_len -= opt_len, data += opt_len)
    {
      kind = data[0];

      if (kind == TCP_OPTION_EOL)
        break;
      else if (kind == TCP_OPTION_NOOP)
        {
          opt_len = 1;
          continue;
        }
      else
        {
          if (opts_len < 2)
            return;
          opt_len = data[1];

          if (opt_len < 2 || opt_len > opts_len)
            return;
        }

      if (kind == TCP_OPTION_MSS)
        {
          mss = *(u16 *) (data + 2);
          if (clib_net_to_host_u16 (mss) > mss_clamping)
            {
              *sum =
                ip_csum_update (*sum, mss, mss_value_net, ip4_header_t,
                                length);
              clib_memcpy (data + 2, &mss_value_net, 2);
            }
          return;
        }
    }
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
