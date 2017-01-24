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
#ifndef included_vnet_vxlan_h
#define included_vnet_vxlan_h

#include <vppinfra/error.h>
#include <vppinfra/hash.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/l2/l2_input.h>
#include <vnet/l2/l2_output.h>
#include <vnet/l2/l2_bd.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/vxlan/vxlan_packet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/ip/udp.h>
#include <vnet/dpo/dpo.h>
#include <vnet/adj/adj_types.h>

//utils
typedef struct {} false_;

#define conditional(V, T, F) _Generic((1 ? (false_*)0 : (void*)(V)), false_*: (F), default: (T))
#define static_assert_type(v, T) _Static_assert(_Generic((v), T: 1, default: 0), #v " Expected type:" #T)

//access
//hash_xxx_mem + key allocator
typedef struct {} mem;
//hash_xxx - small key optimization
typedef struct {} raw;

typedef struct {} key_uword_pad;
typedef struct {} key_dont_pad;

//key alloc
typedef struct {} key_mem;

//storage
typedef union { void * hash; } storage_t;

//aspect calcs
//small key optimization upto sizeof uword
//sizeof(K) < sizeof(uword) adds copy + zero padding
#define key_access(K) conditional(sizeof(K) <= sizeof(uword), (raw){}, (mem){})
#define key_access_t(K) typeof( key_access(K) )
#define key_pad(K) conditional(sizeof(K) < sizeof(uword), (key_uword_pad){}, (key_dont_pad){})
#define key_pad_t(K) typeof( key_pad(K) )

//tests
static_assert_type(key_access(char), raw);
static_assert_type(key_pad(char), key_uword_pad);
static_assert_type(key_access(uword), raw);
static_assert_type(key_pad(uword), key_dont_pad);
typedef struct { int a,b,c; } abc;
static_assert_type(key_access(abc), mem);

//aspects
#define hashmap_(K, V, KA) \
  union { storage_t s; K * key_ptr; V * value_ptr; key_access_t(K) * access; KA * key_alloc; key_pad_t(K) * pad; }

#define hashmap(K, V) hashmap_(K, V, key_mem)

//key allocator
static size_t
hash_key_size(void * h) { return hash_header(h)->user; }

static void * __attribute__((used))
hash_key_mem_clone (void * h, void * key) {
        size_t ksz = hash_key_size (h);
        void * copy = clib_mem_alloc (ksz);
	clib_memcpy (copy, key, ksz);
	return copy;
}

#define hashmap_key_clone(hm, k) \
  _Generic( (*(hm)->key_alloc), \
    key_mem: hash_key_mem_clone((hm)->s.hash, k) )

#define hashmap_key_free(hm, k) \
  _Generic( (*(hm)->key_alloc), \
    key_mem: clib_mem_free(k) )

//key pad
#define hashmap_key_pad(hm, k) \
  _Generic( (*(hm)->pad), \
    key_uword_pad: ({ union { uword u; typeof(*(hm)->key_ptr) key; } x = { .u = 0 }; x.key = *(k); x.u; }),  \
    key_dont_pad: ({ *(uword*)(k); }) )

//init
#define hashmap_init(hm) \
  _Generic( (*(hm)->access), \
    mem: (hm)->s.hash = hash_create_mem(0, sizeof *(hm)->key_ptr, sizeof *(hm)->value_ptr), \
    raw: (hm)->s.hash = 0 )

//get
#define hashmap_get(hm, k) \
  _Generic( (*(hm)->access), \
    mem: hash_get_mem((hm)->s.hash, k), \
    raw: hash_get((hm)->s.hash, hashmap_key_pad(hm, k)) )

//set
#define hashmap_set(hm, k, v) \
  _Generic( (*(hm)->access), \
    mem: hash_set_mem((hm)->s.hash, hashmap_key_clone(hm, k), v), \
    raw: hash_set((hm)->s.hash, hashmap_key_pad(hm, k), v))

    //mem: ({ typeof((hm)->key_ptr) c = hashmap_key_clone(hm, k); clib_warning("k:%p c:%p", k, c); ASSERT(hash_key_size((hm)->s.hash) == sizeof *(hm)->key_ptr); ASSERT(c != k && memcmp(c, k, sizeof *(hm)->key_ptr) == 0); hash_set_mem((hm)->s.hash, c, v); }),

//unset
static void * __attribute__((used))
hash_stored_key (void * h, void * key) {
	hash_pair_t * hp = hash_get_pair_mem (h, key);
	ASSERT (hp);
	return uword_to_pointer (hp->key, void *);
}

#define hashmap_stored_key(hm, k) \
    (typeof((hm)->key_ptr)) hash_stored_key((hm)->s.hash, k)

#define hashmap_unset_mem(hm, k) ({ \
           typeof((hm)->key_ptr) s = hashmap_stored_key(hm, k);  \
	   hash_unset_mem((hm)->s.hash, (void *)s); \
	   hashmap_key_free(hm, s); \
	   })

#define hashmap_unset(hm, k) ({ do {  \
  _Generic( (*(hm)->access), \
    mem: hashmap_unset_mem(hm, k), \
    raw: hash_unset((hm)->s.hash, hashmap_key_pad(hm, k)) ); \
} while(0); })

//hashmap ends

typedef CLIB_PACKED (struct {
  ip4_header_t ip4;            /* 20 bytes */
  udp_header_t udp;            /* 8 bytes */
  vxlan_header_t vxlan;        /* 8 bytes */
}) ip4_vxlan_header_t;

typedef CLIB_PACKED (struct {
  ip6_header_t ip6;            /* 40 bytes */
  udp_header_t udp;            /* 8 bytes */
  vxlan_header_t vxlan;        /* 8 bytes */
}) ip6_vxlan_header_t;

typedef CLIB_PACKED(struct {
  /* 
   * Key fields: ip src and vxlan vni on incoming VXLAN packet
   * all fields in NET byte order
   */
  union {
    struct {
      u32 src;
      u32 vni;                 /* shifted left 8 bits */
    };
    u64 as_u64;
  };
}) vxlan4_tunnel_key_t;

typedef CLIB_PACKED(struct {
  /*
   * Key fields: ip src and vxlan vni on incoming VXLAN packet
   * all fields in NET byte order
   */
  ip6_address_t src;
  u32 vni;                 /* shifted left 8 bits */
}) vxlan6_tunnel_key_t;

typedef struct {
  /* Rewrite string. $$$$ embed vnet_rewrite header */
  u8 * rewrite;

  /* FIB DPO for IP forwarding of VXLAN encap packet */
  dpo_id_t next_dpo;  

  /* vxlan VNI in HOST byte order */
  u32 vni;

  /* tunnel src and dst addresses */
  ip46_address_t src;
  ip46_address_t dst;

  /* mcast packet output intfc index (used only if dst is mcast) */
  u32 mcast_sw_if_index;

  /* decap next index */
  u32 decap_next_index;

  /* The FIB index for src/dst addresses */
  u32 encap_fib_index;

  /* vnet intfc index */
  u32 sw_if_index;
  u32 hw_if_index;

  /**
   * Linkage into the FIB object graph
   */
  fib_node_t node;

  /*
   * The FIB entry for (depending on VXLAN tunnel is unicast or mcast)
   * sending unicast VXLAN encap packets or receiving mcast VXLAN packets
   */
  fib_node_index_t fib_entry_index;
  adj_index_t mcast_adj_index;

  /**
   * The tunnel is a child of the FIB entry for its desintion. This is
   * so it receives updates when the forwarding information for that entry
   * changes.
   * The tunnels sibling index on the FIB entry's dependency list.
   */
  u32 sibling_index;
} vxlan_tunnel_t;

#define foreach_vxlan_input_next        \
_(DROP, "error-drop")                   \
_(L2_INPUT, "l2-input")

typedef enum {
#define _(s,n) VXLAN_INPUT_NEXT_##s,
  foreach_vxlan_input_next
#undef _
  VXLAN_INPUT_N_NEXT,
} vxlan_input_next_t;

typedef enum {
#define vxlan_error(n,s) VXLAN_ERROR_##n,
#include <vnet/vxlan/vxlan_error.def>
#undef vxlan_error
  VXLAN_N_ERROR,
} vxlan_input_error_t;

typedef struct {
  /* vector of encap tunnel instances */
  vxlan_tunnel_t * tunnels;

  /* lookup tunnel by key */
  hashmap(vxlan4_tunnel_key_t, uword) vxlan4_tunnel_by_key; /* keyed on ipv4.dst + vni */
  hashmap(vxlan6_tunnel_key_t, uword) vxlan6_tunnel_by_key; /* keyed on ipv6.dst + vni */

  /* local VTEP IPs ref count used by vxlan-bypass node to check if
     received VXLAN packet DIP matches any local VTEP address */
  hashmap(ip4_address_t, uword) vtep4;  /* local ip4 VTEPs keyed on their ip4 addr */
  hashmap(ip6_address_t, uword) vtep6;  /* local ip6 VTEPs keyed on their ip6 addr */

  /* mcast shared info */
  hashmap(ip46_address_t, uword) mcast_shared; /* keyed on mcast ip46 addr */

  /* Free vlib hw_if_indices */
  u32 * free_vxlan_tunnel_hw_if_indices;

  /* Mapping from sw_if_index to tunnel index */
  u32 * tunnel_index_by_sw_if_index;

  /* convenience */
  vlib_main_t * vlib_main;
  vnet_main_t * vnet_main;
} vxlan_main_t;

vxlan_main_t vxlan_main;

static_assert_type(*vxlan_main.vxlan4_tunnel_by_key.access, raw);
static_assert_type(*vxlan_main.vxlan6_tunnel_by_key.access, mem);

extern vlib_node_registration_t vxlan4_input_node;
extern vlib_node_registration_t vxlan6_input_node;
extern vlib_node_registration_t vxlan4_encap_node;
extern vlib_node_registration_t vxlan6_encap_node;

u8 * format_vxlan_encap_trace (u8 * s, va_list * args);

typedef struct {
  u8 is_add;

  /* we normally use is_ip4, but since this adds to the
   * structure, this seems less of abreaking change */
  u8 is_ip6;
  ip46_address_t src, dst;
  u32 mcast_sw_if_index;
  u32 encap_fib_index;
  u32 decap_next_index;
  u32 vni;
} vnet_vxlan_add_del_tunnel_args_t;

int vnet_vxlan_add_del_tunnel 
(vnet_vxlan_add_del_tunnel_args_t *a, u32 * sw_if_indexp);

#endif /* included_vnet_vxlan_h */
