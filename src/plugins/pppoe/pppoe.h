/*
 *------------------------------------------------------------------
 * Copyright (c) 2017 Intel and/or its affiliates.
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
 *------------------------------------------------------------------
 */

#ifndef _PPPOE_H
#define _PPPOE_H

#include <vnet/plugin/plugin.h>
#include <vppinfra/lock.h>
#include <vppinfra/error.h>
#include <vppinfra/hash.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/dpo/dpo.h>
#include <vnet/adj/adj_types.h>
#include <vnet/fib/fib_table.h>
#include <vlib/vlib.h>
#include <vppinfra/bihash_8_8.h>


typedef struct
{
  u8 ver_type;
  u8 code;
  u16 session_id;
  u16 length;
  u16 ppp_proto;
} pppoe_header_t;

#define PPPOE_VER_TYPE 0x11
#define PPPOE_PADS 0x65

typedef struct
{
  /* pppoe session_id in HOST byte order */
  u16 session_id;

  /* session client addresses */
  ip46_address_t client_ip;

  /* the index of tx interface for pppoe encaped packet */
  u32 encap_if_index;

  /** FIB indices - inner IP packet lookup here */
  u32 decap_fib_index;

  u8 local_mac[6];
  u8 client_mac[6];

  /* vnet intfc index */
  u32 sw_if_index;
  u32 hw_if_index;

} pppoe_session_t;

#define foreach_pppoe_input_next        \
_(DROP, "error-drop")                  \
_(IP4_INPUT, "ip4-input")              \
_(IP6_INPUT, "ip6-input" )             \
_(CP_INPUT, "pppoe-tap-dispatch" )     \

typedef enum
{
#define _(s,n) PPPOE_INPUT_NEXT_##s,
  foreach_pppoe_input_next
#undef _
    PPPOE_INPUT_N_NEXT,
} pppoe_input_next_t;

typedef enum
{
#define pppoe_error(n,s) PPPOE_ERROR_##n,
#include <pppoe/pppoe_error.def>
#undef pppoe_error
  PPPOE_N_ERROR,
} pppoe_input_error_t;


#define MTU 1500
#define MTU_BUFFERS ((MTU + VLIB_BUFFER_DATA_SIZE - 1) / VLIB_BUFFER_DATA_SIZE)
#define NUM_BUFFERS_TO_ALLOC 32

/*
 * The size of pppoe session table
 */
#define PPPOE_NUM_BUCKETS (128 * 1024)
#define PPPOE_MEMORY_SIZE (16<<20)

/* *INDENT-OFF* */
/*
 * The PPPoE key is the mac address and session ID
 */
typedef struct
{
  union
  {
    struct
    {
      u16 session_id;
      u8 mac[6];
    } fields;
    struct
    {
      u32 w0;
      u32 w1;
    } words;
    u64 raw;
  };
} pppoe_entry_key_t;
/* *INDENT-ON* */

/* *INDENT-OFF* */
/*
 * The PPPoE entry results
 */
typedef struct
{
  union
  {
    struct
    {
      u32 sw_if_index;

      u32 session_index;

    } fields;
    u64 raw;
  };
}  pppoe_entry_result_t;
/* *INDENT-ON* */

typedef struct
{
  /* For DP: vector of encap session instances, */
  pppoe_session_t *sessions;

  /* For CP:  vector of CP path */
    BVT (clib_bihash) session_table;

  /* Free vlib hw_if_indices */
  u32 *free_pppoe_session_hw_if_indices;

  /* Mapping from sw_if_index to session index */
  u32 *session_index_by_sw_if_index;

  /* used for pppoe cp path */
  u32 tap_if_index;

  /* API message ID base */
  u16 msg_id_base;

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;

} pppoe_main_t;

extern pppoe_main_t pppoe_main;

extern vlib_node_registration_t pppoe_input_node;
extern vlib_node_registration_t pppoe_tap_dispatch_node;

typedef struct
{
  u8 is_add;
  u8 is_ip6;
  u16 session_id;
  ip46_address_t client_ip;
  u32 encap_if_index;
  u32 decap_fib_index;
  u8 local_mac[6];
  u8 client_mac[6];
} vnet_pppoe_add_del_session_args_t;

int vnet_pppoe_add_del_session
  (vnet_pppoe_add_del_session_args_t * a, u32 * sw_if_indexp);

typedef struct
{
  u8 is_add;
  u32 client_if_index;
  u32 tap_if_index;
} vnet_pppoe_add_del_tap_args_t;

always_inline u64
pppoe_make_key (u8 * mac_address, u16 session_id)
{
  u64 temp;

  /*
   * The mac address in memory is A:B:C:D:E:F
   * The session_id in register is H:L
   */
#if CLIB_ARCH_IS_LITTLE_ENDIAN
  /*
   * Create the in-register key as F:E:D:C:B:A:H:L
   * In memory the key is L:H:A:B:C:D:E:F
   */
  temp = *((u64 *) (mac_address)) << 16;
  temp = (temp & ~0xffff) | (u64) (session_id);
#else
  /*
   * Create the in-register key as H:L:A:B:C:D:E:F
   * In memory the key is H:L:A:B:C:D:E:F
   */
  temp = *((u64 *) (mac_address)) >> 16;
  temp = temp | (((u64) session_id) << 48);
#endif

  return temp;
}

static_always_inline void
pppoe_lookup_1 (BVT (clib_bihash) * session_table,
		pppoe_entry_key_t * cached_key,
		pppoe_entry_result_t * cached_result,
		u8 * mac0,
		u16 session_id0,
		pppoe_entry_key_t * key0,
		u32 * bucket0, pppoe_entry_result_t * result0)
{
  /* set up key */
  key0->raw = pppoe_make_key (mac0, session_id0);
  *bucket0 = ~0;

  if (key0->raw == cached_key->raw)
    {
      /* Hit in the one-entry cache */
      result0->raw = cached_result->raw;
    }
  else
    {
      /* Do a regular session table lookup */
      BVT (clib_bihash_kv) kv;

      kv.key = key0->raw;
      kv.value = ~0ULL;
      BV (clib_bihash_search_inline) (session_table, &kv);
      result0->raw = kv.value;

      /* Update one-entry cache */
      cached_key->raw = key0->raw;
      cached_result->raw = result0->raw;
    }
}

static_always_inline void
pppoe_update_1 (BVT (clib_bihash) * session_table,
		u8 * mac0,
		u16 session_id0,
		pppoe_entry_key_t * key0,
		u32 * bucket0, pppoe_entry_result_t * result0)
{
  /* set up key */
  key0->raw = pppoe_make_key (mac0, session_id0);
  *bucket0 = ~0;

  /* Update the entry */
  BVT (clib_bihash_kv) kv;
  kv.key = key0->raw;
  kv.value = result0->raw;
  BV (clib_bihash_add_del) (session_table, &kv, 1 /* is_add */ );

}
#endif /* _PPPOE_H */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
