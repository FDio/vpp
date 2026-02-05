/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#ifndef __included_sfdp_h__
#define __included_sfdp_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>

#include <vppinfra/hash.h>
#include <vppinfra/error.h>
#include <vppinfra/elog.h>

#include <vppinfra/bihash_24_8.h>
#include <vppinfra/bihash_48_8.h>
#include <vppinfra/bihash_8_8.h>

#include <vppinfra/format_table.h>

#include <vnet/sfdp/expiry/expiry.h>
#include <vnet/sfdp/common.h>
#include <vnet/sfdp/callbacks.h>

/* Sessions constants */
#define SFDP_DEFAULT_LOG2_SESSIONS 19 /* 500k sessions */
#define SFDP_DEFAULT_LOG2_SESSIONS_CACHE_RATIO                                \
  7				     /* 1/128 cached sessions per thread */
#define SFDP_LOG2_MEM_PER_SESSION 12 /* 4kB per session */

/* Tenants constants */
#define SFDP_DEFAULT_LOG2_TENANTS 15 /* 32k tenants */
#define SFDP_LOG2_MEM_PER_TENANT  6  /* 64B per tenant */

#define SFDP_SESSION_ID_TOTAL_BITS   64
#define SFDP_SESSION_ID_EPOCH_N_BITS 16

#define SFDP_BITMAP_SIZE			64
#define SFDP_LOOKUP_NEXT_INDEX_FOR_SCOPE(scope) (scope + SFDP_BITMAP_SIZE)

/* Convention session_index is 31 bit
 * Flow_index (embedded in vlib_buffer_t as "flow_id")
 * Flow_index = (session_index << 1) + !(is_forward)

 * A flow is "forward" if it's going from initiator to responder
 * The packet_direction is 1 if normalisation happened 0 otherwise
 * the stored_direction of a flow is the packet direction of its FSOL
 * Pseudo_flow_index = (session_index << 1) + stored_direction
 *
 * Note that for a packet belonging to a flow
 * ----------------------------------------------------------
 *     !(is_forward) = packet_direction ^ stored_direction
 *        Flow_index = Pseudo_flow_index ^ stored_direction
 * ----------------------------------------------------------
 */

typedef enum
{
  SFDP_SESSION_TYPE_IP4,
  SFDP_SESSION_TYPE_IP6,
  SFDP_SESSION_TYPE_USER,
  /* last */
  SFDP_SESSION_N_TYPES,
} sfdp_session_type_t;

#define foreach_sfdp_session_state                                            \
  _ (FSOL, "embryonic")                                                       \
  _ (ESTABLISHED, "established")                                              \
  _ (TIME_WAIT, "time-wait")                                                  \
  /* Free session does not belong to main pool anymore, but is unused */      \
  _ (FREE, "free")

typedef enum
{
#define _(val, str) SFDP_SESSION_STATE_##val,
  foreach_sfdp_session_state
#undef _
    SFDP_SESSION_N_STATE
} sfdp_session_state_t;

#define foreach_sfdp_flow_counter _ (LOOKUP, "lookup")

typedef enum
{
#define _(x, y) SFDP_FLOW_COUNTER_##x,
  foreach_sfdp_flow_counter
#undef _
    SFDP_FLOW_N_COUNTER
} sfdp_flow_counter_index_t;

#define foreach_sfdp_tenant_session_counter                                   \
  _ (CREATED, "created", "created sessions")                                  \
  _ (REMOVED, "removed", "removed sessions")

#define foreach_sfdp_tenant_data_counter                                      \
  _ (INCOMING, "incoming", "incoming data into tenant")                       \
  _ (OUTGOING, "outgoing", "outgoing data out of tenant")

typedef enum
{
#define _(x, y, z) SFDP_TENANT_SESSION_COUNTER_##x,
  foreach_sfdp_tenant_session_counter
#undef _
    SFDP_TENANT_SESSION_N_COUNTER
} sfdp_tenant_session_counter_index_t;

typedef enum
{
#define _(x, y, z) SFDP_TENANT_DATA_COUNTER_##x,
  foreach_sfdp_tenant_data_counter
#undef _
    SFDP_TENANT_DATA_N_COUNTER
} sfdp_tenant_data_counter_index_t;

enum
{
  SFDP_FLOW_FORWARD = 0,
  SFDP_FLOW_REVERSE = 1,
  SFDP_FLOW_F_B_N = 2
};

enum
{
  SFDP_SESSION_KEY_PRIMARY,
  SFDP_SESSION_KEY_SECONDARY,
  SFDP_SESSION_N_KEY
};
/* Flags to determine key validity in the session */
#define foreach_sfdp_session_key_flag                                         \
  _ (PRIMARY_VALID_IP4, 0x1, "primary-valid-ip4")                             \
  _ (PRIMARY_VALID_IP6, 0x2, "primary-valid-ip6")                             \
  _ (SECONDARY_VALID_IP4, 0x4, "secondary-valid-ip4")                         \
  _ (SECONDARY_VALID_IP6, 0x8, "secondary-valid-ip6")                         \
  _ (PRIMARY_VALID_USER, 0x10, "primary-valid-user")                          \
  _ (SECONDARY_VALID_USER, 0x20, "secondary-valid-user")

enum
{
#define _(x, n, s) SFDP_SESSION_KEY_FLAG_##x = n,
  foreach_sfdp_session_key_flag
#undef _
};

#define foreach_sfdp_sp_node                                                  \
  _ (IP4_REASS, "error-drop", "sp-ip4-reassembly")                            \
  _ (IP6_REASS, "error-drop", "sp-ip6-reassembly")                            \
  _ (IP4_UNKNOWN_PROTO, "error-drop", "sp-ip4-unknown-proto")                 \
  _ (IP6_UNKNOWN_PROTO, "error-drop", "sp-ip6-unknown-proto")                 \
  _ (IP4_ICMP4_ERROR, "error-drop", "sp-ip4-icmp4-error")                     \
  _ (IP6_ICMP6_ERROR, "error-drop", "sp-ip4-icmp6-error")                     \
  _ (IP4_TABLE_OVERFLOW, "error-drop", "sp-ip4-table-overflow")               \
  _ (IP6_TABLE_OVERFLOW, "error-drop", "sp-ip6-table-overflow")

enum
{
#define _(name, val, str) SFDP_SP_NODE_##name,
  foreach_sfdp_sp_node
#undef _
    SFDP_N_SP_NODES
};

typedef union
{
  struct
  {
    union
    {
      u32 spi;
      struct
      {
	u16 port_lo;
	u16 port_hi;
      };
    };
    u8 unused;
    u8 proto;
    u16 unused2;
    u32 ip_addr_lo;
    u32 ip_addr_hi;
  };
  u8x16u as_u8x16;
  u32x4u as_u32x4;
  u64x2u as_u64x2;
} __clib_packed sfdp_ip4_key_t;
STATIC_ASSERT_SIZEOF (sfdp_ip4_key_t, 16);

typedef union
{
  struct
  {
    union
    {
      u32 spi;
      struct
      {
	u16 port_lo;
	u16 port_hi;
      };
    };
    u16 unused;
    u8 proto;
    u8 unused2;
    ip6_address_t ip6_addr_lo;
    ip6_address_t ip6_addr_hi;
  };
  struct
  {
    u32x2u as_u32x2;
    u32x8u as_u32x8;
  };
  struct
  {
    u16x4u as_u16x4;
    u16x16u as_u16x16;
  };
  struct
  {
    u8x8u as_u8x8;
    u8x16u as_u8x16[2];
  };
  struct
  {
    u64 as_u64;
    u64x4u as_u64x4;
  };
} __clib_packed sfdp_ip6_key_t;
STATIC_ASSERT_SIZEOF (sfdp_ip6_key_t, 40);

typedef struct
{
  sfdp_ip4_key_t ip4_key;

  union
  {
    struct
    {
      u32 context_id;
      u8 zeros[4];
    };
    u64 as_u64;
  };
} __clib_packed sfdp_session_ip4_key_t;
STATIC_ASSERT_SIZEOF (sfdp_session_ip4_key_t, 24);

typedef struct
{
  sfdp_ip6_key_t ip6_key;

  union
  {
    struct
    {
      u32 context_id;
      u8 zeros[4];
    };
    u64 as_u64;
  };
} __clib_packed sfdp_session_ip6_key_t;
STATIC_ASSERT_SIZEOF (sfdp_session_ip6_key_t, 48);

typedef union
{
  sfdp_session_ip4_key_t key4;
  sfdp_session_ip6_key_t key6;
} sfdp_session_ip46_key_t;

typedef union
{
  sfdp_ip4_key_t key4;
  sfdp_ip6_key_t key6;
} sfdp_ip46_key_t;

typedef union
{
  clib_bihash_kv_24_8_t kv4;
  clib_bihash_kv_48_8_t kv6;
} sfdp_bihash_kv46_t;

#define SFDP_SESSION_IP46_KEYS_TYPE(n)                                        \
  union                                                                       \
  {                                                                           \
    sfdp_session_ip4_key_t keys4[(n)];                                        \
    sfdp_session_ip6_key_t keys6[(n)];                                        \
  }

#define SFDP_UNBOUND_THREAD_INDEX ((u16) ~0)
typedef struct sfdp_session
{
  CLIB_CACHE_LINE_ALIGN_MARK (cache0);
  sfdp_bitmap_t bitmaps[SFDP_FLOW_F_B_N];
  u64 session_id;
  u64 expiry_opaque[2];
  sfdp_tenant_index_t tenant_idx;
  session_version_t session_version;
  u8 state; /* see sfdp_session_state_t */
  u8 proto;
  u16 owning_thread_index;
  u8 unused0[14];
  u8 pseudo_dir[SFDP_SESSION_N_KEY];
  u8 type; /* see sfdp_session_type_t */
  u8 key_flags;
  u16 parser_index[SFDP_SESSION_N_KEY];
  u8 scope_index;
  u8 unused1[55];
  CLIB_CACHE_LINE_ALIGN_MARK (cache1);
  union
  {
    sfdp_session_ip46_key_t keys[SFDP_SESSION_N_KEY];
    u8 keys_data[SFDP_SESSION_N_KEY][64];
  };
} sfdp_session_t; /* TODO: optimise mem layout, this is bad */
#if CLIB_CACHE_LINE_BYTES == 64
STATIC_ASSERT ((STRUCT_OFFSET_OF (sfdp_session_t, cache1) -
		STRUCT_OFFSET_OF (sfdp_session_t, cache0)) ==
		 2 * CLIB_CACHE_LINE_BYTES,
	       "cache line alignment is broken for sfdp_session_t");
#else
STATIC_ASSERT ((STRUCT_OFFSET_OF (sfdp_session_t, cache1) -
		STRUCT_OFFSET_OF (sfdp_session_t, cache0)) ==
		 CLIB_CACHE_LINE_BYTES,
	       "cache line alignment is broken for sfdp_session_t");
#endif

/* The members of the second cacheline are bigger than 64 bytes, thus due to
 * the alignment constraints, the struct size depends on the cacheline size. */
#if CLIB_CACHE_LINE_BYTES == 64
STATIC_ASSERT_SIZEOF (sfdp_session_t, 4 * CLIB_CACHE_LINE_BYTES);
#else
STATIC_ASSERT_SIZEOF (sfdp_session_t, 2 * CLIB_CACHE_LINE_BYTES);
#endif

always_inline void *
sfdp_get_session_expiry_opaque (sfdp_session_t *s)
{
  return (void *) s->expiry_opaque;
}

typedef struct
{
  u32 *expired_sessions; // per thread expired session vector
  u64 session_id_ctr;
  u64 session_id_template;
  u32 *session_freelist;
  u32 n_sessions; /* Number of sessions belonging to this thread */
} sfdp_per_thread_data_t;

// TODO: Find a way to abstract, or share, timeout definition.
//       They should be either private to timer.h, or sharable between them.

/* Per-tenant timeout type */

typedef struct sfdp_timeout
{
  const char *name; // Timeout name used to parse config and display
  u32 val;	    // Timeout value used when creating a new tenant
} sfdp_timeout_t;

STATIC_ASSERT_SIZEOF (sfdp_timeout_t[8], 16 * 8);

/* Maximum number of tenant timers configurable */
#define SFDP_MAX_TIMEOUTS 8

typedef struct
{
  sfdp_tenant_id_t tenant_id;
  u32 context_id;
  sfdp_bitmap_t bitmaps[SFDP_FLOW_F_B_N];
  u32 timeouts[SFDP_MAX_TIMEOUTS];
  u32 sp_node_indices[SFDP_N_SP_NODES];
  uword icmp4_lookup_next;
  uword icmp6_lookup_next;

} sfdp_tenant_t;

typedef struct
{
  /* key = (u64) tenant_id; val= (u64) tenant_idx; */
  clib_bihash_8_8_t tenant_idx_by_id;

  /* (sfdp_session_ip4_key_t) -> (thread_index(32 MSB),session_index(31 bits),
   * stored_direction (1 LSB)) */
  clib_bihash_24_8_t table4;

  /* (sfdp_session_ip6_key_t) -> (thread_index(32 MSB),session_index(31 bits),
   * stored_direction (1 LSB)) */
  clib_bihash_48_8_t table6;
  clib_bihash_8_8_t session_index_by_id;
  clib_spinlock_t session_lock;
  sfdp_session_t *sessions; /* fixed pool */
  u32 free_sessions;
  vlib_combined_counter_main_t per_session_ctr[SFDP_FLOW_N_COUNTER];
  u32 *frame_queue_index_per_scope;
  uword *handoff_node_index_per_scope;
  uword *ip4_lookup_node_index_per_scope;
  uword *ip6_lookup_node_index_per_scope;
  uword **parser_node_index_per_scope_per_original;
  u32 icmp4_error_frame_queue_index;
  u32 icmp6_error_frame_queue_index;
  u64 session_id_ctr_mask;
  vlib_simple_counter_main_t tenant_session_ctr[SFDP_TENANT_SESSION_N_COUNTER];
  vlib_combined_counter_main_t tenant_data_ctr[SFDP_TENANT_DATA_N_COUNTER];

  /* pool of tenants */
  sfdp_tenant_t *tenants;

  /* per-thread data */
  sfdp_per_thread_data_t *per_thread_data;
  u16 msg_id_base;
  sfdp_expiry_callbacks_t expiry_callbacks;

  /* Timer names and defaults.
   * Timers with name equal to NULL are not configured. */
  sfdp_timeout_t timeouts[SFDP_MAX_TIMEOUTS];

  u32 log2_sessions;
  u32 log2_sessions_cache_per_thread;
  u32 log2_tenants;

  /* Per-thread number of sessions margin before eviction.
   * See sfdp_set_eviction_sessions_margin function more information. */
  u32 eviction_sessions_margin;

  /* If this is set, don't run polling nodes on main */
  int no_main;
} sfdp_main_t;

typedef struct
{
  u32 scope_index;
} sfdp_lookup_node_runtime_data_t;

#define sfdp_foreach_timeout(sfdp, timeout)                                   \
  for (timeout = (sfdp)->timeouts;                                            \
       timeout < (sfdp)->timeouts + SFDP_MAX_TIMEOUTS; timeout++)

#define sfdp_foreach_session(sfdp, i, s)                                      \
  pool_foreach_index (i, (sfdp)->sessions)                                    \
    if ((s = sfdp_session_at_index (i)) && s->state != SFDP_SESSION_STATE_FREE)

extern sfdp_main_t sfdp_main;
extern vlib_node_registration_t sfdp_handoff_node;
extern vlib_node_registration_t sfdp_lookup_ip4_icmp_node;
extern vlib_node_registration_t sfdp_lookup_ip6_icmp_node;
extern vlib_node_registration_t sfdp_lookup_ip4_node;
extern vlib_node_registration_t sfdp_lookup_ip6_node;
format_function_t format_sfdp_session;
format_function_t format_sfdp_ipv4_context_id;
format_function_t format_sfdp_ipv4_ingress;
format_function_t format_sfdp_ipv4_egress;
format_function_t format_sfdp_ipv6_context_id;
format_function_t format_sfdp_ipv6_ingress;
format_function_t format_sfdp_ipv6_egress;
format_function_t format_sfdp_session_detail;
format_function_t format_sfdp_session_state;
format_function_t format_sfdp_session_type;
format_function_t format_sfdp_tenant;
format_function_t format_sfdp_tenant_extra;
format_function_t format_sfdp_sp_node;
unformat_function_t unformat_sfdp_service;
unformat_function_t unformat_sfdp_service_bitmap;
unformat_function_t unformat_sfdp_sp_node;
unformat_function_t unformat_sfdp_timeout_name;

static_always_inline u64
sfdp_num_sessions ()
{
  return (1ULL << (sfdp_main.log2_sessions));
}

static_always_inline u64
sfdp_num_sessions_cache_per_thread ()
{
  return (1ULL << (sfdp_main.log2_sessions_cache_per_thread));
}

static_always_inline int
sfdp_table_is_full ()
{
  /* Note: We use >= to be on the safe side... */
  return pool_elts (sfdp_main.sessions) >= sfdp_num_sessions ();
}

static_always_inline u64
sfdp_real_active_sessions ()
{
  u64 sessions = pool_elts (sfdp_main.sessions);
  sfdp_per_thread_data_t *ptd;
  vec_foreach (ptd, sfdp_main.per_thread_data)
    {
      sessions -= vec_len (ptd->session_freelist);
    }
  return sessions;
}

// Number of sessions that can be allocated by threads in the global pool
static_always_inline u64
sfdp_remaining_sessions_in_pool ()
{
  return sfdp_num_sessions () - pool_elts (sfdp_main.sessions);
}

// Return the number of sessions that this thread should be able to allocate
static_always_inline u64
sfdp_sessions_available_for_this_thread (sfdp_per_thread_data_t *ptd)
{
  return sfdp_remaining_sessions_in_pool () + vec_len (ptd->session_freelist);
}

static_always_inline u64
sfdp_session_num_thread_factor ()
{
  u32 n_workers = vlib_num_workers ();
  return n_workers ? n_workers : 1;
}

static_always_inline u64
sfdp_ip4_num_buckets ()
{
  return (1ULL << (sfdp_main.log2_sessions - 1));
}

static_always_inline u64
sfdp_ip4_mem_size ()
{
  return (1ULL << (sfdp_main.log2_sessions + SFDP_LOG2_MEM_PER_SESSION));
}

static_always_inline u64
sfdp_ip6_num_buckets ()
{
  return (1ULL << (sfdp_main.log2_sessions - 1));
}

static_always_inline u64
sfdp_ip6_mem_size ()
{
  return (1ULL << (sfdp_main.log2_sessions + SFDP_LOG2_MEM_PER_SESSION));
}

static_always_inline u64
sfdp_tenant_num_buckets ()
{
  return (1ULL << (sfdp_main.log2_tenants - 2));
}

static_always_inline u64
sfdp_tenant_mem_size ()
{
  return (1ULL << (sfdp_main.log2_tenants + SFDP_LOG2_MEM_PER_TENANT));
}

static_always_inline sfdp_per_thread_data_t *
sfdp_get_per_thread_data (u32 thread_index)
{
  return vec_elt_at_index (sfdp_main.per_thread_data, thread_index);
}

static_always_inline u32
sfdp_session_index_from_lookup (u64 val)
{
  return (val & (~(u32) 0)) >> 1;
}

static_always_inline u8
sfdp_thread_index_from_lookup (u64 val)
{
  return (val >> 32) & 0xFF;
}

static_always_inline u16
sfdp_session_version_from_lookup (u64 val)
{
  return (val >> 48);
}

static_always_inline u32
sfdp_packet_dir_from_lookup (u64 val)
{
  return val & 0x1;
}

static_always_inline u32
sfdp_pseudo_flow_index_from_lookup (u64 val)
{
  return val & (~(u32) 0);
}

/** The format of the lookup value is composed of
 *  1. 16 bits of session version
 *  (8 bits of padding)
 *  2. 8 bits of thread index
 *  3. 32 bits of pseudo flow index
 **/
static_always_inline u64
sfdp_session_mk_table_value (u8 thread_index, u32 pseudo_flow_index,
			     session_version_t session_version)
{
  u64 value = 0;
  value |= ((u64) session_version) << 48;
  value |= ((u64) thread_index) << 32;
  value |= (u64) pseudo_flow_index;
  return value;
}

static_always_inline sfdp_session_t *
sfdp_session_at_index (u32 idx)
{
  return pool_elt_at_index (sfdp_main.sessions, idx);
}

static_always_inline sfdp_session_t *
sfdp_session_at_index_no_check (u32 idx)
{
  return sfdp_main.sessions + idx;
}

static_always_inline int
sfdp_session_at_index_is_active (u32 idx)
{
  // TODO: We could use SFDP_SESSION_STATE_FREE alone maybe if its value was
  // zero.
  sfdp_main_t *sfdp = &sfdp_main;
  return (!pool_is_free_index (sfdp->sessions, idx)) &&
	 (sfdp->sessions[idx].state != SFDP_SESSION_STATE_FREE);
}

static_always_inline sfdp_session_t *
sfdp_session_at_index_if_valid (u32 idx)
{
  return sfdp_session_at_index_is_active (idx) ? sfdp_session_at_index (idx) :
						 NULL;
}

static_always_inline u32
sfdp_mk_flow_index (u32 session_index, u8 dir)
{
  return (session_index << 1) | !(dir == SFDP_FLOW_FORWARD);
}

static_always_inline u32
sfdp_session_from_flow_index (u32 flow_index)
{
  return flow_index >> 1;
}

static_always_inline u32
sfdp_direction_from_flow_index (u32 flow_index)
{
  return (flow_index & 0x1);
}

static_always_inline sfdp_tenant_t *
sfdp_tenant_at_index (sfdp_main_t *sfdpm, u32 idx)
{
  return pool_elt_at_index (sfdpm->tenants, idx);
}

static_always_inline u8
sfdp_session_n_keys (sfdp_session_t *session)
{
  if (session->key_flags & (SFDP_SESSION_KEY_FLAG_SECONDARY_VALID_IP4 |
			    SFDP_SESSION_KEY_FLAG_SECONDARY_VALID_IP6))
    return 2;
  else
    return 1;
}

static_always_inline void
sfdp_notify_new_sessions (sfdp_main_t *sfdpm, u32 *new_sessions, u32 len)
{
  sfdpm->expiry_callbacks.notify_new_sessions (new_sessions, len);
  SFDP_CALLBACKS_CALL (notify_new_sessions, new_sessions, len);
}

static_always_inline void
sfdp_notify_deleted_sessions (sfdp_main_t *sfdpm, u32 *deleted_sessions,
			      u32 len)
{
  SFDP_CALLBACKS_CALL (notify_deleted_sessions, deleted_sessions, len);
}

static_always_inline u32
sfdp_alloc_session (sfdp_main_t *sfdp, sfdp_per_thread_data_t *ptd,
		    bool bound_to_thread)
{
  u32 res = ~0;
  u32 n_local_elem;
  sfdp_session_t *session;

  if (bound_to_thread)
    n_local_elem = vec_len (ptd->session_freelist);

  if (bound_to_thread && n_local_elem)
    res = vec_pop (ptd->session_freelist);
  else
    {
      clib_spinlock_lock_if_init (&sfdp->session_lock);
      if (sfdp->free_sessions)
	{
	  pool_get (sfdp->sessions, session);
	  sfdp->free_sessions -= 1;
	  clib_spinlock_unlock_if_init (&sfdp->session_lock);
	  res = session - sfdp->sessions;
	}
      else
	clib_spinlock_unlock_if_init (&sfdp->session_lock);
    }
  if (bound_to_thread && res != ~0)
    ptd->n_sessions += 1;
  return res;
}

static_always_inline void
sfdp_free_session (sfdp_main_t *sfdp, sfdp_per_thread_data_t *ptd,
		   u32 session_index)
{
  if (ptd &&
      vec_len (ptd->session_freelist) < sfdp_num_sessions_cache_per_thread ())
    vec_add1 (ptd->session_freelist, session_index);
  else
    {
      clib_spinlock_lock_if_init (&sfdp->session_lock);
      pool_put_index (sfdp->sessions, session_index);
      sfdp->free_sessions += 1;
      clib_spinlock_unlock_if_init (&sfdp->session_lock);
    }
  if (ptd)
    ptd->n_sessions -= 1;
}

static_always_inline void
sfdp_session_generate_and_set_id (sfdp_main_t *sfdp,
				  sfdp_per_thread_data_t *ptd,
				  sfdp_session_t *session)
{
  clib_bihash_kv_8_8_t kv2;
  u64 value;
  u32 session_idx = session - sfdp->sessions;
  u32 pseudo_flow_idx = (session_idx << 1);
  u32 thread_index = session->owning_thread_index;
  u64 session_id = (ptd->session_id_ctr & (sfdp->session_id_ctr_mask)) |
		   ptd->session_id_template;
  ptd->session_id_ctr +=
    2; /* two at a time, because last bit is reserved for direction */
  session->session_id = session_id;
  value = sfdp_session_mk_table_value (thread_index, pseudo_flow_idx,
				       session->session_version);
  kv2.key = session_id;
  kv2.value = value;
  clib_bihash_add_del_8_8 (&sfdp->session_index_by_id, &kv2, 1);
}

/* Internal function to create a new session.
 * sfdp_notify_new_sessions must be called afterward. If thread_index is ~0,
 * the session is created with no assigned thread
 * Return value: 0 --> SUCCESS
		 1 --> Unable to allocate session
		 2 --> Collision */
static_always_inline int
sfdp_create_session_inline (sfdp_main_t *sfdp, sfdp_per_thread_data_t *ptd, sfdp_tenant_t *tenant,
			    sfdp_tenant_index_t tenant_idx, u16 thread_index, f64 time_now, void *k,
			    u64 *h, u64 *lookup_val, u32 scope_index, int is_ipv6)
{
  sfdp_bihash_kv46_t kv = {};
  u64 value;
  u8 proto;
  sfdp_session_t *session;
  u32 session_idx;
  u32 pseudo_flow_idx;

  session_idx =
    sfdp_alloc_session (sfdp, ptd, thread_index != SFDP_UNBOUND_THREAD_INDEX);

  if (session_idx == ~0)
    return 1;

  session = pool_elt_at_index (sfdp->sessions, session_idx);

  pseudo_flow_idx = (lookup_val[0] & 0x1) | (session_idx << 1);
  value = sfdp_session_mk_table_value (thread_index, pseudo_flow_idx,
				       session->session_version + 1);
  if (is_ipv6)
    {
      clib_memcpy_fast (&kv.kv6.key, k, sizeof (kv.kv6.key));
      kv.kv6.value = value;
      proto = ((sfdp_session_ip6_key_t *) k)->ip6_key.proto;
      if (clib_bihash_add_del_48_8 (&sfdp->table6, &kv.kv6, 2))
	{
	  /* colision - remote thread created same entry */
	  sfdp_free_session (sfdp, ptd, session_idx);
	  return 2;
	}
      session->type = SFDP_SESSION_TYPE_IP6;
      session->key_flags = SFDP_SESSION_KEY_FLAG_PRIMARY_VALID_IP6;
    }
  else
    {
      clib_memcpy_fast (&kv.kv4.key, k, sizeof (kv.kv4.key));
      kv.kv4.value = value;
      proto = ((sfdp_session_ip4_key_t *) k)->ip4_key.proto;
      if (clib_bihash_add_del_24_8 (&sfdp->table4, &kv.kv4, 2))
	{
	  /* colision - remote thread created same entry */
	  sfdp_free_session (sfdp, ptd, session_idx);
	  return 2;
	}
      session->type = SFDP_SESSION_TYPE_IP4;
      session->key_flags = SFDP_SESSION_KEY_FLAG_PRIMARY_VALID_IP4;
    }
  // TODO: Would be nice to do this upon free instead to have avoid having to
  // check
  //       if the session is valid at all when checking invalidation.
  session->session_version += 1;
  session->tenant_idx = tenant_idx;
  session->state = SFDP_SESSION_STATE_FSOL;
  session->owning_thread_index = thread_index;
  session->scope_index = scope_index;
  if (ptd)
    sfdp_session_generate_and_set_id (sfdp, ptd, session);

  clib_memcpy_fast (session->bitmaps, tenant->bitmaps,
		    sizeof (session->bitmaps));
  if (is_ipv6)
    clib_memcpy_fast (&session->keys[SFDP_SESSION_KEY_PRIMARY].key6, k,
		      sizeof (session->keys[0].key6));
  else
    clib_memcpy_fast (&session->keys[SFDP_SESSION_KEY_PRIMARY].key4, k,
		      sizeof (session->keys[0].key4));
  session->pseudo_dir[SFDP_SESSION_KEY_PRIMARY] = lookup_val[0] & 0x1;
  session->proto = proto;

  lookup_val[0] ^= value;
  /* Bidirectional counter zeroing */
  vlib_zero_combined_counter (&sfdp->per_session_ctr[SFDP_FLOW_COUNTER_LOOKUP],
			      lookup_val[0]);
  vlib_zero_combined_counter (&sfdp->per_session_ctr[SFDP_FLOW_COUNTER_LOOKUP],
			      lookup_val[0] | 0x1);
  vlib_increment_simple_counter (
    &sfdp->tenant_session_ctr[SFDP_TENANT_SESSION_COUNTER_CREATED],
    thread_index, tenant_idx, 1);
  return 0;
}
int sfdp_create_session (vlib_main_t *vm, vlib_buffer_t *b, u32 context_id,
			 u32 thread_index, u32 tenant_index,
			 u32 *session_index, int is_ipv6);
int sfdp_create_session_with_scope_index (vlib_main_t *vm, vlib_buffer_t *b,
					  u32 context_id, u32 thread_index,
					  u32 tenant_index, u32 *session_index,
					  u32 scope_index, int is_ipv6);

clib_error_t *sfdp_tenant_add_del (sfdp_main_t *sfdp, sfdp_tenant_id_t tenant_id, u32 context_id,
				   u8 is_del);
clib_error_t *sfdp_set_services (sfdp_main_t *sfdp, sfdp_tenant_id_t tenant_id,
				 sfdp_bitmap_t bitmap, u8 direction);
clib_error_t *sfdp_set_timeout (sfdp_main_t *sfdp, sfdp_tenant_id_t tenant_id, u32 timeout_idx,
				u32 timeout_val);

clib_error_t *sfdp_set_sp_node (sfdp_main_t *sfdp, sfdp_tenant_id_t tenant_id, u32 sp_index,
				u32 node_index);
clib_error_t *sfdp_set_icmp_error_node (sfdp_main_t *sfdp, sfdp_tenant_id_t tenant_id, u8 is_ip6,
					u32 node_index);
clib_error_t *sfdp_kill_session (sfdp_main_t *sfdp, u32 session_index, u8 is_all);
void sfdp_normalise_ip4_key (sfdp_session_t *session,
			     sfdp_session_ip4_key_t *result, u8 key_idx);

void sfdp_normalise_ip6_key (sfdp_session_t *session,
			     sfdp_session_ip6_key_t *result, u8 key_idx);

void sfdp_table_format_add_header_col (table_t *t);
u32 sfdp_table_format_insert_session (table_t *t, u32 n, u32 session_index, sfdp_session_t *session,
				      sfdp_tenant_id_t tenant_id, f64 now);
int sfdp_bihash_add_del_inline_with_hash_24_8 (clib_bihash_24_8_t *h,
					       clib_bihash_kv_24_8_t *kv,
					       u64 hash, u8 is_add);

int sfdp_bihash_add_del_inline_with_hash_48_8 (clib_bihash_48_8_t *h,
					       clib_bihash_kv_48_8_t *kv,
					       u64 hash, u8 is_add);

void sfdp_ip4_full_reass_custom_context_register_next_node (u16 node_index);
void sfdp_ip6_full_reass_custom_context_register_next_node (u16 node_index);
void
sfdp_ip4_full_reass_custom_context_register_next_err_node (u16 node_index);
void
sfdp_ip6_full_reass_custom_context_register_next_err_node (u16 node_index);

#define SFDP_CORE_PLUGIN_BUILD_VER "1.0"

#endif /* __included_sfdp_h__ */
