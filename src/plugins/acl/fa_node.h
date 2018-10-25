#ifndef _FA_NODE_H_
#define _FA_NODE_H_

#include <stddef.h>
#include <vppinfra/bihash_16_8.h>
#include <vppinfra/bihash_40_8.h>

#include <plugins/acl/exported_types.h>

// #define FA_NODE_VERBOSE_DEBUG 3

#define TCP_FLAG_FIN    0x01
#define TCP_FLAG_SYN    0x02
#define TCP_FLAG_RST    0x04
#define TCP_FLAG_PUSH   0x08
#define TCP_FLAG_ACK    0x10
#define TCP_FLAG_URG    0x20
#define TCP_FLAG_ECE    0x40
#define TCP_FLAG_CWR    0x80
#define TCP_FLAGS_RSTFINACKSYN (TCP_FLAG_RST + TCP_FLAG_FIN + TCP_FLAG_SYN + TCP_FLAG_ACK)
#define TCP_FLAGS_ACKSYN (TCP_FLAG_SYN + TCP_FLAG_ACK)

#define ACL_FA_CONN_TABLE_DEFAULT_HASH_NUM_BUCKETS (64 * 1024)
#define ACL_FA_CONN_TABLE_DEFAULT_HASH_MEMORY_SIZE (1ULL<<30)
#define ACL_FA_CONN_TABLE_DEFAULT_MAX_ENTRIES 500000

typedef union {
  u64 as_u64;
  struct {
    u32 lc_index;
    u16 mask_type_index_lsb;
    u8 tcp_flags;
    u8 tcp_flags_valid:1;
    u8 l4_valid:1;
    u8 is_nonfirst_fragment:1;
    u8 is_ip6:1;
    u8 flags_reserved:4;
  };
} fa_packet_info_t;

typedef enum {
  FA_SK_L4_FLAG_IS_INPUT    = (1 << 0),
  FA_SK_L4_FLAG_IS_SLOWPATH = (1 << 1),
} fa_session_l4_key_l4_flags_t;

typedef union {
  u64 as_u64;
  struct {
    u16 port[2];
    union {
      struct {
        u8 proto;
        u8 l4_flags;
        u16 lsb_of_sw_if_index;
      };
      u32 non_port_l4_data;
    };
  };
} fa_session_l4_key_t;


static_always_inline
int is_session_l4_key_u64_slowpath(u64 l4key) {
  fa_session_l4_key_t k = { .as_u64 = l4key };
  return (k.l4_flags & FA_SK_L4_FLAG_IS_SLOWPATH) ? 1 : 0;
}

typedef union {
  struct {
    union {
      struct {
        /* we put the IPv4 addresses
           after padding so we can still
           use them as (shorter) key together with
           L4 info */
        u32 l3_zero_pad[6];
        ip4_address_t ip4_addr[2];
      };
      ip6_address_t ip6_addr[2];
    };
    fa_session_l4_key_t l4;
    /* This field should align with u64 value in bihash_40_8 and bihash_16_8 keyvalue struct */
    fa_packet_info_t pkt;
  };
  clib_bihash_kv_40_8_t kv_40_8;
  struct {
    u64 padding_for_kv_16_8[3];
    clib_bihash_kv_16_8_t kv_16_8;
  };
} fa_5tuple_t;

static_always_inline u8 *
format_fa_session_l4_key(u8 * s, va_list * args)
{
  fa_session_l4_key_t *l4 = va_arg (*args, fa_session_l4_key_t *);
  int is_input = (l4->l4_flags & FA_SK_L4_FLAG_IS_INPUT) ? 1 : 0;
  int is_slowpath = (l4->l4_flags & FA_SK_L4_FLAG_IS_SLOWPATH) ? 1 : 0;

  return (format (s, "l4 lsb_of_sw_if_index %d proto %d l4_is_input %d l4_slow_path %d l4_flags 0x%02x port %d -> %d",
                  l4->lsb_of_sw_if_index,
                  l4->proto, is_input, is_slowpath,
                  l4->l4_flags, l4->port[0], l4->port[1]));
}

typedef struct {
  fa_5tuple_t info; /* (5+1)*8 = 48 bytes */
  u64 last_active_time;   /* +8 bytes = 56 */
  u32 sw_if_index;        /* +4 bytes = 60 */
  union {
    u8 as_u8[2];
    u16 as_u16;
  } tcp_flags_seen; ;     /* +2 bytes = 62 */
  u16 thread_index;          /* +2 bytes = 64 */
  u64 link_enqueue_time;  /* 8 byte = 8 */
  u32 link_prev_idx;      /* +4 bytes = 12 */
  u32 link_next_idx;      /* +4 bytes = 16 */
  u8 link_list_id;        /* +1 bytes = 17 */
  u8 deleted;             /* +1 bytes = 18 */
  u8 is_ip6;              /* +1 bytes = 19 */
  u8 reserved1[5];        /* +5 bytes = 24 */
  u64 n_packets;          /* +8 bytes = 32 */
  u64 n_bytes;            /* +8 bytes = 40 */
  u64 reserved2[3];       /* +3*8 bytes = 64 */
} fa_session_t;

#define FA_POLICY_EPOCH_MASK 0x7fff
/* input policy epochs have the MSB set */
#define FA_POLICY_EPOCH_IS_INPUT 0x8000


/* This structure is used to fill in the u64 value
   in the per-sw-if-index hash table */
typedef struct {
  union {
    u64 as_u64;
    struct {
      u32 session_index;
      u16 thread_index;
      u16 intf_policy_epoch;
    };
  };
} fa_full_session_id_t;

/*
 * A few compile-time constraints on the size and the layout of the union, to ensure
 * it makes sense both for bihash and for us.
 */

#define CT_ASSERT_EQUAL(name, x,y) typedef int assert_ ## name ## _compile_time_assertion_failed[((x) == (y))-1]
CT_ASSERT_EQUAL(fa_l3_key_size_is_40, offsetof(fa_5tuple_t, pkt), offsetof(clib_bihash_kv_40_8_t, value));
CT_ASSERT_EQUAL(fa_ip6_kv_val_at_pkt, offsetof(fa_5tuple_t, pkt), offsetof(fa_5tuple_t, kv_40_8.value));
CT_ASSERT_EQUAL(fa_ip4_kv_val_at_pkt, offsetof(fa_5tuple_t, pkt), offsetof(fa_5tuple_t, kv_16_8.value));
CT_ASSERT_EQUAL(fa_l4_key_t_is_8, sizeof(fa_session_l4_key_t), sizeof(u64));
CT_ASSERT_EQUAL(fa_packet_info_t_is_8, sizeof(fa_packet_info_t), sizeof(u64));
CT_ASSERT_EQUAL(fa_l3_kv_size_is_48, sizeof(fa_5tuple_t), sizeof(clib_bihash_kv_40_8_t));
CT_ASSERT_EQUAL(fa_ip4_starts_at_kv16_key, offsetof(fa_5tuple_t, ip4_addr), offsetof(fa_5tuple_t, kv_16_8));
CT_ASSERT_EQUAL(fa_ip4_and_ip6_kv_value_match, offsetof(fa_5tuple_t, kv_16_8.value), offsetof(fa_5tuple_t, kv_40_8.value));

/* Let's try to fit within two cachelines */
CT_ASSERT_EQUAL(fa_session_t_size_is_128, sizeof(fa_session_t), 128);

/* Session ID MUST be the same as u64 */
CT_ASSERT_EQUAL(fa_full_session_id_size_is_64, sizeof(fa_full_session_id_t), sizeof(u64));

CT_ASSERT_EQUAL(fa_5tuple_opaque_t_must_match_5tuple, sizeof(fa_5tuple_opaque_t), sizeof(fa_5tuple_t));
#undef CT_ASSERT_EQUAL

#define FA_SESSION_BOGUS_INDEX ~0

typedef struct {
  /* The pool of sessions managed by this worker */
  fa_session_t *fa_sessions_pool;
  /* incoming session change requests from other workers */
  clib_spinlock_t pending_session_change_request_lock;
  u64 *pending_session_change_requests;
  u64 *wip_session_change_requests;
  u64 rcvd_session_change_requests;
  u64 sent_session_change_requests;
  /* per-worker ACL_N_TIMEOUTS of conn lists */
  u32 *fa_conn_list_head;
  u32 *fa_conn_list_tail;
  /* expiry time set whenever an element is enqueued */
  u64 *fa_conn_list_head_expiry_time;
  /* adds and deletes per-worker-per-interface */
  u64 *fa_session_dels_by_sw_if_index;
  u64 *fa_session_adds_by_sw_if_index;
  /* sessions deleted due to epoch change */
  u64 *fa_session_epoch_change_by_sw_if_index;
  /* Vector of expired connections retrieved from lists */
  u32 *expired;
  /* the earliest next expiry time */
  u64 next_expiry_time;
  /* if not zero, look at all the elements until their enqueue timestamp is after below one */
  u64 requeue_until_time;
  /* Current time between the checks */
  u64 current_time_wait_interval;
  /* Counter of how many sessions we did delete */
  u64 cnt_deleted_sessions;
  /* Counter of already deleted sessions being deleted - should not increment unless a bug */
  u64 cnt_already_deleted_sessions;
  /* Number of times we requeued a session to a head of the list */
  u64 cnt_session_timer_restarted;
  /* swipe up to this enqueue time, rather than following the timeouts */
  u64 swipe_end_time;
  /* bitmap of sw_if_index serviced by this worker */
  uword *serviced_sw_if_index_bitmap;
  /* bitmap of sw_if_indices to clear. set by main thread, cleared by worker */
  uword *pending_clear_sw_if_index_bitmap;
  /* atomic, indicates that the swipe-deletion of connections is in progress */
  u32 clear_in_process;
  /* Interrupt is pending from main thread */
  int interrupt_is_pending;
  /*
   * Interrupt node on the worker thread sets this if it knows there is
   * more work to do, but it has to finish to avoid hogging the
   * core for too long.
   */
  int interrupt_is_needed;
  /*
   * Set to indicate that the interrupt node wants to get less interrupts
   * because there is not enough work for the current rate.
   */
  int interrupt_is_unwanted;
  /*
   * Set to copy of a "generation" counter in main thread so we can sync the interrupts.
   */
  int interrupt_generation;
} acl_fa_per_worker_data_t;


typedef enum {
  ACL_FA_ERROR_DROP,
  ACL_FA_N_NEXT,
} acl_fa_next_t;


enum
{
  ACL_FA_CLEANER_RESCHEDULE = 1,
  ACL_FA_CLEANER_DELETE_BY_SW_IF_INDEX,
} acl_fa_cleaner_process_event_e;

void acl_fa_enable_disable(u32 sw_if_index, int is_input, int enable_disable);

void show_fa_sessions_hash(vlib_main_t * vm, u32 verbose);

u8 *format_acl_plugin_5tuple (u8 * s, va_list * args);

/* use like: elog_acl_maybe_trace_X1(am, "foobar: %d", "i4", int32_value); */

#define elog_acl_maybe_trace_X1(am, acl_elog_trace_format_label, acl_elog_trace_format_args, acl_elog_val1)              \
do {                                                                                                                     \
  if (am->trace_sessions) {                                                                                              \
    CLIB_UNUSED(struct { u8 available_space[18 - sizeof(acl_elog_val1)]; } *static_check);                               \
    u16 thread_index = os_get_thread_index ();                                                                           \
    vlib_worker_thread_t * w = vlib_worker_threads + thread_index;                                                       \
    ELOG_TYPE_DECLARE (e) =                                                                                              \
      {                                                                                                                  \
        .format = "(%02d) " acl_elog_trace_format_label,                                                                 \
        .format_args = "i2" acl_elog_trace_format_args,                                                                  \
      };                                                                                                                 \
    CLIB_PACKED(struct                                                                                                   \
      {                                                                                                                  \
        u16 thread;                                                                                                      \
        typeof(acl_elog_val1) val1;                                                                                      \
      }) *ed;                                                                                                            \
    ed = ELOG_TRACK_DATA (&vlib_global_main.elog_main, e, w->elog_track);                                                \
    ed->thread = thread_index;                                                                                           \
    ed->val1 = acl_elog_val1;                                                                                            \
  }                                                                                                                      \
} while (0)


/* use like: elog_acl_maybe_trace_X2(am, "foobar: %d some u64: %lu", "i4i8", int32_value, int64_value); */

#define elog_acl_maybe_trace_X2(am, acl_elog_trace_format_label, acl_elog_trace_format_args,                             \
                                                                                           acl_elog_val1, acl_elog_val2) \
do {                                                                                                                     \
  if (am->trace_sessions) {                                                                                              \
    CLIB_UNUSED(struct { u8 available_space[18 - sizeof(acl_elog_val1) - sizeof(acl_elog_val2)]; } *static_check);       \
    u16 thread_index = os_get_thread_index ();                                                                           \
    vlib_worker_thread_t * w = vlib_worker_threads + thread_index;                                                       \
    ELOG_TYPE_DECLARE (e) =                                                                                              \
      {                                                                                                                  \
        .format = "(%02d) " acl_elog_trace_format_label,                                                                 \
        .format_args = "i2" acl_elog_trace_format_args,                                                                  \
      };                                                                                                                 \
    CLIB_PACKED(struct                                                                                                   \
      {                                                                                                                  \
        u16 thread;                                                                                                      \
        typeof(acl_elog_val1) val1;                                                                                      \
        typeof(acl_elog_val2) val2;                                                                                      \
      }) *ed;                                                                                                            \
    ed = ELOG_TRACK_DATA (&vlib_global_main.elog_main, e, w->elog_track);                                                \
    ed->thread = thread_index;                                                                                           \
    ed->val1 = acl_elog_val1;                                                                                            \
    ed->val2 = acl_elog_val2;                                                                                            \
  }                                                                                                                      \
} while (0)


/* use like: elog_acl_maybe_trace_X3(am, "foobar: %d some u64 %lu baz: %d", "i4i8i4", int32_value, u64_value, int_value); */

#define elog_acl_maybe_trace_X3(am, acl_elog_trace_format_label, acl_elog_trace_format_args, acl_elog_val1,              \
                                                                                           acl_elog_val2, acl_elog_val3) \
do {                                                                                                                     \
  if (am->trace_sessions) {                                                                                              \
    CLIB_UNUSED(struct { u8 available_space[18 - sizeof(acl_elog_val1) - sizeof(acl_elog_val2)                           \
                                               - sizeof(acl_elog_val3)]; } *static_check);                               \
    u16 thread_index = os_get_thread_index ();                                                                           \
    vlib_worker_thread_t * w = vlib_worker_threads + thread_index;                                                       \
    ELOG_TYPE_DECLARE (e) =                                                                                              \
      {                                                                                                                  \
        .format = "(%02d) " acl_elog_trace_format_label,                                                                 \
        .format_args = "i2" acl_elog_trace_format_args,                                                                  \
      };                                                                                                                 \
    CLIB_PACKED(struct                                                                                                   \
      {                                                                                                                  \
        u16 thread;                                                                                                      \
        typeof(acl_elog_val1) val1;                                                                                      \
        typeof(acl_elog_val2) val2;                                                                                      \
        typeof(acl_elog_val3) val3;                                                                                      \
      }) *ed;                                                                                                            \
    ed = ELOG_TRACK_DATA (&vlib_global_main.elog_main, e, w->elog_track);                                                \
    ed->thread = thread_index;                                                                                           \
    ed->val1 = acl_elog_val1;                                                                                            \
    ed->val2 = acl_elog_val2;                                                                                            \
    ed->val3 = acl_elog_val3;                                                                                            \
  }                                                                                                                      \
} while (0)


/* use like: elog_acl_maybe_trace_X4(am, "foobar: %d some int %d baz: %d bar: %d", "i4i4i4i4", int32_value, int32_value2, int_value, int_value); */

#define elog_acl_maybe_trace_X4(am, acl_elog_trace_format_label, acl_elog_trace_format_args, acl_elog_val1,              \
                                                                            acl_elog_val2, acl_elog_val3, acl_elog_val4) \
do {                                                                                                                     \
  if (am->trace_sessions) {                                                                                              \
    CLIB_UNUSED(struct { u8 available_space[18 - sizeof(acl_elog_val1) - sizeof(acl_elog_val2)                           \
                                               - sizeof(acl_elog_val3) -sizeof(acl_elog_val4)]; } *static_check);        \
    u16 thread_index = os_get_thread_index ();                                                                           \
    vlib_worker_thread_t * w = vlib_worker_threads + thread_index;                                                       \
    ELOG_TYPE_DECLARE (e) =                                                                                              \
      {                                                                                                                  \
        .format = "(%02d) " acl_elog_trace_format_label,                                                                 \
        .format_args = "i2" acl_elog_trace_format_args,                                                                  \
      };                                                                                                                 \
    CLIB_PACKED(struct                                                                                                   \
      {                                                                                                                  \
        u16 thread;                                                                                                      \
        typeof(acl_elog_val1) val1;                                                                                      \
        typeof(acl_elog_val2) val2;                                                                                      \
        typeof(acl_elog_val3) val3;                                                                                      \
        typeof(acl_elog_val4) val4;                                                                                      \
      }) *ed;                                                                                                            \
    ed = ELOG_TRACK_DATA (&vlib_global_main.elog_main, e, w->elog_track);                                                \
    ed->thread = thread_index;                                                                                           \
    ed->val1 = acl_elog_val1;                                                                                            \
    ed->val2 = acl_elog_val2;                                                                                            \
    ed->val3 = acl_elog_val3;                                                                                            \
    ed->val4 = acl_elog_val4;                                                                                            \
  }                                                                                                                      \
} while (0)


#endif
