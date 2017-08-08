#ifndef _FA_NODE_H_
#define _FA_NODE_H_

#include <stddef.h>
#include <vppinfra/bihash_40_8.h>

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
#define ACL_FA_CONN_TABLE_DEFAULT_HASH_MEMORY_SIZE (1<<30)
#define ACL_FA_CONN_TABLE_DEFAULT_MAX_ENTRIES 1000000

typedef union {
  u64 as_u64;
  struct {
    u32 sw_if_index;
    u16 mask_type_index_lsb;
    u8 tcp_flags;
    u8 tcp_flags_valid:1;
    u8 is_input:1;
    u8 l4_valid:1;
    u8 is_nonfirst_fragment:1;
    u8 is_ip6:1;
    u8 flags_reserved:3;
  };
} fa_packet_info_t;

typedef union {
  u64 as_u64;
  struct {
    u16 port[2];
    u16 proto;
    u16 lsb_of_sw_if_index;
  };
} fa_session_l4_key_t;

typedef union {
  struct {
    ip46_address_t addr[2];
    fa_session_l4_key_t l4;
    /* This field should align with u64 value in bihash_40_8 keyvalue struct */
    fa_packet_info_t pkt;
  };
  clib_bihash_kv_40_8_t kv;
} fa_5tuple_t;


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
  u8 reserved1[7];        /* +7 bytes = 24 */
  u64 reserved2[5];       /* +5*8 bytes = 64 */
} fa_session_t;


/* This structure is used to fill in the u64 value
   in the per-sw-if-index hash table */
typedef struct {
  union {
    u64 as_u64;
    struct {
      u32 session_index;
      u16 thread_index;
      u16 reserved0;
    };
  };
} fa_full_session_id_t;

/*
 * A few compile-time constraints on the size and the layout of the union, to ensure
 * it makes sense both for bihash and for us.
 */

#define CT_ASSERT_EQUAL(name, x,y) typedef int assert_ ## name ## _compile_time_assertion_failed[((x) == (y))-1]
CT_ASSERT_EQUAL(fa_l3_key_size_is_40, offsetof(fa_5tuple_t, pkt), offsetof(clib_bihash_kv_40_8_t, value));
CT_ASSERT_EQUAL(fa_l4_key_t_is_8, sizeof(fa_session_l4_key_t), sizeof(u64));
CT_ASSERT_EQUAL(fa_packet_info_t_is_8, sizeof(fa_packet_info_t), sizeof(u64));
CT_ASSERT_EQUAL(fa_l3_kv_size_is_48, sizeof(fa_5tuple_t), sizeof(clib_bihash_kv_40_8_t));

/* Let's try to fit within two cachelines */
CT_ASSERT_EQUAL(fa_session_t_size_is_128, sizeof(fa_session_t), 128);

/* Session ID MUST be the same as u64 */
CT_ASSERT_EQUAL(fa_full_session_id_size_is_64, sizeof(fa_full_session_id_t), sizeof(u64));
#undef CT_ASSERT_EQUAL

typedef struct {
  /* The pool of sessions managed by this worker */
  fa_session_t *fa_sessions_pool;
  /* per-worker ACL_N_TIMEOUTS of conn lists */
  u32 *fa_conn_list_head;
  u32 *fa_conn_list_tail;
  /* adds and deletes per-worker-per-interface */
  u64 *fa_session_dels_by_sw_if_index;
  u64 *fa_session_adds_by_sw_if_index;
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


#endif
