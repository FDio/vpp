#ifndef _FA_NODE_H_
#define _FA_NODE_H_

#include <stddef.h>
#include "bihash_40_8.h"

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
    u8 tcp_flags;
    u8 tcp_flags_valid:1;
    u8 is_input:1;
    u8 l4_valid:1;
    u8 is_nonfirst_fragment:1;
    u8 flags_reserved:4;
  };
} fa_packet_info_t;

typedef union {
  u64 as_u64;
  struct {
    u16 port[2];
    u16 proto;
    u16 rsvd;
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
  u8 link_list_id;           /* +1 bytes = 63 */
  u8 reserved1;           /* +1 bytes = 64 */
  u32 link_prev_idx;
  u32 link_next_idx;
  u64 reserved2[7];
} fa_session_t;


/*
 * A few compile-time constraints on the size and the layout of the union, to ensure
 * it makes sense both for bihash and for us.
 */

#define CT_ASSERT_EQUAL(name, x,y) typedef int assert_ ## name ## _compile_time_assertion_failed[((x) == (y))-1]
CT_ASSERT_EQUAL(fa_l3_key_size_is_40, offsetof(fa_5tuple_t, pkt), offsetof(clib_bihash_kv_40_8_t, value));
CT_ASSERT_EQUAL(fa_l4_key_t_is_8, sizeof(fa_session_l4_key_t), sizeof(u64));
CT_ASSERT_EQUAL(fa_packet_info_t_is_8, sizeof(fa_packet_info_t), sizeof(u64));
CT_ASSERT_EQUAL(fa_l3_kv_size_is_48, sizeof(fa_5tuple_t), sizeof(clib_bihash_kv_40_8_t));

/* Let's try to fit within the cacheline */
CT_ASSERT_EQUAL(fa_session_t_size_is_64, sizeof(fa_session_t), 128);
#undef CT_ASSERT_EQUAL


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


#endif
