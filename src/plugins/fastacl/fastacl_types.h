/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 FastNetMon (fastnetmon.com)
 */

#ifndef __included_fastacl_types_h__
#define __included_fastacl_types_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>
#include <linux/psample.h>

typedef struct fastacl_main_t_ fastacl_main_t;

#define foreach_fastacl_match_flag                                                                 \
  _ (0, DST_PREFIX, "dst-prefix")                                                                  \
  _ (1, SRC_PREFIX, "src-prefix")                                                                  \
  _ (2, PROTO, "proto")                                                                            \
  _ (3, DST_PORT, "dst-port")                                                                      \
  _ (4, SRC_PORT, "src-port")                                                                      \
  _ (5, EITHER_PORT, "either-port")                                                                \
  _ (6, ICMP_TYPE, "icmp-type")                                                                    \
  _ (7, ICMP_CODE, "icmp-code")                                                                    \
  _ (8, TCP_FLAGS, "tcp-flags")                                                                    \
  _ (9, PKT_LEN, "pkt-len")                                                                        \
  _ (10, DSCP, "dscp")                                                                             \
  _ (11, FRAGMENT, "fragment")                                                                     \
  _ (15, IS_IP6, "is-ip6")

typedef enum
{
#define _(bit, name, str) FASTACL_MATCH_##name = (1 << (bit)),
  foreach_fastacl_match_flag
#undef _
} fastacl_match_flag_t;

#define FASTACL_FRAG_DF	 (1 << 0)
#define FASTACL_FRAG_ISF (1 << 1)
#define FASTACL_FRAG_FF	 (1 << 2)
#define FASTACL_FRAG_LF	 (1 << 3)

#define FASTACL_L4_PORTS_BYTES	   4
#define FASTACL_L4_ICMP_TYPE_BYTES 1
#define FASTACL_L4_ICMP_CODE_BYTES 2
#define FASTACL_L4_TCP_FLAGS_BYTES 14

typedef struct
{
  u32 flags;

  ip46_address_t dst_addr;
  ip46_address_t src_addr;
  u8 dst_prefix_len;
  u8 src_prefix_len;

  u8 proto;

  u16 dst_port_min;
  u16 dst_port_max;
  u16 src_port_min;
  u16 src_port_max;

  u16 either_port_min;
  u16 either_port_max;

  u8 icmp_type;
  u8 icmp_code;

  u8 tcp_flags_value;
  u8 tcp_flags_mask;

  u16 pkt_len_min;
  u16 pkt_len_max;

  u8 dscp;

  u8 fragment_flags;
  u8 fragment_mask;
} fastacl_match_t;

#define foreach_fastacl_match_scalar_field                                                         \
  _ (u8, proto)                                                                                    \
  _ (u16, dst_port_min)                                                                            \
  _ (u16, dst_port_max)                                                                            \
  _ (u16, src_port_min)                                                                            \
  _ (u16, src_port_max)                                                                            \
  _ (u16, either_port_min)                                                                         \
  _ (u16, either_port_max)                                                                         \
  _ (u8, icmp_type)                                                                                \
  _ (u8, icmp_code)                                                                                \
  _ (u8, tcp_flags_value)                                                                          \
  _ (u8, tcp_flags_mask)                                                                           \
  _ (u16, pkt_len_min)                                                                             \
  _ (u16, pkt_len_max)                                                                             \
  _ (u8, dscp)                                                                                     \
  _ (u8, fragment_flags)                                                                           \
  _ (u8, fragment_mask)

static_always_inline u8
fastacl_max_prefix_len (int is_ip6)
{
  return is_ip6 ? 128 : 32;
}

struct nl_sock;

#define FASTACL_NL_MAX_MCAST_GROUP 32

#define FASTACL_PSAMPLE_FAMILY "psample"
#define FASTACL_PSAMPLE_GROUP  "packets"

typedef struct
{
  struct nl_sock *sk;
  u16 family_id;
  u32 group_id;
  u32 seq;
} fastacl_psample_worker_t;

typedef struct
{
  u16 family_id;
  u32 group_id;
} fastacl_psample_main_t;

typedef enum
{
  FASTACL_ACTION_TYPE_DROP = 0,

  FASTACL_ACTION_TYPE_PERMIT = 3,
} fastacl_action_type_t;

typedef struct
{
  u8 type;
  u32 sample_ratio;
  u32 sample_group;
} fastacl_action_t;

#define foreach_fastacl_action_field                                                               \
  _ (type)                                                                                         \
  _ (sample_ratio)                                                                                 \
  _ (sample_group)

typedef struct
{
  f64 time;
  u64 packets;
  u64 bytes;
  f64 pps;
  f64 l3_bps;
  f64 l1_bps;
} fastacl_rate_snapshot_t;

typedef struct fastacl_rule_t_
{
  u32 index;
  u32 order;
  fastacl_match_t match;
  fastacl_action_t action;
  u64 packet_count;
  u64 byte_count;
  fastacl_rate_snapshot_t rate_snap;
} fastacl_rule_t;

#define FASTACL_TSS_BUCKETS_DEFAULT (64 * 1024)
#define FASTACL_TSS_BUCKETS_MIN	    1024

#define FASTACL_L1_OVERHEAD_BYTES 38

#define foreach_fastacl_per_worker_rule_vec                                                        \
  _ (rule_sample_count)                                                                            \
  _ (rule_sample_missed)                                                                           \
  _ (rule_sample_credit)

typedef struct
{
  u64 total_processed;
  u64 total_dropped;
  u64 total_bytes_processed;
  u64 total_bytes_dropped;
  u64 *rule_sample_count;
  u64 *rule_sample_missed;
  u32 *rule_sample_credit;
  fastacl_psample_worker_t psample;
} fastacl_per_worker_t;

typedef struct
{
  u64 total_processed;
  u64 total_dropped;
  u64 total_bytes_processed;
  u64 total_bytes_dropped;
  fastacl_rate_snapshot_t processed_rate;
  fastacl_rate_snapshot_t dropped_rate;
} fastacl_aggregate_counters_t;

typedef struct
{
  u32 rule_index;
  u32 rule_order;
  u8 action_type;
  u32 next_index;
  u64 pkt_count;
} fastacl_trace_t;

typedef struct
{
  ip4_header_t *ip0;
  u8 *l4;
  u16 l4_bytes;
  u8 pkt_proto;
  u8 is_ip6;
  u8 unparseable;
  u16 l4_src_port;
  u16 l4_dst_port;
  u16 pkt_len;
  u8 pkt_dscp;
  u8 pkt_frag_flags;
} fastacl_parsed_t;

#define foreach_fastacl_error                                                                      \
  _ (MATCHED, "packets matched a rule")                                                            \
  _ (DROPPED, "packets dropped")                                                                   \
  _ (PASSED, "packets passed (no match)")                                                          \
  _ (UNPARSEABLE, "packets passed (IP version not 4 or 6)")                                        \
  _ (SAMPLED, "packets sampled to psample")                                                        \
  _ (SAMPLE_FAIL, "sample sends that failed (netlink backpressure)")

typedef enum
{
#define _(sym, str) FASTACL_ERROR_##sym,
  foreach_fastacl_error
#undef _
    FASTACL_N_ERROR,
} fastacl_error_t;

#define FASTACL_RATE_MIN_INTERVAL 0.5

#endif
