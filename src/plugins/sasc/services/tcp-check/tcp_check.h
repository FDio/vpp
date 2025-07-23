// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2025 Cisco Systems, Inc.

#ifndef included_sasc_tcp_check_h
#define included_sasc_tcp_check_h

#include <vlib/vlib.h>
#include <sasc/sasc.h>
/* Convention: uppercase relates to responder lowercase to initiator */
#define foreach_sasc_tcp_check_session_flag                                                        \
    _(WAIT_FOR_RESP_SYN, 0, "S")                                                                   \
    _(WAIT_FOR_INIT_ACK_TO_SYN, 1, "a")                                                            \
    _(WAIT_FOR_RESP_ACK_TO_SYN, 2, "A")                                                            \
    _(SEEN_FIN_INIT, 3, "f")                                                                       \
    _(SEEN_FIN_RESP, 4, "F")                                                                       \
    _(SEEN_ACK_TO_FIN_INIT, 5, "r")                                                                \
    _(SEEN_ACK_TO_FIN_RESP, 6, "R")                                                                \
    _(ESTABLISHED, 7, "U")                                                                         \
    _(REMOVING, 8, "D")                                                                            \
    _(BLOCKED, 9, "X")

typedef enum {
#define _(name, x, str) SASC_TCP_CHECK_SESSION_FLAG_##name = (1 << (x)),
    foreach_sasc_tcp_check_session_flag SASC_TCP_CHECK_SESSION_N_FLAG
#undef _
} sasc_tcp_check_session_flag_t;

#define SASC_TCP_CHECK_TCP_FLAGS_MASK                                                              \
    (0x3F) /* Include all TCP flags: FIN(0x1) | SYN(0x2) | RST(0x4) | PSH(0x8) | ACK(0x10) |       \
              URG(0x20) */
#define SASC_TCP_CHECK_TCP_FLAGS_FIN (0x1)
#define SASC_TCP_CHECK_TCP_FLAGS_SYN (0x2)
#define SASC_TCP_CHECK_TCP_FLAGS_RST (0x4)
#define SASC_TCP_CHECK_TCP_FLAGS_PSH (0x8)
#define SASC_TCP_CHECK_TCP_FLAGS_ACK (0x10)
#define SASC_TCP_CHECK_TCP_FLAGS_URG (0x20)
/* transitions are labelled with TCP Flags encoded in u8 as
   0 0 0 ACK 0 RST SYN FIN
   Transition table for each direction is 32x9
   result of the lookup is (what is set, what is cleared)
 */
/*#define foreach_sasc_tcp_check_forward_transition \
_(WAIT_FOR_INIT_ACK_TO_SYN, ACK, )*/

typedef struct {
    CLIB_CACHE_LINE_ALIGN_MARK(cacheline0);
    u32 flags;
    union {
        u32 fin_num[SASC_FLOW_F_B_N];
        u64 as_u64_0;
    };
    session_version_t version;
    /* Retransmit detection fields */
    u32 last_seq[SASC_FLOW_F_B_N];         /* Last sequence number seen per direction */
    u32 last_ack[SASC_FLOW_F_B_N];         /* Last ACK number seen per direction */
    u32 retransmit_count[SASC_FLOW_F_B_N]; /* Count of retransmits per direction */
    f64 last_pkt_time[SASC_FLOW_F_B_N];    /* Timestamp of last packet per direction */
    u16 last_window[SASC_FLOW_F_B_N];      /* Last window size seen per direction */
    u8 last_flags[SASC_FLOW_F_B_N];        /* Last packet flags per direction */
    u32 last_data_len[SASC_FLOW_F_B_N];    /* Last packet data length per direction */
    /* Enhanced retransmission timing tracking */
    f64 last_retransmit_time[SASC_FLOW_F_B_N];   /* Timestamp of last retransmit per direction */
    f64 retransmit_delays[SASC_FLOW_F_B_N][16];  /* Retransmission delay history (max 16 samples) */
    u32 retransmit_delay_count[SASC_FLOW_F_B_N]; /* Number of retransmission delays recorded */
    u32 retransmit_burst_count[SASC_FLOW_F_B_N]; /* Count of consecutive retransmits in burst */
    f64 last_retransmit_burst_start[SASC_FLOW_F_B_N]; /* Start time of current retransmit burst */
    u32 packet_count[SASC_FLOW_F_B_N];                /* Total packet count per direction */
    u32 data_packet_count[SASC_FLOW_F_B_N];           /* Data packet count per direction */
    u32 ack_packet_count[SASC_FLOW_F_B_N];            /* ACK packet count per direction */
    /* Reorder detection fields */
    u32 expected_seq[SASC_FLOW_F_B_N];  /* Expected next sequence number per direction */
    u32 reorder_count[SASC_FLOW_F_B_N]; /* Count of reordered packets per direction */
    /* Configuration fields */
    f64 retransmit_threshold; /* Configurable retransmit detection threshold (seconds) */
    u32 reorder_tolerance;    /* Configurable reorder tolerance (sequence numbers) */
    /* Fast retransmit detection */
    u32 dup_ack_count[SASC_FLOW_F_B_N];    /* Duplicate ACK count per direction */
    u32 last_dup_ack_seq[SASC_FLOW_F_B_N]; /* Last duplicate ACK sequence number */
    /* Session-specific anomaly counters */
    u32 invalid_tcp_header_count; /* Count of invalid TCP headers */
    u32 malformed_flags_count;    /* Count of malformed TCP flags */
    u32 unexpected_syn_count;     /* Count of unexpected SYN packets */
    u32 protocol_violation_count; /* Count of protocol violations */
    u32 invalid_fin_ack_count;    /* Count of invalid FIN ACKs */
    u32 fast_retransmit_count;    /* Count of fast retransmits (3 dup ACKs) */
    u32 window_probe_count;       /* Count of window probes */
    u32 handshake_timeout_count;  /* Count of handshake timeouts */
    /* RTT Calculation and Statistics */
    u32 last_ts_val[SASC_FLOW_F_B_N];       /* Last seen timestamp value for RTT calculation */
    f64 last_ts_time[SASC_FLOW_F_B_N];      /* Time of last seen timestamp value */
    f64 rtt_min[SASC_FLOW_F_B_N];           /* Minimum RTT observed */
    f64 rtt_max[SASC_FLOW_F_B_N];           /* Maximum RTT observed */
    f64 rtt_sum[SASC_FLOW_F_B_N];           /* Sum of all RTT samples for averaging */
    u32 rtt_count[SASC_FLOW_F_B_N];         /* Count of RTT samples */
    u32 rtt_histogram[SASC_FLOW_F_B_N][16]; /* RTT histogram in milliseconds (log2 bins) */
    /* RTT calculation without timestamps */
    u32 rtt_seq[SASC_FLOW_F_B_N];  /* Sequence number being tracked for RTT */
    f64 rtt_time[SASC_FLOW_F_B_N]; /* Time when the tracked sequence was sent */
} sasc_tcp_check_session_state_t;

typedef struct {
    sasc_tcp_check_session_state_t *state; /* vec indexed by session-index */
    u16 msg_id_base;

    /* Counters */
    vlib_simple_counter_main_t *counters;
    vlib_log2_histogram_main_t rtt_histogram;
} sasc_tcp_check_main_t;

extern sasc_tcp_check_main_t sasc_tcp_check_main;

format_function_t format_sasc_tcp_check_session_flags;
// u32
// sasc_table_format_insert_tcp_check_session(table_t *t, u32 n, sasc_main_t *sasc, u32
// session_index,
//                                            sasc_session_t *session,
//                                            sasc_tcp_check_session_state_t *tcp_session);

#endif /* __included_sasc_tcp_check_h__ */