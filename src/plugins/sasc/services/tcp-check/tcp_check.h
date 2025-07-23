// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2025 Cisco Systems, Inc.

#ifndef included_sasc_tcp_check_h
#define included_sasc_tcp_check_h

#include <vlib/vlib.h>
#include <sasc/sasc.h>
#include <vnet/tcp/tcp_packet.h> /* For sack_block_t and TCP option definitions */
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

/* SACK-related constants */
#define TCP_MAX_SACK_BLOCKS 255 /* Maximum number of SACK blocks to process */
/* transitions are labelled with TCP Flags encoded in u8 as
   0 0 0 ACK 0 RST SYN FIN
   Transition table for each direction is 32x9
   result of the lookup is (what is set, what is cleared)
 */
/*#define foreach_sasc_tcp_check_forward_transition \
_(WAIT_FOR_INIT_ACK_TO_SYN, ACK, )*/

typedef enum {
    SASC_TCP_CLOSE_NONE = 0,
    SASC_TCP_CLOSE_GRACEFUL,            /* FIN/FIN-ACK/ACK on both sides */
    SASC_TCP_CLOSE_HALF_CLOSED_FWD,     /* only forward side FIN observed */
    SASC_TCP_CLOSE_HALF_CLOSED_REV,     /* only reverse side FIN observed */
    SASC_TCP_CLOSE_SIMULTANEOUS_FIN,    /* both sides FIN without RST */
    SASC_TCP_CLOSE_ABORT_MIDSTREAM,     /* RST seen without any prior FIN */
    SASC_TCP_CLOSE_ABORT_AFTER_FIN_FWD, /* RST after forward FIN */
    SASC_TCP_CLOSE_ABORT_AFTER_FIN_REV, /* RST after reverse FIN */
    SASC_TCP_CLOSE_HANDSHAKE_RESET      /* RST during SYN handshake */
} sasc_tcp_close_cause_t;

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
    /* Spurious retransmission classification */
    u32 spurious_retransmit_count;         /* Full-segment already SACKed */
    u32 spurious_retransmit_partial_bytes; /* Overlap bytes with SACKed ranges */
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
    u32 starts_without_syn_count; /* Count of sessions that start without SYN (e.g., after restart)
                                   */
    /* RTT Calculation and Statistics */
    u32 last_ts_val[SASC_FLOW_F_B_N];  /* Last seen timestamp value for RTT calculation */
    f64 last_ts_time[SASC_FLOW_F_B_N]; /* Time of last seen timestamp value */
    f64 rtt_min[SASC_FLOW_F_B_N];      /* Minimum RTT observed */
    f64 rtt_max[SASC_FLOW_F_B_N];      /* Maximum RTT observed */
    f64 rtt_sum[SASC_FLOW_F_B_N];      /* Sum of all RTT samples for averaging */
    u32 rtt_count[SASC_FLOW_F_B_N];    /* Count of RTT samples */
    /* Welford accumulators for RTT variance */
    f64 rtt_mean[SASC_FLOW_F_B_N];          /* Online mean */
    f64 rtt_M2[SASC_FLOW_F_B_N];            /* Online M2 for variance */
    u32 rtt_histogram[SASC_FLOW_F_B_N][16]; /* RTT histogram in milliseconds (log2 bins) */
    /* RTT calculation without timestamps */
    u32 rtt_seq[SASC_FLOW_F_B_N];  /* Sequence number being tracked for RTT */
    f64 rtt_time[SASC_FLOW_F_B_N]; /* Time when the tracked sequence was sent */

    /* Close classification and timing */
    u8 close_cause;          /* sasc_tcp_close_cause_t */
    u8 half_closed_dir;      /* 0xff = none, else SASC_FLOW_* that FINed first */
    u8 saw_simultaneous_fin; /* boolean */
    f64 close_time;          /* wall-clock seconds when we entered transitory */

    /* Handshake validation and probes */
    u32 syn_isn_fwd;                  /* ISN from forward SYN */
    u32 syn_isn_rev;                  /* ISN from reverse SYN (SYN-ACK) */
    u32 keepalive_count;              /* Detected TCP keepalive probes */
    u32 handshake_ack_mismatch_count; /* Bad ACKs during 3WHS */

    /* Internal: request teardown on data-after-FIN violation */
    u8 pending_remove_due_to_data_after_fin;

    /* SACK-related tracking and anomaly detection */
    u8 sack_permitted[SASC_FLOW_F_B_N];        /* SACK permitted flag per direction */
    u32 sack_blocks_received[SASC_FLOW_F_B_N]; /* Total SACK blocks received per direction */
    u32 sack_bytes_received[SASC_FLOW_F_B_N];  /* Total bytes acknowledged via SACK per direction */
    u32 sack_duplicate_blocks[SASC_FLOW_F_B_N]; /* Count of duplicate SACK blocks per direction */
    u32 sack_invalid_blocks[SASC_FLOW_F_B_N];   /* Count of invalid SACK blocks per direction */
    u32 sack_reneging_count[SASC_FLOW_F_B_N];   /* Count of SACK reneging events per direction */
    u32 sack_blocks_per_packet[SASC_FLOW_F_B_N][16]; /* Distribution of SACK blocks per packet */
    u32 last_sack_high_water[SASC_FLOW_F_B_N];     /* Highest SACK sequence number per direction */
    f64 last_sack_time[SASC_FLOW_F_B_N];           /* Timestamp of last SACK per direction */
    u32 sack_blocks_in_flight[SASC_FLOW_F_B_N];    /* Current SACK blocks being tracked */
    sack_block_t sack_history[SASC_FLOW_F_B_N][8]; /* Recent SACK blocks for reneging detection */
    u8 sack_history_count[SASC_FLOW_F_B_N];        /* Number of SACK blocks in history */

    /* Byte-weighted impact */
    u64 retransmit_bytes[SASC_FLOW_F_B_N]; /* Total bytes in retransmitted segments */
    u64 reorder_bytes[SASC_FLOW_F_B_N];    /* Total bytes observed as out-of-order */

    /* Zero-window tracking */
    u8 zero_window_active[SASC_FLOW_F_B_N];          /* Whether zero-window currently active */
    f64 zero_window_start_time[SASC_FLOW_F_B_N];     /* When current ZW episode started */
    f64 zero_window_duration_total[SASC_FLOW_F_B_N]; /* Total time in zero-window */
    u32 zero_window_episodes[SASC_FLOW_F_B_N];       /* Number of zero-window episodes */

    /* Timing for time-normalized rates */
    f64 first_seen_time; /* First packet time for this session in tcp-check */
    f64 last_seen_time;  /* Last packet time observed */

    /* ECN tracking and analysis */
    u32 ecn_ce_count[SASC_FLOW_F_B_N];  /* CE (Congestion Experienced) marks received per direction
                                         */
    u32 ecn_ect_count[SASC_FLOW_F_B_N]; /* ECT (ECN-Capable Transport) marks sent per direction */
    u8 ecn_negotiated;                  /* ECN was negotiated during handshake (ECE/CWR flags) */
    u32 ecn_ce_bytes[SASC_FLOW_F_B_N];  /* Bytes received with CE marks per direction */
    u32 ecn_ect_bytes[SASC_FLOW_F_B_N]; /* Bytes sent with ECT marks per direction */
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