/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019, LabN Consulting, L.L.C.
 * Copyright (c) 2015 Cisco and/or its affiliates.
 * May 18 2019, Christian E. Hopps <chopps@labn.net>
 */
#ifndef __included_ipsec_iptfs_h__
#define __included_ipsec_iptfs_h__

/* Always expect TFS inbound, turn this into a global config later */
#define IPTFS_ENABLE_GLOBAL_RX_MODE 1

/*
 * Support multiple encapsulation threads -- for faster single connection
 * disable this, we could rewire a different encap node perhaps to do this
 * dynamically.
 */
#define IPTFS_ENABLE_ENCAP_MULTITHREAD 1

/*
 * Support decrypt separate from decapsulation
 */
#define IPTFS_ENABLE_DECAP_ISOLATION 0

/*
 * Enable event logs
 */
#define IPTFS_ENABLE_CC_EVENT_LOGS     0
#define IPTFS_ENABLE_DECAP_EVENT_LOGS  0
#define IPTFS_ENABLE_PACER_EVENT_LOGS  0
#define IPTFS_ENABLE_OUTPUT_EVENT_LOGS 0
#define IPTFS_ENABLE_ZPOOL_EVENT_LOGS  0

/* Turn on some debug prints */
#define IPTFS_CC_DEBUG 0

#define IPTFS_MAX_PACKET_SIZE 9152 /* ATM: 9120 use 64b aligned (143 * 64) */

#undef IPTFS_OUTPUT_BACKUP

/*
 * IPTFS_*_MAX_MISSED is the number of packets we are willing to queue to
 * the next node from the sending routine to catch up on missed time slots. If
 * we have missed more than this number of slots we will drop those slots.
 *
 * This number should probably not be larger than the size of the TX output
 * queue.
 *
 * Also if this number is larger than VLIB_FRAME_SIZE then IPTFS_*_BACKUP
 * must be defined as we need to loop back to catchup and not send more than
 * VLIB_FRAME_SIZE packets per worker loop. The PACER always backs up (or
 * bursts forward).
 */
#define IPTFS_PACER_MAX_MISSED	1023
#define IPTFS_OUTPUT_MAX_MISSED (VLIB_FRAME_SIZE - 1)

/*
 * The amount of tunnel packets to queue to send faster than tunnel-rate if the
 * max-latency is exceeded. We choose a full frame as we can send them all each
 * trip through the pacer, and the pacer runs cooperatively with the encap so
 * we never want to queue more than this either.
 */
#define IPTFS_MIN_RATE_OVER_ALLOW VLIB_FRAME_SIZE

#if defined(IPTFS_OUTPUT_BACKUP)
/* We don't actually want the output routine backing up.*/
#else
STATIC_ASSERT ((IPTFS_OUTPUT_MAX_MISSED <= VLIB_FRAME_SIZE), "Max missed can't be this large");
#endif

/* Need enough to cover maximum missed / catchup all-pad-packets */
#if IPTFS_OUTPUT_MAX_MISSED > VLIB_FRAME_SIZE
#define IPTFS_OUTPUT_ZPOOL_SIZE ((IPTFS_OUTPUT_MAX_MISSED + 1) * 4)
#else
#define IPTFS_OUTPUT_ZPOOL_SIZE (VLIB_FRAME_SIZE * 8)
#endif

/* Require at least twice the free buffers we need to catchup */
STATIC_ASSERT ((IPTFS_OUTPUT_ZPOOL_SIZE / 2) >= IPTFS_OUTPUT_MAX_MISSED,
	       "output zpool size not large enough for max missed slots");

/*
 * IPTFS_ZPOOL_MAX_ALLOC  is a sanity value to make sure the user doesn't
 * specify a max latency so large that we pre-allocate too many zero buffers
 */
#define IPTFS_ZPOOL_MAX_ALLOC (VLIB_FRAME_SIZE * 1024)

/* VLIB_FRAME_SIZE * 4 == 1024 */
#define IPTFS_TXQ_LOG2 10
#define IPTFS_TXQ_SIZE (1 << IPTFS_TXQ_LOG2)

/*
 * Tuning parmaters
 */
#define IPTFS_DECAP_MIN_CHAIN_LEN (64 * 4 + 1)

#define IPTFS_ENCAP_COPY_AND_CHAIN

#ifdef IPTFS_ENCAP_COPY_AND_CHAIN
#define IPTFS_ENCAP_STRADDLE_COPY_OVER_INDRECT_SIZE(satd)                                          \
  (CLIB_CACHE_LINE_BYTES * 4 - iptfs_sa_data_hdrlen (satd))
#endif

/*
 * This value is used if the user doesn't specify a max latency. It represents
 * the amount of traffic that can be burst into the tunnel. The faster the
 * tunnel the smaller amount that can be burst in. If this is not acceptable,
 * the user can always specify the max latency.
 */
#define IPTFS_DEF_ENCAP_QUEUE_SIZE (VLIB_FRAME_SIZE * 2)

/* This is the number of frames (of up tot 256 packets) that can be queued to
 * the decap tx thread -- b/c the decap thread always runs slower than the
 * packet rx thread we need to make this very large -- against the
 * recommendation from VPP designers. This is b/c all the frames we send will
 * be small as there is no back-pressure on the rx thread from the consumer */
// #define IPTFS_DECAP_HANDOFF_QUEUE_SIZE 64
#define IPTFS_DECAP_HANDOFF_QUEUE_SIZE 512
/* This is the number of frames (of up tot 256 packets) that can be queued to
 * the encap tx crypto thread */
#define IPTFS_ENCAP_HANDOFF_QUEUE_SIZE 64

#include <stdbool.h>
#include <sys/queue.h>
#include <vlib/counter.h>
#include <vlib/threads.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ipsec/ipsec.h>
#include <vnet/ipsec/ipsec_sa.h>
#include <vnet/ipsec/ipsec_itf.h>

#include <vppinfra/bihash_8_8.h>
#include <vppinfra/elog.h>
#include <vppinfra/error.h>

#include <plugins/iptfs/iptfs_sring.h>

typedef struct iptfs_zpool_t iptfs_zpool_t;

#define iptfs_log(...)	clib_warning ("INFO: " __VA_ARGS__)
#define iptfs_warn(...) clib_warning ("WARN: " __VA_ARGS__)

extern bool iptfs_debug;
extern bool iptfs_pkt_debug;
extern u32 iptfs_pkt_type_debug_mask;

/*
 * fine-grained debugging flags for use with iptfs_pkt_debug_t().
 */
#define foreach_pt_debug_type                                                                      \
  _ ("encap", ENCAP)                                                                               \
  _ ("pacer", PACER)                                                                               \
  _ ("output-userdata", OUTPUT_USERDATA)                                                           \
  _ ("decap", DECAP)

/*
 * define the bits (0, 1, 2, ...)
 */
typedef enum
{
#define _(s, t) IPTFS_PT_DEBUG_FLAG_BIT_##t,
  foreach_pt_debug_type
#undef _
    IPTFS_PT_DEBUG_FLAG_BIT_MAX
} iptfs_pt_debug_flag_bit_t;

/*
 * define the masks (1<<0, 1<<1, 1<<2, ...)
 */
typedef enum
{
#define _(s, t) IPTFS_PT_DBG_##t = 1 << IPTFS_PT_DEBUG_FLAG_BIT_##t,
  foreach_pt_debug_type
#undef _
} iptfs_pt_debug_flag_t;

// #define IPTFS_DISABLE_SCOUNTERS
// #define IPTFS_DISABLE_PCOUNTERS
// #define IPTFS_DEBUG_CORRUPTION
#define IPTFS_DEBUG

#ifdef IPTFS_DEBUG_CORRUPTION
#define IPTFS_DBG_ARG(x) x
#else
#define IPTFS_DBG_ARG(x) x __attribute__ ((unused))
#endif

#ifdef IPTFS_DEBUG
#define iptfs_assert(truth)                                                                        \
  do                                                                                               \
    {                                                                                              \
      if (!(truth))                                                                                \
	{                                                                                          \
	  _clib_error (CLIB_ERROR_ABORT, 0, 0, "%s:%d (%s) assertion `%s' fails", __FILE__,        \
		       (uword) __LINE__, clib_error_function, #truth);                             \
	}                                                                                          \
    }                                                                                              \
  while (0)
#else
#define iptfs_assert(true)
#endif

#ifdef IPTFS_DEBUG
#define iptfs_debug(...)                                                                           \
  do                                                                                               \
    {                                                                                              \
      if (iptfs_debug)                                                                             \
	clib_warning ("DEBUG: " __VA_ARGS__);                                                      \
    }                                                                                              \
  while (0)

#ifdef IPTFS_DEBUG_CORRUPTION
#define iptfs_pkt_debug_s(s, ...)                                                                  \
  do                                                                                               \
    {                                                                                              \
      if (iptfs_pkt_debug)                                                                         \
	clib_warning ("PDEBUG: " __VA_ARGS__);                                                     \
      (*s) = format ((*s), "\nPDEBUG: " __VA_ARGS__);                                              \
    }                                                                                              \
  while (0)
#else
#define iptfs_pkt_debug_s(s, ...)                                                                  \
  do                                                                                               \
    {                                                                                              \
      if (iptfs_pkt_debug)                                                                         \
	clib_warning ("PDEBUG: " __VA_ARGS__);                                                     \
    }                                                                                              \
  while (0)
#endif

#define iptfs_pkt_debug(...)                                                                       \
  do                                                                                               \
    {                                                                                              \
      if (iptfs_pkt_debug)                                                                         \
	clib_warning ("PDEBUG: " __VA_ARGS__);                                                     \
    }                                                                                              \
  while (0)

#define iptfs_pkt_debug_t(type, ...)                                                               \
  do                                                                                               \
    {                                                                                              \
      if (type & iptfs_pkt_type_debug_mask)                                                        \
	clib_warning ("PTDEBUG: " __VA_ARGS__);                                                    \
    }                                                                                              \
  while (0)
#else /* IPTFS_DEBUG */
#define iptfs_debug(...)
#define iptfs_pkt_debug(...)
#define iptfs_pkt_debug_s(s, ...)
#define iptfs_pkt_debug_t(type, ...)
#endif /* IPTFS_DEBUG */

#include <vnet/ipsec/esp.h>
#include <plugins/iptfs/iptfs_bufq.h>

/*
 * Packet formats
 */
typedef enum
{
  IPTFS_SUBTYPE_BASIC = 0x0,
  IPTFS_SUBTYPE_CC = 0x1,
  IPTFS_SUBTYPE_LAST = IPTFS_SUBTYPE_CC
} iptfs_subtype_t;

typedef CLIB_PACKED (struct {
  u8 subtype; /* 0 */
  u8 resv;
  u16 block_offset;
}) ipsec_iptfs_basic_header_t;

/*
 * RFC53438 uses a vale of 1/64 pps (one packet every 64 seconds), we cannot
 * use this value as the send rate also determines the RTT (as we consider
 * transmission delay in RTT). Instead we limit our minimum send rate to 2 pps.
 * Using even a value of 1pps forces a > 5s slow start.
 */
#define IPTFS_CC_MIN_PPS (2)

#define IPTFS_CC_RTT_LOG2   22
#define IPTFS_CC_RTT_MAX    ((1 << IPTFS_CC_RTT_LOG2) - 1)
#define IPTFS_CC_RTT_MASK   ((1 << IPTFS_CC_RTT_LOG2) - 1)
#define IPTFS_CC_DELAY_LOG2 21
#define IPTFS_CC_DELAY_MAX  ((1 << IPTFS_CC_DELAY_LOG2) - 1)
#define IPTFS_CC_DELAY_MASK ((1 << IPTFS_CC_DELAY_LOG2) - 1)

typedef CLIB_PACKED (struct {
  u8 subtype; /* 1 */
  u8 flags;
  u16 block_offset;
  u32 loss_rate;
  union
  {
    struct
    {
      u8 rtt_and_adelay1[4];
      u8 adelay2_and_xdelay[4];
    };
    struct
    {
      u32 rtt_and_delay;
      u32 delays;
    };
  };
  u32 tval;
  u32 techo;
}) ipsec_iptfs_cc_header_t;

static inline void
iptfs_cc_get_rtt_and_delays (ipsec_iptfs_cc_header_t *cch, u32 *rtt, u32 *actual_delay,
			     u32 *xmit_delay)
{
  *rtt = (cch->rtt_and_adelay1[0] << 14) | (cch->rtt_and_adelay1[1] << 6) |
	 (cch->rtt_and_adelay1[2] & 0xFC) >> 2;

  *actual_delay = ((cch->rtt_and_adelay1[2] & 0x03) << (21 - 2)) |
		  (cch->rtt_and_adelay1[3] << (21 - 2 - 8)) |
		  (cch->adelay2_and_xdelay[0] << (21 - 2 - 8 - 8)) |
		  ((cch->adelay2_and_xdelay[1] & 0xE0) >> -(21 - 2 - 8 - 8 - 8));

  *xmit_delay = ((cch->adelay2_and_xdelay[1] & 0x1F) << (21 - 5)) |
		(cch->adelay2_and_xdelay[2] << 8) | cch->adelay2_and_xdelay[3];

  u32 v1 = clib_net_to_host_u32 (cch->rtt_and_delay);
  u32 v2 = clib_net_to_host_u32 (cch->delays);
  u32 r, a, x;
  r = v1 >> (32 - 22);
  a = ((v1 & ((1 << 10) - 1)) << 11) | ((v2 >> 21) & ((1 << 11) - 1));
  x = v2 & ((1 << 21) - 1);

  ASSERT (r == *rtt);
  ASSERT (x == *xmit_delay);
  ASSERT (a == *actual_delay);
}

static inline void
iptfs_cc_set_rtt_and_delays (ipsec_iptfs_cc_header_t *cch, u32 rtt, u32 actual_delay,
			     u32 xmit_delay)
{
  ASSERT (rtt <= IPTFS_CC_RTT_MAX);
  ASSERT (actual_delay <= IPTFS_CC_DELAY_MAX);
  ASSERT (actual_delay <= IPTFS_CC_DELAY_MAX);

  cch->rtt_and_adelay1[0] = (rtt >> 14) & 0xFF;
  cch->rtt_and_adelay1[1] = (rtt >> 6) & 0xFF;
  cch->rtt_and_adelay1[2] = (((rtt << 2) & 0xFC) | ((actual_delay >> (21 - 2)) & 0x03));
  cch->rtt_and_adelay1[3] = ((actual_delay >> (21 - 2 - 8)) & 0xFF);
  cch->adelay2_and_xdelay[0] = ((actual_delay >> (21 - 2 - 8 - 8)) & 0xFF);
  cch->adelay2_and_xdelay[1] =
    ((actual_delay << -(21 - 2 - 8 - 8 - 8)) & 0xE0) | ((xmit_delay >> (21 - 5)) & 0x1F);
  cch->adelay2_and_xdelay[2] = (xmit_delay >> 8) & 0xFF;
  cch->adelay2_and_xdelay[3] = (xmit_delay & 0xFF);

  volatile u32 old_rtt = rtt;
  volatile u32 old_xmit_delay = xmit_delay;
  (void) old_rtt;
  (void) old_xmit_delay;
  rtt <<= (32 - 22);
  rtt |= ((actual_delay >> 11) & ((1 << 10) - 1));
  rtt = clib_host_to_net_u32 (rtt);
  xmit_delay &= IPTFS_CC_DELAY_MASK;
  xmit_delay |= ((actual_delay & ((1 << 11) - 1)) << (32 - 11));
  xmit_delay = clib_host_to_net_u32 (xmit_delay);
  ASSERT (rtt == cch->rtt_and_delay);
  ASSERT (xmit_delay == cch->delays);
}

typedef CLIB_PACKED (union {
  ipsec_iptfs_basic_header_t basic;
  ipsec_iptfs_cc_header_t cc;
}) ipsec_iptfs_header_t;

#define foreach_ipsec_iptfs_hdr_flag                                                               \
  _ (IPSEC_IPTFS_HDR_FLAG_ECN, (1u << 0), "ecn")                                                   \
  _ (IPSEC_IPTFS_HDR_FLAG_P, (1u << 1), "p")

typedef enum
{
#define _(n, v, s) n = v,
  foreach_ipsec_iptfs_hdr_flag
#undef _
} ipsec_iptfs_hdr_flag_t;

typedef struct
{
  ipsec_iptfs_header_t h;
} iptfs_header_trace_t;

typedef enum
{
  IPTFS_POLLER_OUTPUT,
  IPTFS_POLLER_PACER,
  IPTFS_POLLER_ZPOOL,
  IPTFS_POLLER_ENCAP_ONLY,
  IPTFS_POLLER_COUNT,
} iptfs_polling_node_t;

#define foreach_iptfs_wk_range_type                                                                \
  _ (IPTFS_WK_RANGE_ENCAP, "encap")                                                                \
  _ (IPTFS_WK_RANGE_DECAP, "decap")                                                                \
  _ (IPTFS_WK_RANGE_DECRYPT, "decrypt")                                                            \
  _ (IPTFS_WK_RANGE_OUTPUT, "output")                                                              \
  _ (IPTFS_WK_RANGE_ZPOOL, "zpool")

typedef enum
{
#define _(n, s) n,
  foreach_iptfs_wk_range_type
#undef _
    IPTFS_WK_RANGE_COUNT
} iptfs_wk_range_type_t;

/*
 * Congestion Control Data
 *
 * u32 is fine for loss interval count, if we get more than 4G of packets with
 * no drops, we will restart the algorithm indicating zero loss.
 *
 * le_start_time is the start time of the loss event we wait for the sender's
 * RTT before wrapping things up (i.e., all loss during le_start_time + RTT is
 * considered to be part of the same event).
 *
 * For fix-rate we save the current time when processing a vector of received
 * packets, when we receive an out-of-order (future) seq no we save the
 * current time.
 */

/* We have 9 loss-intervals, 8 saved and the current one */
#define LOSS_INT_MAX 8
typedef struct
{
  u32 *li_ints;		  /* vector capacity LOSS_INT_MAX */
  u64 li_gen;		  /* generation of the LI vector */
  u64 li_last_gen;	  /* last time we ran the algorithm */
  u64 li_last_recalc;	  /* last time we ran the algorithm */
  u64 le_start_time;	  /* start of most recent loss event */
  u64 le_end_time;	  /* start of most recent loss event */
  u64 le_start_good_time; /* start of pkt prior to loss event */
  u64 le_rrtt_clks;	  /* rtt value when end time was set */
  u64 le_start_seq;	  /* lowest sequence of most recent loss event */
  u64 le_start_good_seq;  /* seq when good time was marked */
  u64 le_prev_end_seq;	  /* end squence from I_1 (previous) */
} iptfs_cc_data_t;

/*
 * IPTFS Per-SA config data
 */

typedef struct
{
  u64 tfs_ebyterate;		     /* L1 bytes per second */
  u64 tfs_byterate;		     /* L3 bytes per second */
  u64 tfs_max_delay;		     /* usec, used to determine maxq */
  u32 tfs_output_thread_index;	     /* thread to run output on */
  u32 tfs_decap_thread_index;	     /* hand decap tx duty to thread */
  u32 tfs_decrypt_thread_index;	     /* hand decrypt rx duty to thread */
  u32 tfs_encap_thread_index;	     /* hand encap tx duty to thread */
  u32 tfs_output_zpool_thread_index; /* allocate zbuffers thread */
  u32 tfs_encap_zpool_thread_index;  /* allocate zbuffers thread */
  u32 tfs_inbound_sa_id;	     /* inbound sa */
  u16 tfs_mtu;			     /* bytes per packet */
  u8 tfs_rewin;			     /* reorder window size */
  u8 tfs_df : 1;		     /* dont-fragment */
  u8 tfs_mode_type : 2;		     /* mode 1 (1.5) or 2 */
  u8 tfs_no_pad_only : 1;	     /* no-pad-only */
  u8 tfs_decap_chaining : 1;	     /* use-chaining for decap */
  u8 tfs_encap_chaining : 1;	     /* use-chaining for encap */
  u8 tfs_no_pad_trace : 1;	     /* set to avoid tracing all pad packets */
} ipsec_iptfs_config_t;

/*
 * IPTFS Per-SA operational data
 */

typedef struct ipsec_sa_iptfs_data
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  u16 tfs_mtu;			   /* IMMUTABLE: bytes per packet */
  u8 tfs_rewin;			   /* IMMUTABLE: reorder window size */
  u8 tfs_df : 1;		   /* IMMUTABLE: dont-fragment */
  u8 tfs_mode_type : 2;		   /* IMMUTABLE: mode 1 (1.5) or 2 */
  u8 tfs_no_pad_only : 1;	   /* IMMUTABLE: no-pad-only */
  u8 tfs_decap_chaining : 1;	   /* IMMUTABLE: use-chaining for decap */
  u8 tfs_encap_chaining : 1;	   /* IMMUTABLE: use-chaining for encap */
  u8 tfs_is_inbound : 1;	   /* IMMUTABLE: set if inbound SA */
  u8 tfs_ipv6 : 1;		   /* IMMUTABLE: if tunnel is ipv6 */
  u8 tfs_cc : 1;		   /* IMMUTABLE: use congestion control (unimpl) */
  u8 tfs_input_running : 1;	   /* True if SA inbound is running */
  u8 tfs_output_running : 1;	   /* True if SA outbound is running */
  u8 tfs_encap_zpool_running : 1;  /* True if zpool for SA is running */
  u8 tfs_output_zpool_running : 1; /* True if zpool for SA is running */
  u8 tfs_pad_req_pending : 1;	   /* set if a pad buffer request is pending */
  u8 tfs_no_pad_trace : 1;	   /* set to avoid tracing all pad packets */
  f64 clocks_per_usec;		   /* used in CC mode to calculate RTT */
  f64 usecs_per_clock;		   /* used in CC mode to calculate RTT */
  struct
  {
    u32 infirst;		/* packet being constructed */
    vlib_buffer_t *inlastb;	/* last in chain of packet being constructed */
    iptfs_bufq outq;		/* Queue of completed iptfs */
    iptfs_bufq_limit limit;	/* Queue size and limit */
    u64 lastdue;		/* last time a packet was supposed sent */
    u32 *buffers;		/* scratch vec for allocating buffers */
    iptfs_zpool_t *zpool;	/* zpool for enacp */
    u32 encap_thread_index;	/* The encap thread used for this SA */
    u32 output_thread_index;	/* The output thread used for this SA */
    u16 q_packet_avail;		/* Avail in the top packet */
    u16 tfs_ipsec_payload_size; /* The IPTFS packet size (w/o ipsec) */
    u16 tfs_payload_size;	/* The IPTFS payload size (user) */
    f64 cc_x;			/* basis for pdelay - pps */
    f64 *cc_x_recv_set;		/* RFC5348 */
    u64 *cc_x_recv_set_ts;	/* RFC5348 */
    u64 cc_next_check;		/* when we can next check for CC */
    u64 pd_lastinfo_ts;		/* TS of last lossinfo used */
    u64 pd_tld;			/* Time last doubled for slow-start */
    u64 cc_rto;			/* RTO timeout for CC data  */
    u64 cc_rto_ts;		/* RTO timeout for CC data  */
    u32 pd_loss_rate;		/* Loss rate used for CC algo */
    u32 pd_our_rtt;		/* Our RTT estimate used in CC algo */
    u32 pd_our_rtt_clks;	/* Our RTT estimate used in CC algo */
    u32 cc_inb_sa_index;	/* The paired SA for CC mode */
#if IPTFS_ENABLE_PACER_EVENT_LOGS
    elog_track_t pacer_track; /* The elog pacer track for this SA */
#endif
#if IPTFS_ENABLE_ZPOOL_EVENT_LOGS
    elog_track_t zpool_track; /* The elog zpool track for this SA */
#endif
    u32 zpool_thread_index; /* The zpool thread used for this SA, this
			       doesn't get accessed in the fast-path so
			       leave at the bottom */
  } tfs_encap;
  struct
  {
    SRING_RING (IPTFS_TXQ_LOG2, u32) q; /* Lockless rx->tx ring */
    u64 lastdue;			/* last time a packet was supposed sent */
    volatile u64 pdelay;		/* clocks between packet send */
    iptfs_zpool_t *zpool;		/* zpool for output */
#ifdef IPTFS_DEBUG_CORRUPTION
    u64 encap_seq; /* used for debugging */
#endif
    u16 output_gen; /* used to debug traces */
#if IPTFS_ENABLE_OUTPUT_EVENT_LOGS
    elog_track_t output_track; /* The elog output track for this SA */
#endif
#if IPTFS_ENABLE_ZPOOL_EVENT_LOGS
    elog_track_t zpool_track; /* The elog output track for this SA */
#endif
    u32 zpool_thread_index; /* The output zpool thread used for this SA, this
			       doesn't get accessed in the fast-path so
			       leave at the bottom */
  } tfs_tx;
  struct
  {
    CLIB_CACHE_LINE_ALIGN_MARK (cacheline1);

    /* This code is not thread safe -- see comment (A) in decap_reorder */
    u64 nextseq;	       /* expected next sequence number */
    u64 frag_nseq;	       /* expected next frag sequence number */
    u32 *win;		       /* vector of reorder buffers */
    u64 recv_clock;	       /* clock of last rx (post-reorder) packet */
    u64 recv_seq;	       /* seq when clock was taken */
    u32 frag_bi;	       /* in-progress fragmentation buffer */
    vlib_buffer_t *frag_lastb; /* in-progress last buffer in chain */

    u32 cc_out_sa_index;	 /* The paired SA for CC mode */
    iptfs_cc_data_t cc_data;	 /* data used for calculating CC info */
    volatile u64 cc_lastvals;	 /* combination of their tval and cpu usecs */
    volatile u64 cc_lossinfo;	 /* combination of rlrate and our RTT */
    volatile u64 cc_lossinfo_ts; /* time we set the loss info */
    volatile u32 cc_llrate_net;	 /* our calculated loss rate net-order */
    u64 cc_rrtt_clks;		 /* remote RTT in our clks */
    u32 cc_rrtt;		 /* their advertised RTT for lrate calc */
    volatile u64 cc_delact;	 /* Used for show commands */
    u32 decap_thread_index;	 /* thread to hand-off packets to */
    u32 decrypt_thread_index;	 /* thread to hand-off packets to */
#if IPTFS_ENABLE_DECAP_EVENT_LOGS
    elog_track_t decap_track; /* The elog decap track for this SA */
#endif
#if IPTFS_ENABLE_CC_EVENT_LOGS
    elog_track_t cc_track; /* The elog decap track for this SA */
#endif
  } tfs_rx;
  elog_track_t tfs_error_track; /* The elog error track for this SA */
  u32 tfs_use_count;
  u16 tfs_old_mtu; /* IMMUTABLE: Old MTU on TUN if we changed */
  const ipsec_iptfs_config_t *tfs_config;
} iptfs_sa_data_t;

/* Getter so that value is atomically got */
static inline void
iptfs_rx_get_lastvals (iptfs_sa_data_t *satd, u32 *their_tval, u32 *last_time)
{
  u64 lv = satd->tfs_rx.cc_lastvals;
  *their_tval = (lv >> 32) & 0xFFFFFFFF;
  *last_time = lv & 0xFFFFFFFF;
}

/* Setter so that value is atomically set */
static inline void
iptfs_rx_set_lastvals (iptfs_sa_data_t *satd, u32 their_tval, u32 last_time)
{
  u64 lv = ((u64) their_tval) << 32;
  lv |= last_time & 0xFFFFFFFF;
  satd->tfs_rx.cc_lastvals = lv;
}

static inline void
iptfs_rx_get_delay_actual_for_show (iptfs_sa_data_t *satd, u32 *actual_delay, u32 *xmit_delay,
				    u32 *actual)
{
  u64 v = satd->tfs_rx.cc_delact;
  *actual = v >> (64 - 22);
  *actual_delay = (v >> (64 - 22 - 21)) & IPTFS_CC_DELAY_MASK;
  *xmit_delay = v & IPTFS_CC_DELAY_MASK;
}

/* Setter so that value is atomically set */
static inline void
iptfs_rx_set_delay_actual_for_show (iptfs_sa_data_t *satd, u32 actual_delay, u32 xmit_delay,
				    u32 actual)
{
  u64 v = ((u64) actual) << (64 - 22);
  v |= (actual_delay & IPTFS_CC_DELAY_MASK) << (64 - 22 - 21);
  v |= (xmit_delay & IPTFS_CC_DELAY_MASK);
  satd->tfs_rx.cc_delact = v;
}

static inline u32
iptfs_rx_get_loss_info_rtt_v (u64 v)
{
  return (v >> 32) & IPTFS_CC_RTT_MASK;
}

static inline void
iptfs_rx_get_loss_info_v (u64 v, u32 *our_rtt, u32 *loss_rate)
{
  *our_rtt = (v >> 32) & IPTFS_CC_RTT_MASK;
  *loss_rate = v & 0xFFFFFFFF;
}

static inline void
iptfs_rx_get_loss_info (iptfs_sa_data_t *satd, u32 *our_rtt, u32 *loss_rate)
{
  return iptfs_rx_get_loss_info_v (satd->tfs_rx.cc_lossinfo, our_rtt, loss_rate);
}

/* Setter so that value is atomically set */
static inline void
iptfs_rx_set_loss_info (iptfs_sa_data_t *satd, u32 our_rtt, u32 loss_rate, u64 now)
{
  ASSERT (our_rtt <= IPTFS_CC_RTT_MAX);

  u64 v = ((u64) our_rtt) << 32;
  v |= loss_rate & 0xFFFFFFFF;
  satd->tfs_rx.cc_lossinfo = v;
  /* update this after updating the info */
  satd->tfs_rx.cc_lossinfo_ts = now;
}

static inline f64
iptfs_cc_check_min_rate (f64 x)
{
  if (x < IPTFS_CC_MIN_PPS)
    x = IPTFS_CC_MIN_PPS;
  return x;
}

static inline void
iptfs_update_clocks_per_usec (vlib_main_t *vm, iptfs_sa_data_t *satd)
{
  satd->clocks_per_usec = vm->clib_time.clocks_per_second / 1e6;
  /* Avoid FP division in fast path by doig it here once */
  satd->usecs_per_clock = 1.0 / satd->clocks_per_usec;
}

static inline u64
iptfs_get_cpu_usec (iptfs_sa_data_t *satd, u64 clks)
{
  return clks * satd->usecs_per_clock;
}

static inline u32
iptfs_get_cpu_tval (u64 clks)
{
  /* divide by 256 and mask to 32 bits */
  return (clks >> 8);
}

static inline u32
iptfs_tval_to_usec (iptfs_sa_data_t *satd, u32 tval)
{
  /* multiply by 256 and then by usecs per clock */
  return satd->usecs_per_clock * (tval << 8);
}

#define iptfs_sa_data_hdrlen(satd)                                                                 \
  (!(satd)->tfs_cc ? sizeof (ipsec_iptfs_basic_header_t) : sizeof (ipsec_iptfs_cc_header_t))

#define iptfs_get_sa_data(sa_index)                                                                \
  ({                                                                                               \
    iptfs_assert (sa_index < vec_len (ipsec_iptfs_main.sa_data));                                  \
    ipsec_iptfs_main.sa_data + sa_index;                                                           \
  })

#define iptfs_sa_data_to_index(satd)                                                               \
  ({                                                                                               \
    u32 sa_index = satd - ipsec_iptfs_main.sa_data;                                                \
    ASSERT (sa_index < vec_len (ipsec_iptfs_main.sa_data));                                        \
    sa_index;                                                                                      \
  })

#define iptfs_sa_data_to_sa(satd)                                                                  \
  pool_elt_at_index (ipsec_main.sad, (satd - ipsec_iptfs_main.sa_data))

#define iptfs_is_sa_index_possible_IPTFS(sa_index)                                                 \
  ({                                                                                               \
    int _rv = 0;                                                                                   \
    if ((sa_index) != ~0)                                                                          \
      {                                                                                            \
	ipsec_sa_t *_sa = ipsec_sa_get (sa_index);                                                 \
	if (_sa->tfs_type != IPSEC_SA_TFS_TYPE_NO_TFS)                                             \
	  _rv = 1;                                                                                 \
	else if (!IPTFS_ENABLE_GLOBAL_RX_MODE || !ipsec_sa_is_set_IS_TUNNEL (_sa) ||               \
		 !ipsec_sa_is_set_IS_INBOUND (_sa))                                                \
	  _rv = 0;                                                                                 \
	else                                                                                       \
	  _rv = 1;                                                                                 \
      }                                                                                            \
    _rv;                                                                                           \
  })

#define iptfs_is_sa_index_valid(sa_index)                                                          \
  ({                                                                                               \
    int _rv = 0;                                                                                   \
    if (iptfs_is_sa_index_possible_IPTFS (sa_index))                                               \
      {                                                                                            \
	if (vec_len (ipsec_iptfs_main.sa_data) > sa_index)                                         \
	  {                                                                                        \
	    iptfs_sa_data_t *satd = iptfs_get_sa_data (sa_index);                                  \
	    if (satd->tfs_config)                                                                  \
	      _rv = 1;                                                                             \
	  }                                                                                        \
      }                                                                                            \
    _rv;                                                                                           \
  })

/*
 * There are places in the code we predict wther min rate mode is selected,
 * normally this is not the case but if it is change this to PREDICT_TRUE
 */
#define iptfs_is_min_rate(satd) PREDICT_FALSE ((satd)->tfs_mode_type == IPTFS_MODE_TYPE_MIN_RATE)

#define IPTFS_ENET_OHEAD (14 + 4 + 8 + 12)

#define iptfs_conf_pps(conf)                                                                       \
  ((conf)->tfs_ebyterate ? ((f64) (conf)->tfs_ebyterate / ((conf)->tfs_mtu + IPTFS_ENET_OHEAD)) :  \
			   ((f64) (conf)->tfs_byterate / (conf)->tfs_mtu))

#define foreach_ipsec_iptfs_default                                                                \
  _ (IPSEC_IPTFS_DEFAULT_MTU, 1500, "mtu")                                                         \
  _ (IPSEC_IPTFS_DEFAULT_MAX_DELAY, 0, "max-delay")                                                \
  _ (IPSEC_IPTFS_DEFAULT_REORDER_WINDOW, 5, "reorder-window")

typedef enum
{
#define _(n, v, s) n = (v),
  foreach_ipsec_iptfs_default
#undef _
} ipsec_iptfs_default_t;

#define IPTFS_MAX_REORDER_WINDOW 10

#define foreach_iptfs_event_type _ (IPTFS_EVENT_TYPE_MORE_BUFFERS, "more-buffers")

typedef enum
{
#define _(n, s) n,
  foreach_iptfs_event_type
#undef _
    IPTFS_EVENT_N_TYPES
} iptfs_event_type_t;

/* This is stored in 2-bit field so change tfs_mode_type if adding more */
#define foreach_iptfs_mode_type                                                                    \
  _ (IPTFS_MODE_TYPE_FIXED_RATE, "fixed-rate")                                                     \
  _ (IPTFS_MODE_TYPE_ENCAP_ONLY, "encap-only")                                                     \
  _ (IPTFS_MODE_TYPE_MIN_RATE, "min-rate")

typedef enum
{
#define _(n, s) n,
  foreach_iptfs_mode_type
#undef _
    IPTFS_N_MODES
} iptfs_mode_type_t;

/*
 * Per-thread data
 */

#define IPTFS_DEBUG_STRING_COUNT 4096

/*
 * Lock priorities.
 *
 * thread-ZPOOL-ACTIVE > per-SA-BUFQ
 * thread-ACTIVE > per-SA-BUFQ
 */

typedef struct
{
  u32 *sa_active[IPTFS_POLLER_COUNT];
  u32 *sa_encap_only_active;
  u32 *cc_decap_run;
  u32 *cc_decap_save;
  u32 debug_idx;
  u8 *debug_strings[IPTFS_DEBUG_STRING_COUNT];
} iptfs_thread_main_t;

/*
 * Counters and Guages
 */
#define IPTFS_ENABLE_EXTENDED_COUNTERS

#if IPTFS_UNUSED_GAUGES
#define foreach_iptfs_gauge _ (IPTFS_GAUGE_PPS, "pps")

typedef enum
{
#define _(E, n, f) E,
  foreach_iptfs_gauge
#undef _
    IPTFS_GAUGE_N_GAUGES
} iptfs_gauge_t;
#endif

#ifdef IPTFS_ENABLE_EXTENDED_COUNTERS
#define foreach_iptfs_counter                                                                      \
  _ (IPTFS_CNT_DECAP_RX_ALL_PAD, "decap-rx-all-pad")                                               \
  _ (IPTFS_CNT_DECAP_RX_ENDS_WITH_FRAG, "decap-rx-ends-with-frag")                                 \
  _ (IPTFS_CNT_DECAP_RX_NO_REUSE, "decap-rx-no-reuse")                                             \
  _ (IPTFS_CNT_DECAP_TX_CHAINED, "decap-tx-chained-buffer")                                        \
  _ (IPTFS_CNT_DECAP_TX_INDIRECT, "decap-tx-indirect-buffer")                                      \
  _ (IPTFS_CNT_DECAP_TX_REUSED, "decap-tx-reused-buffer")                                          \
  _ (IPTFS_CNT_DECAP_TX_COPIED, "decap-tx-copied-to-buffer")                                       \
  _ (IPTFS_CNT_ZPOOL_MORE_SIGNALED, "zpool-more-signaled")                                         \
  _ (IPTFS_CNT_ENCAP_Q_FULL, "encap-rxq-full")                                                     \
  _ (IPTFS_CNT_ENCAP_STRADDLE_COPY, "encap-straddle-copy")                                         \
  _ (IPTFS_CNT_ENCAP_PADOUT, "encap-padout")                                                       \
  _ (IPTFS_CNT_OUTPUT_TX_FASTER, "output-tx-faster")                                               \
  _ (IPTFS_CNT_OUTPUT_TX_ALL_PADS, "output-tx-all-pads")                                           \
  _ (IPTFS_CNT_OUTPUT_TX_PAD_ADD, "output-tx-pad-add")                                             \
  _ (IPTFS_CNT_OUTPUT_TX_PAD_INS, "output-tx-pad-insert")                                          \
  _ (IPTFS_CNT_PACER_EMPTY_SLOTS, "pacer-tx-empty-slots")                                          \
  _ (IPTFS_CNT_PPS, "tx-pps")                                                                      \
  _ (IPTFS_CNT_RTT, "tx-rtt")                                                                      \
  _ (IPTFS_CNT_LOSS_RATE, "tx-lossrate")                                                           \
  _ (IPTFS_CNT_ZPOOL_FILLED, "zpool-filled")
#else
#define foreach_iptfs_counter                                                                      \
  _ (IPTFS_CNT_DECAP_RX_ALL_PAD, "decap-rx-all-pad")                                               \
  _ (IPTFS_CNT_ZPOOL_MORE_SIGNALED, "zpool-more-signaled")                                         \
  _ (IPTFS_CNT_ENCAP_Q_FULL, "encap-rxq-full")                                                     \
  _ (IPTFS_CNT_ENCAP_PADOUT, "encap-padout")                                                       \
  _ (IPTFS_CNT_OUTPUT_TX_FASTER, "output-tx-faster")                                               \
  _ (IPTFS_CNT_OUTPUT_TX_ALL_PADS, "output-tx-all-pads")                                           \
  _ (IPTFS_CNT_OUTPUT_TX_PAD_ADD, "output-tx-pad-add")                                             \
  _ (IPTFS_CNT_OUTPUT_TX_PAD_INS, "output-tx-pad-insert")                                          \
  _ (IPTFS_CNT_PPS, "tx-pps")                                                                      \
  _ (IPTFS_CNT_RTT, "tx-rtt")                                                                      \
  _ (IPTFS_CNT_LOSS_RATE, "tx-lossrate")                                                           \
  _ (IPTFS_CNT_ZPOOL_FILLED, "zpool-filled")
#endif

typedef enum
{
#define _(E, n) E,
  foreach_iptfs_counter
#undef _
    IPTFS_CNT_N_COUNTERS
} iptfs_counter_t;

#ifdef IPTFS_ENABLE_EXTENDED_COUNTERS
#define foreach_iptfs_pcounter                                                                     \
  _ (IPTFS_PCNT_DECAP_RX_PAD_DATABLOCK_EXC, "decap-rx-pad-datablock-exc")                          \
  _ (IPTFS_PCNT_DECAP_RX_PAD_DATABLOCK, "decap-rx-pad-datablock")                                  \
  _ (IPTFS_PCNT_DECAP_RX, "decap-rx")                                                              \
  _ (IPTFS_PCNT_DECAP_TX, "decap-tx")                                                              \
  _ (IPTFS_PCNT_DECAP_TX_HDR_COPY, "decap-tx-hdr-copy")                                            \
  _ (IPTFS_PCNT_ENCAP_RX, "encap-rx")                                                              \
  _ (IPTFS_PCNT_ENCAP_TX, "encap-tx")                                                              \
  _ (IPTFS_PCNT_OUTPUT_RX, "output-rx")                                                            \
  _ (IPTFS_PCNT_OUTPUT_TX, "output-tx")                                                            \
  _ (IPTFS_PCNT_PACER_RX, "pacer-rx")                                                              \
  _ (IPTFS_PCNT_PACER_TX, "pacer-tx")
#else
#define foreach_iptfs_pcounter                                                                     \
  _ (IPTFS_PCNT_DECAP_RX, "decap-rx")                                                              \
  _ (IPTFS_PCNT_DECAP_TX, "decap-tx")                                                              \
  _ (IPTFS_PCNT_ENCAP_RX, "encap-rx")                                                              \
  _ (IPTFS_PCNT_ENCAP_TX, "encap-tx")                                                              \
  _ (IPTFS_PCNT_OUTPUT_RX, "output-rx")                                                            \
  _ (IPTFS_PCNT_OUTPUT_TX, "output-tx")                                                            \
  _ (IPTFS_PCNT_PACER_RX, "pacer-rx")                                                              \
  _ (IPTFS_PCNT_PACER_TX, "pacer-tx")
#endif

typedef enum
{
#define _(E, n) E,
  foreach_iptfs_pcounter
#undef _
    IPTFS_PCNT_N_COUNTERS
} iptfs_pcounter_t;

typedef struct
{
  u32 first;
  u32 last;
  u32 next;
} iptfs_worker_range_t;

/*
 * Global data
 */

typedef struct
{
  iptfs_sa_data_t *sa_data; /* Per SA IP_TFS data */
  u32 *if_to_sa;	    /* ipsec interface to output SA map */
  iptfs_worker_range_t worker_range;
  iptfs_worker_range_t wk_ranges[IPTFS_WK_RANGE_COUNT];
  iptfs_thread_main_t *workers_main;
  u32 encap4_tun_feature_index;
  u32 encap6_tun_feature_index;
#if IPTFS_ENABLE_ENCAP_MULTITHREAD
  u32 encap_frame_queue; /* handoff loopback frame-queue */
#endif
  u32 decap_frame_queue;	 /* handoff decap frame queue */
  uword *handoff_queue_by_index; /* hash of handoff queues for encrypt */
  u32 encap4_only_frame_queue;	 /* handoff queue to encrypt */
  u32 encap6_only_frame_queue;	 /* handoff queue to encrypt */

  vlib_simple_counter_main_t cm[IPTFS_CNT_N_COUNTERS];
  vlib_combined_counter_main_t pcm[IPTFS_PCNT_N_COUNTERS];
#ifdef IPTFS_ENCRYPT_PREOUTPUT
  u32 output_enq4_tun_feature_index;
  u32 output_enq6_tun_feature_index;
#endif
  u16 msg_id_base; /* API message ID base */
} ipsec_iptfs_main_t;

extern ipsec_iptfs_main_t ipsec_iptfs_main;
extern vlib_node_registration_t iptfs_decap_node;
extern vlib_node_registration_t iptfs_encap_enq_node;
#if IPTFS_ENABLE_ENCAP_MULTITHREAD
extern vlib_node_registration_t iptfs_encap_handoff_node;
#endif
extern vlib_node_registration_t iptfs_encap4_tun_node;
extern vlib_node_registration_t iptfs_encap6_tun_node;
extern vlib_node_registration_t iptfs_output_node;
extern vlib_node_registration_t iptfs_pacer_node;

/*
 * Buffer fields
 *
 * Intra-iptfs: use opaque2 area
 *	(encap path debug)	u64 esp_seq_debug
 *	(encap path)		u16 tfs_actual_data
 *	(encap path)		1-bit iptfs_reused_user
 *
 * IPTFS->IPSEC:
 *	iptfs sets ipsec.sad_index
 *
 * IPSEC->IPTFS:
 *	ipsec sets u64 ipsec.esp_seq
 *	ipsec sets u32 ipsec.sad_index
 */
typedef struct
{
  union
  {
    struct
    {
      u16 tfs_actual_data;
      u8 iptfs_reused_user : 1;
      u64 esp_seq_debug;
    } encap;
  };
} ipsec_private_data_t;

/* Fit into u32 unused[6] of vnet buffer opaque union (overlaps ipsec) */
STATIC_ASSERT (sizeof (ipsec_private_data_t) <= STRUCT_SIZE_OF (vnet_buffer_opaque_t, unused),
	       "Custom iptfs private data too large for vnet_buffer_opaque_t");

#define iptfs_private(b)                                                                           \
  ((ipsec_private_data_t *) ((u8 *) ((b)->opaque2) +                                               \
			     STRUCT_OFFSET_OF (vnet_buffer_opaque2_t, unused)))

/*
 * ELOG
 */

#define IPTFS_ELOGP(e, t) elog_data_inline (vlib_global_main.elog_main, (e), (t))

#define IPTFS_ELOG(e, t) ELOG_TRACK_DATA_INLINE (vlib_global_main.elog_main, (e), (t))

#define IPTFS_ELOG_DEFAULT_TRACK(e)                                                                \
  ELOG_TRACK_DATA_INLINE (vlib_global_main.elog_main, (e),                                         \
			  vlib_global_main.elog_main->default_track)

#define IPTFS_ELOG_THREAD(e, thread_index)                                                         \
  IPTFS_ELOG ((e), vlib_worker_threads[(thread_index)].elog_track)

#define IPTFS_ELOG_CURRENT_THREAD(e) IPTFS_ELOG_THREAD ((e), vlib_get_thread_index ())

/*
 * Debug Strings
 */

always_inline u8 **
iptfs_next_debug_string (void)
{
#ifdef IPTFS_DEBUG_CORRUPTION
  iptfs_thread_main_t *tm =
    vec_elt_at_index (ipsec_iptfs_main.workers_main, vlib_get_thread_index ());
  u8 **dbg = &tm->debug_strings[tm->debug_idx++];
  if (tm->debug_idx == IPTFS_DEBUG_STRING_COUNT)
    tm->debug_idx = 0;
  vec_reset_length (*dbg);
  *dbg = format (*dbg, "");
  return dbg;
#else
  return NULL;
#endif
}

/*
 * Counters and gauges
 */
#if IPTFS_UNUSED_GAUGES
#ifdef IPTFS_DISABLE_GAUGES
#define iptfs_set_gauge(gauge, thread_index, index, value)
#else
always_inline void
iptfs_set_gauge (uint gauge, u32 thread_index, uint index, f64 value)
{
  vlib_set_simple_counter (&ipsec_itpfs_main.gm[gauge], thread_index, index, value);
}
#endif
#endif

#ifdef IPTFS_DISABLE_SCOUNTERS
#define iptfs_set_counter(counter, thread_index, index, count)
#define iptfs_inc_counter(counter, thread_index, index, count)
#define iptfs_prefetch_counter(counter, thread_index, index)
#else
always_inline void
iptfs_set_counter (uint counter, u32 thread_index, uint index, u64 value)
{
  vlib_set_simple_counter (&ipsec_iptfs_main.cm[counter], thread_index, index, value);
}

always_inline void
iptfs_inc_counter (uint counter, u32 thread_index, uint index, uint count)
{
  vlib_increment_simple_counter (&ipsec_iptfs_main.cm[counter], thread_index, index, count);
}

always_inline void
iptfs_prefetch_counter (uint counter, u32 thread_index, uint index)
{
  counter_t *counters = ipsec_iptfs_main.cm[counter].counters[thread_index];
  CLIB_PREFETCH (counters + index, CLIB_CACHE_LINE_BYTES, STORE);
}
#endif

#ifdef IPTFS_DISABLE_PCOUNTERS
#define iptfs_inc_pcounter(counter, thread_index, index, pcount, pbytes)
#define iptfs_prefetch_pcounter(counter, thread_index, index)
#else
always_inline void
iptfs_inc_pcounter (uint counter, u32 thread_index, uint index, uint pcount, uint pbytes)
{
  vlib_increment_combined_counter (&ipsec_iptfs_main.pcm[counter], thread_index, index, pcount,
				   pbytes);
}

always_inline void
iptfs_prefetch_pcounter (uint counter, u32 thread_index, uint index)
{
  vlib_prefetch_combined_counter (&ipsec_iptfs_main.pcm[counter], thread_index, index);
}
#endif

#ifdef IPTFS_ENABLE_EXTENDED_COUNTERS
#define iptfs_inc_x_counter(counter, thread_index, index, count)                                   \
  iptfs_inc_counter (counter, thread_index, index, count)
#define iptfs_prefetch_x_counter(counter, thread_index, index)                                     \
  iptfs_prefetch_counter (counter, thread_index, index)
#define iptfs_inc_x_pcounter(counter, thread_index, index, pcount, pbytes)                         \
  iptfs_inc_pcounter (counter, thread_index, index, pcount, pbytes)
#define iptfs_prefetch_x_pcounter(counter, thread_index, index)                                    \
  iptfs_prefetch_pcounter (counter, thread_index, index)
#else
#define iptfs_inc_x_counter(counter, thread_index, index, count)
#define iptfs_prefetch_x_counter(counter, thread_index, index)
#define iptfs_inc_x_pcounter(counter, thread_index, index, pcount, pbytes)
#define iptfs_prefetch_x_pcounter(counter, thread_index, index)
#endif

void iptfs_buffer_free (vlib_main_t *vm, u32 *buffers, u32 n_buffers);

/*
 * Initialize count IPTFS buffers for encap use.
 */
static inline bool
iptfs_alloc_buffers (vlib_main_t *vm, u32 *bi, uword count)
{
  uword actual = vlib_buffer_alloc (vm, bi, count);
  if (PREDICT_FALSE ((actual != count)))
    {
      clib_warning ("%s: Failed to get output %u buffers (got %u)", __FUNCTION__, count, actual);
      if (actual)
	iptfs_buffer_free (vm, bi, actual);
      return false;
    }
  return true;
}

/*
 * Initialize an IPTFS buffer for encap use.
 */
always_inline void
iptfs_init_buffer (vlib_main_t *vm, vlib_buffer_t *b, u32 sa_index)
{
  VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b);
  vnet_buffer (b)->ipsec.sad_index = sa_index;

  clib_memset (iptfs_private (b), 0, sizeof (*iptfs_private (b)));
  iptfs_private (b)->encap.iptfs_reused_user = false;

  /* 0 Represents local0 */
  ASSERT (vnet_buffer (b)->sw_if_index[VLIB_RX] == 0);

  /*
   * Generic default would be ~0; however, that means "use FIB index of VLIB_RX
   * interface", and local0's default FIB index is 0 so no need to set this.
   */
  ASSERT (vnet_buffer (b)->sw_if_index[VLIB_TX] == 0);

  /*
   * Do not set VNET_BUFFER_F_LOCALLY_ORIGINATED.
   *
   * For IPv4 and IPv6 it skips checksum calculation and ttl and is predicted
   * false branch in IPv4. In IPv6 it also enables local fragmentation which we
   * are definitely not interested in.
   */

  /*
   * We want all the flags clear except possibly VLIB_BUFFER_EXT_HDR_VALID,
   * and other user flags which may be set by DPDK (or other) templates
   */
  ASSERT (!(b->flags & (VLIB_BUFFER_FLAGS_ALL & ~VLIB_BUFFER_EXT_HDR_VALID)));
  ASSERT (b->current_data == 0);
  ASSERT (b->current_length == 0);
}

/*
 * Initialize an IPTFS buffer for encap use.
 */
always_inline vlib_buffer_t *
iptfs_check_empty_buffer (vlib_main_t *vm, u32 bi, u32 sa_index)
{
  vlib_buffer_t *b = vlib_get_buffer (vm, bi);
  /*
   * Just verify everything is as we expect it to be
   */
  ASSERT (vnet_buffer (b)->ipsec.sad_index == sa_index);
  ASSERT (vnet_buffer (b)->sw_if_index[VLIB_RX] == 0);
  ASSERT (vnet_buffer (b)->sw_if_index[VLIB_TX] == 0);
  ASSERT (!(b->flags & (VLIB_BUFFER_FLAGS_ALL & ~VLIB_BUFFER_EXT_HDR_VALID)));
  ASSERT (b->current_data == 0);
  ASSERT (b->current_length == 0);
  // We should always have 36+14 bytes in the pre-data area for this.
  // vlib_buffer_make_headroom (b, sizeof (ip4_and_udp_and_esp_header_t));
  return b;
}

#define vlib_node_increment_counter_p(vm, node, cnt, eto, to)                                      \
  do                                                                                               \
    {                                                                                              \
      vlib_node_increment_counter ((vm), (node)->node_index, (cnt),                                \
				   VLIB_FRAME_SIZE - ((eto) - (to)));                              \
    }                                                                                              \
  while (0)

#define vlib_put_next_frame_with_cnt(vm, node, ni, to, eto, cnt)                                   \
  do                                                                                               \
    {                                                                                              \
      if ((to))                                                                                    \
	{                                                                                          \
	  vlib_put_next_frame ((vm), (node), (ni), (eto) - (to));                                  \
	  if (cnt != ~0)                                                                           \
	    vlib_node_increment_counter_p ((vm), (node), (cnt), (eto), (to));                      \
	}                                                                                          \
    }                                                                                              \
  while (0)

#define vlib_put_get_next_frame(vm, node, ni, to, eto, cnt)                                        \
  do                                                                                               \
    {                                                                                              \
      /* Put the frame if it is full */                                                            \
      if ((to) && (eto) != (to))                                                                   \
	;                                                                                          \
      else                                                                                         \
	{                                                                                          \
	  vlib_put_next_frame_with_cnt (vm, node, ni, to, eto, cnt);                               \
	  vlib_get_next_frame_p ((vm), (node), (ni), (to), (eto));                                 \
	}                                                                                          \
    }                                                                                              \
  while (0)

#define vlib_put_get_next_frame_a(vm, node, ni, toa, etoa)                                         \
  vlib_put_get_next_frame (vm, node, ni, (toa)[(ni)], (etoa)[(ni)], ~0)

static inline void
vlib_put_get_next (vlib_main_t *vm, vlib_node_runtime_t *node, u32 next_index, u32 *from, u32 count,
		   u32 **top, u32 **etop)
{
  u32 *to = *top, *eto = *etop;
  u32 copied = 0;
  while (count)
    {
      vlib_put_get_next_frame (vm, node, next_index, to, eto, ~0);
      copied = clib_min (count, eto - to);
      clib_memcpy_fast (to, from, copied * sizeof (*to));
      from += copied;
      to += copied;
      count -= copied;
    }
  *top = to;
  *etop = eto;
}

static inline int
half_range (vlib_buffer_t **start, vlib_buffer_t **end, u32 limit)
{
  u32 range = (end - start) / 2;
  return range < limit ? range : limit;
}

#ifndef CLIB_N_PREFETCHES
#define CLIB_N_PREFETCHES 4
#endif /* CLIB_N_PREFETCHES */

/* These values are twice what is prefetched */
#define IPTFS_N_PREFETCH_DECAP_REORDER 8 /* No data, no write */
#define IPTFS_N_PREFETCH_DECAP	       2
#define IPTFS_N_PREFETCH_ENCAP	       2
#define IPTFS_N_PREFETCH_ENCAP_HANDOFF 8
#define IPTFS_N_PREFETCH_OUTPUT	       8 /* No data, no write, small loop */

#define CACHE_LINE_MASK(a)	 ((uword) (a) & ~(CLIB_CACHE_LINE_BYTES - 1))
#define CACHE_LINE_MASK_BYTES(a) ((u8 *) ((uword) (a) & ~(CLIB_CACHE_LINE_BYTES - 1)))

#define _FOREACH_PREFETCH(b, eb, nprefetch, type, wdata)                                           \
  do                                                                                               \
    {                                                                                              \
      vlib_buffer_t **bp, **ebp;                                                                   \
      for (u32 half = half_range ((b), (eb), (nprefetch)); (b) < (eb);                             \
	   half = half_range ((b), (eb), (nprefetch)))                                             \
	{                                                                                          \
	  /* prefetch second half */                                                               \
	  if (half)                                                                                \
	    {                                                                                      \
	      for (bp = (b) + half, ebp = bp + half; bp < ebp; bp++)                               \
		{                                                                                  \
		  vlib_prefetch_buffer_header (*bp, type);                                         \
		  if (wdata)                                                                       \
		    vlib_prefetch_buffer_data (*bp, type);                                         \
		}                                                                                  \
	    }                                                                                      \
	  else                                                                                     \
	    half = 1; /* Process at least one next */                                              \
                                                                                                   \
	  /* process first half or last one */                                                     \
	  for (ebp = (b) + half; (b) < ebp; (b)++)
// for (ebp = (b) + half; (b) < ebp && to < eto; (b)++)

#define END_FOREACH_PREFETCH                                                                       \
  }                                                                                                \
  }                                                                                                \
  while (0)

#define FOREACH_PREFETCH(b, eb, nprefetch) _FOREACH_PREFETCH (b, eb, nprefetch, LOAD, 0)

#define FOREACH_PREFETCH_WITH_DATA(b, eb, nprefetch, type)                                         \
  _FOREACH_PREFETCH (b, eb, nprefetch, type, 1)

/*
 * Packet tracing data
 */

typedef struct
{
  u8 type;
  u16 offset;
  u16 pktlen;
} iptfs_datablock_trace_t;

typedef struct
{
  u8 is_decap : 1;	  /* If this is actually result of decap */
  u8 bad_header : 1;	  /* If the header was bad. */
  u8 bad_decode : 1;	  /* If the header was bad. */
  u8 header_straddle : 1; /* If the header was bad. */
  u16 ndb;		  /* Number of db that follow */
  u32 esp_seq;		  /* ESP sequence (lo) if decap */
  u32 sad_index;
  u16 output_gen;      /* generation num of the output routine */
  u16 output_ord;      /* ordinal of packet sent from the generation */
  u16 output_last_ord; /* last ordinal of the output to send */
  u16 iptfs_len;       /* encap: iptfs length */
  union
  {
    struct
    {
      ipsec_iptfs_header_t h;
      iptfs_datablock_trace_t db[0]; /* datablock trace */
    };
    struct
    {
      u16 block_number; /* block number decap is from */
    };
  };
} iptfs_packet_trace_t;

static inline void
iptfs_decapped_packet_trace_store (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_buffer_t *b0,
				   u32 esp_seq, u16 block_number)
{
  iptfs_packet_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
  t->is_decap = true;
  t->esp_seq = esp_seq;
  t->block_number = block_number;
}

extern ipsec_iptfs_config_t iptfs_default_config;

clib_error_t *ipsec_iptfs_check_support (ipsec_sa_t *sa);
f64 ipsec_iptfs_get_conf_payload_rate (u32 sa_index);
u16 ipsec_iptfs_get_payload_size (u32 sa_index);
clib_error_t *iptfs_api_hookup (vlib_main_t *vm);
clib_error_t *iptfs_backend_update ();
clib_error_t *iptfs_encap_backend_update ();
clib_error_t *iptfs_output_backend_update ();
void iptfs_clear_counters (void);
void iptfs_header_trace_store (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_buffer_t *b);
void iptfs_encapped_packet_trace_store (vlib_main_t *vm, vlib_node_runtime_t *node,
					vlib_buffer_t *b, u32 gen, u16 ord, u16 last_ord,
					bool bad_header);
u32 iptfs_next_thread_index (iptfs_worker_range_t *range, u32 thread_index);
void iptfs_skip_thread_index (iptfs_worker_range_t *range);
#ifdef IPTFS_DEBUG_CORRUPTION
void iptfs_output_encrypt_debug (vlib_main_t *vm, ipsec_sa_t *sa, void *esp, vlib_buffer_t *srcb,
				 vlib_buffer_t *dstb);
#endif
u8 *format_ip46_header (u8 *s, va_list *args);
u8 *format_iptfs_config (u8 *s, va_list *args);
u8 *format_iptfs_config_early (u8 *s, va_list *args);
u8 *format_iptfs_data (u8 *s, va_list *args);
u8 *format_iptfs_encap_trace (u8 *s, va_list *args);
u8 *format_iptfs_header_trace (u8 *s, va_list *args);
u8 *format_iptfs_packet_trace (u8 *s, va_list *args);
u8 *format_iptfs_header (u8 *s, va_list *args);
uword unformat_iptfs_config (unformat_input_t *input, va_list *args);
void iptfs_dump_debug_all_strings ();
void iptfs_dump_debug_strings (i32 thread_idx);

#define IPSEC_IPTFS_PLUGIN_BUILD_VER "1.0"

#endif /* __included_ipsec_iptfs_h__ */
