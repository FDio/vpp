/* SPDX-License-Identifier: Apache-2.0 */

/*
 * eta.h — mighty_xddos ETA (Encrypted Traffic Analysis), VPP mode: copies
 * TLS/QUIC ClientHello packets to etad (eta/etad) through a memif
 * interface. See node.c's package doc comment for the packet path; the
 * Kernel/XDP mode counterpart is ebpf/xdp_bridge/kern/xdp_bridge.c's
 * eta_extract, and both must select the same packets.
 */

#ifndef __included_eta_h__
#define __included_eta_h__

#include <vlib/vlib.h>
#include <vnet/vnet.h>

/* Same values as kern/xdp_bridge.c's ETA_* constants. */
#define ETA_QUIC_MIN_INITIAL 1200
#define ETA_FLOW_SLOTS	     256 /* per-thread split-ClientHello slots (power of 2) */
#define ETA_FLOW_TIMEOUT     1.0 /* seconds */
#define ETA_MIN_BURST	     32

/* Header put in front of every copied frame — must match etad's
 * memif_source.cc (struct eta_frame_hdr). Host byte order. */
#define ETA_FRAME_MAGIC	    0x31415445 /* "ETA1" */
#define ETA_FRAME_F_INBOUND 0x1	   /* received on a WAN-role interface */
typedef struct
{
  u32 magic;
  u32 sw_if_index; /* interface the packet was received on */
  u32 flags;	   /* ETA_FRAME_F_* */
  u32 reserved;
} eta_frame_hdr_t;

typedef enum
{
  ETA_ROLE_NONE = 0,
  ETA_ROLE_WAN,
  ETA_ROLE_LAN,
} eta_role_t;

/* A split ClientHello being followed into its next segments. Addresses as
 * in the IPv4 header, ports in host byte order. */
typedef struct
{
  u32 saddr;
  u32 daddr;
  u16 sport;
  u16 dport;
  u32 next_seq;
  u32 remaining; /* ClientHello bytes still to come; 0 = free slot */
  f64 expire;
} eta_flow_slot_t;

/* Per-thread state: token bucket and the split-ClientHello slots. */
typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  f64 tokens;
  f64 last;
  u32 active_slots; /* slots in use; 0 lets the hot path skip the probe */
  eta_flow_slot_t slots[ETA_FLOW_SLOTS];
} eta_per_thread_t;

/* Counters (simple counters, index ETA_CNT_*). */
enum
{
  ETA_CNT_EXPORTED,	/* ClientHello packets copied to the output */
  ETA_CNT_RATE_LIMITED, /* skipped by the rate limit */
  ETA_CNT_NO_BUFFER,	/* skipped: no buffer for the copy */
  ETA_N_CNT,
};

typedef struct
{
  int enabled;
  u32 output_sw_if_index; /* memif interface the copies go to */
  u32 rate;		  /* packets/s for the whole system, 0 = unlimited */
  int inbound_only;	  /* only ClientHellos received on a WAN-role interface */
  f64 rate_per_thread;
  f64 burst;

  u8 *role_by_sw_if_index;	 /* eta_role_t */
  u8 *feature_on_by_sw_if_index; /* interface-output feature attached */
  eta_per_thread_t *per_thread;

  vlib_simple_counter_main_t counters[ETA_N_CNT];

  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
} eta_main_t;

extern eta_main_t eta_main;
extern vlib_node_registration_t eta_node;

#endif /* __included_eta_h__ */
