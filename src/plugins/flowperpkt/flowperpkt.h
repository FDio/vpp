/*
 * flowperpkt.h - skeleton vpp engine plug-in header file
 *
 * Copyright (c) 2016 Cisco and/or its affiliates.
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
 */
#ifndef __included_flowperpkt_h__
#define __included_flowperpkt_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>

#include <vppinfra/hash.h>
#include <vppinfra/error.h>
#include <vnet/flow/flow_report.h>
#include <vnet/flow/flow_report_classify.h>
#include <vppinfra/tw_timer_2t_1w_2048sl.h>

/* Default timers in seconds */
#define FLOWPERPKT_TIMER_ACTIVE   (15)
//#define FLOWPERPKT_TIMER_PASSIVE      (30*60)
#define FLOWPERPKT_TIMER_PASSIVE  (30)
#define FLOWPERPKT_LOG2_HASHSIZE  (16)

typedef enum
{
  FLOW_RECORD_L2 = 1 << 0,
  FLOW_RECORD_L3 = 1 << 1,
  FLOW_RECORD_L4 = 1 << 2,
  FLOW_RECORD_L2_IP4 = 1 << 3,
  FLOW_RECORD_L2_IP6 = 1 << 4,
  FLOW_N_RECORDS = 1 << 5,
} flowperpkt_record_t;

typedef enum __attribute__ ((__packed__))
{
FLOW_VARIANT_IP4,
    FLOW_VARIANT_IP6,
    FLOW_VARIANT_L2,
    FLOW_VARIANT_L2_IP4,
    FLOW_VARIANT_L2_IP6, FLOW_N_VARIANTS,} flowperpkt_variant_t;

STATIC_ASSERT (sizeof (flowperpkt_variant_t) == 1,
         "flowperpkt_variant_t is expected to be 1 byte, "
         "revisit padding in flowperpkt_key_t");

typedef struct
{
  /* what to collect per variant */
  flowperpkt_record_t flags;
  /** ipfix buffers under construction, per-worker thread */
  vlib_buffer_t **buffers_per_worker;
  /** frames containing ipfix buffers, per-worker thread */
  vlib_frame_t **frames_per_worker;
  /** next record offset, per worker thread */
  u16 *next_record_offset_per_worker;
} flowperpkt_protocol_context_t;

#define FLOWPERPKT_KEY_IN_U32 22
typedef CLIB_PACKED (union
         {
         struct
         {
         u32 rx_sw_if_index;
         u32 tx_sw_if_index; u8 src_mac[6]; u8 dst_mac[6];
         u16 ethertype;
         ip46_address_t src_address; ip46_address_t dst_address;
         u8 protocol;
         u16 src_port; u16 dst_port; flowperpkt_variant_t which;
         }; u32 as_u32[FLOWPERPKT_KEY_IN_U32];
         }) flowperpkt_key_t;

STATIC_ASSERT (sizeof (flowperpkt_key_t) == FLOWPERPKT_KEY_IN_U32 *
         sizeof (u32), "flowperpkt_key_t padding is wrong");

typedef struct
{
  flowperpkt_key_t key;
  u64 packetcount;
  u64 octetcount;
  f64 last_updated;
  u32 active_timer_handle;
  u32 passive_timer_handle;
  bool timer_on;
} flowperpkt_entry_t;

/**
 * @file
 * @brief flow-per-packet plugin header file
 */
typedef struct
{
  /** API message ID base */
  u16 msg_id_base;

  flowperpkt_protocol_context_t context[FLOW_N_VARIANTS];
  u16 template_reports[FLOW_N_RECORDS];
  u16 template_size[FLOW_N_RECORDS];

  /** Time reference pair */
  u64 nanosecond_time_0;
  f64 vlib_time_0;

  /** Per CPU flow-state */
  u8 ht_log2len;    /* Hash table size is 2^log2len */
  u32 **hash_per_worker;
  flowperpkt_entry_t **pool_per_worker;

  TWT (tw_timer_wheel) ** timers_per_worker;

  flowperpkt_record_t record;
  u32 active_timer;
  u32 passive_timer;

  bool initialized;

  /** convenience vlib_main_t pointer */
  vlib_main_t *vlib_main;
  /** convenience vnet_main_t pointer */
  vnet_main_t *vnet_main;
} flowperpkt_main_t;

extern flowperpkt_main_t flowperpkt_main;

void flowperpkt_flush_callback_ip4 (void);
void flowperpkt_flush_callback_ip6 (void);
void flowperpkt_flush_callback_l2 (void);
void flowperpkt_export_entry (vlib_main_t * vm, flowperpkt_entry_t * e);
void flowperpkt_expired_timer_callback (u32 * expired_timers);
u8 *format_flowperpkt_entry (u8 * s, va_list * args);

#endif /* __included_flowperpkt_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
