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

typedef enum
{
  FLOW_RECORD_L2 = 1 << 0,
  FLOW_RECORD_L3 = 1 << 1,
  FLOW_RECORD_L4 = 1 << 2,
  FLOW_RECORD_L2_IP4 = 1 << 3,
  FLOW_RECORD_L2_IP6 = 1 << 4,
  FLOW_N_RECORDS = 1 << 5,
} flowperpkt_record_t;

typedef enum
{
  FLOW_VARIANT_IP4,
  FLOW_VARIANT_IP6,
  FLOW_VARIANT_L2,
  FLOW_VARIANT_L2_IP4,
  FLOW_VARIANT_L2_IP6,
  FLOW_N_VARIANTS,
} flowperpkt_variant_t;

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
} flowperpkt_protocol_context;

/**
 * @file
 * @brief flow-per-packet plugin header file
 */
typedef struct
{
  /** API message ID base */
  u16 msg_id_base;

  flowperpkt_protocol_context context[FLOW_N_VARIANTS];
  u16 template_reports[FLOW_N_RECORDS];
  u16 template_size[FLOW_N_RECORDS];

  /** Time reference pair */
  u64 millisecond_time_0;
  f64 vlib_time_0;

  /** convenience vlib_main_t pointer */
  vlib_main_t *vlib_main;
  /** convenience vnet_main_t pointer */
  vnet_main_t *vnet_main;
} flowperpkt_main_t;

extern flowperpkt_main_t flowperpkt_main;

extern vlib_node_registration_t flowperpkt_ipv4_node;

void flowperpkt_flush_callback_ip4 (void);
void flowperpkt_flush_callback_ip6 (void);
void flowperpkt_flush_callback_l2 (void);
uword flowperpkt_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
			  vlib_frame_t * frame, flowperpkt_variant_t variant);

#endif /* __included_flowperpkt_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
