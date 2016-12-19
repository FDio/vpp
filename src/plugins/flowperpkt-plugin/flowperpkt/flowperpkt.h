/*
 * flowperpkt.h - skeleton vpp engine plug-in header file
 *
 * Copyright (c) <current-year> <your-organization>
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

/**
 * @file
 * @brief flow-per-packet plugin header file
 */
typedef struct
{
  /** API message ID base */
  u16 msg_id_base;

  /** Have the reports [templates] been created? */
  int ipv4_report_created;
  int l2_report_created;

  /** stream/template IDs */
  u16 ipv4_report_id;
  u16 l2_report_id;

  /** ipfix buffers under construction, per-worker thread */
  vlib_buffer_t **ipv4_buffers_per_worker;
  vlib_buffer_t **l2_buffers_per_worker;

  /** frames containing ipfix buffers, per-worker thread */
  vlib_frame_t **ipv4_frames_per_worker;
  vlib_frame_t **l2_frames_per_worker;

  /** next record offset, per worker thread */
  u16 *ipv4_next_record_offset_per_worker;
  u16 *l2_next_record_offset_per_worker;

  /** Time reference pair */
  u64 nanosecond_time_0;
  f64 vlib_time_0;

  /** convenience vlib_main_t pointer */
  vlib_main_t *vlib_main;
  /** convenience vnet_main_t pointer */
  vnet_main_t *vnet_main;
} flowperpkt_main_t;

typedef enum
{
  FLOW_VARIANT_IPV4,
  FLOW_VARIANT_L2,
  FLOW_N_VARIANTS,
} flowperpkt_variant_t;

extern flowperpkt_main_t flowperpkt_main;

extern vlib_node_registration_t flowperpkt_ipv4_node;

void flowperpkt_flush_callback_ipv4 (void);
void flowperpkt_flush_callback_l2 (void);

#endif /* __included_flowperpkt_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
