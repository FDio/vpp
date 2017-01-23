/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
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
#ifndef __included_ip6_ioam_flow_report_h__
#define __included_ip6_ioam_flow_report_h__

#include <ioam/analyse/ioam_analyse.h>
#include <vnet/flow/flow_report.h>

#define foreach_ioam_ipfix_info_element           \
_(ioamPacketSent, 5239, u32)                     \
_(ioamPacketCount, 5237, u32)                     \
_(ioamByteCount, 5238, u32)                       \
_(ioamPathMap, 5262, u32)                         \
_(ioamNumberOfPaths, 5264, u16)                   \
_(ioamSfcValidatedCount, 5278, u32)               \
_(ioamSfcInValidatedCount, 5279, u32)             \
_(ioamSeqnoRxCount, 5280, u32)                    \
_(ioamSeqnoLostCount, 5281, u32)                  \
_(ioamSeqnoReorderedCount, 5282, u32)             \
_(ioamSeqnoDupCount, 5283, u32)


typedef enum
{
#define _(n,v,t) n = v,
  foreach_ioam_ipfix_info_element
#undef _
} ioam_ipfix_info_element_id_t;

#define foreach_ioam_ipfix_field                                          \
_(pkt_sent, 0xffffffff, ioamPacketSent, 4)                      \
_(pkt_counter, 0xffffffff, ioamPacketCount, 4)                      \
_(bytes_counter, 0xffffffff, ioamByteCount, 4)                      \
_(pot_data.sfc_validated_count, 0xffffffff, ioamSfcValidatedCount, 4)     \
_(pot_data.sfc_invalidated_count, 0xffffffff, ioamSfcInValidatedCount, 4) \
_(seqno_data.rx_packets, 0xffffffff, ioamSeqnoRxCount, 4) \
_(seqno_data.lost_packets, 0xffffffff, ioamSeqnoLostCount, 4) \
_(seqno_data.reordered_packets, 0xffffffff, ioamSeqnoReorderedCount, 4) \
_(seqno_data.dup_packets, 0xffffffff, ioamSeqnoDupCount, 4)

clib_error_t *ioam_flow_report_init (vlib_main_t * vm);

typedef struct
{
  u8 num_nodes;
  u8 trace_type;
  u16 reserve;
  u32 mean_delay;
  u32 pkt_counter;
  u32 bytes_counter;
  ioam_path_map_t path[0];
} ioam_path;

clib_error_t *ioam_flow_create (u8 del);

u8 *ioam_template_rewrite (flow_report_main_t * frm, flow_report_t * fr,
			   ip4_address_t * collector_address,
			   ip4_address_t * src_address, u16 collector_port);

u16 ioam_analyse_add_ipfix_record (flow_report_t * fr,
				   ioam_analyser_data_t * record,
				   vlib_buffer_t * b0, u16 offset,
				   ip6_address_t * src, ip6_address_t * dst,
				   u16 src_port, u16 dst_port);

#endif /* __included_ip6_ioam_flow_report_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
