/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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

#define foreach_ioam_ipfix_info_element           \
_(ioamMyNodeId, 5234, u32)                        \
_(ioamStartTimeStamp, 5235, u32)                  \
_(ioamEndTimeStamp, 5236, u32)                    \
_(ioamPacketCount, 5237, u32)                     \
_(ioamByteCount, 5238, u32)                       \
_(ioamProtocol, 5260, u16)                        \
_(ioamPathMap, 5262, u32)                         \
_(ioamNumberOfNodes, 5263, u16)                   \
_(ioamSfcId, 5277, u32)                           \
_(ioamSfcValidatedCount, 5278, u32)               \
_(ioamSfcInValidatedCount, 5279, u32)                                  

typedef enum {
#define _(n,v,t) n = v,
  foreach_ioam_ipfix_info_element
#undef _
} ioam_ipfix_info_element_id_t;

#define foreach_ioam_ipfix_field                                          \
/* Following are sent manually: sourceIPv6Address, destinationIPv6Address */ \
_(ipfix->my_node_id, 0xffffffff, ioamMyNodeId, 4)                          \
_(ipfix->pkt_counter, 0xffffffff, ioamPacketCount, 4)                      \
_(ipfix->bytes_counter, 0xffffffff, ioamByteCount, 4)                      \
_(ipfix->sfc_id, 0xffffffff, ioamSfcId, 4)                                 \
_(ipfix->sfc_validated_count, 0xffffffff, ioamSfcValidatedCount, 4)        \
_(ipfix->sfc_invalidated_count, 0xffffffff, ioamSfcInValidatedCount, 4)    \
_(ipfix->start_timestamp, 0xffffffff, ioamStartTimeStamp, 4)               \
_(ipfix->end_timestamp, 0xffffffff, ioamEndTimeStamp, 4)                   \
_(ipfix->src_port, 0xffff, sourceTransportPort, 2)                         \
_(ipfix->dst_port, 0xffff, destinationTransportPort, 2)                    \
_(ipfix->protocol, 0xffff, ioamProtocol, 2)                                \
_(ipfix->num_nodes, 0xffff, ioamNumberOfNodes, 2)        
/* Following are sent manually: ioamPathMap */

#define foreach_ipfix_path_field              \
_(pm->node_id, 0, 0, 4)                       \
_(pm->ingress_if, 0, 0, 2)                    \
_(pm->egress_if, 0, 0, 2)                    


#endif /* __included_ip6_ioam_flow_report_h__ */
