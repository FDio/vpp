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
#ifndef __included_flow_report_classify_h__
#define __included_flow_report_classify_h__

#define foreach_ipfix_ip4_field                                             \
_(ip->src_address.as_u32, ((u32[]){0xFFFFFFFF}), sourceIPv4Address, 4)      \
_(ip->dst_address.as_u32, ((u32[]){0xFFFFFFFF}), destinationIPv4Address, 4) \
_(ip->protocol, ((u8[]){0xFF}), protocolIdentifier, 1)

#define foreach_ipfix_ip6_field                                             \
_(ip6->src_address.as_u8,                                                   \
  ((u32[]){0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF}),                   \
  sourceIPv6Address, 16)                                                    \
_(ip6->dst_address.as_u8,                                                   \
  ((u32[]){0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF}),                   \
  destinationIPv6Address, 16)                                               \
_(ip6->protocol, ((u8[]){0xFF}), protocolIdentifier, 1)

#define foreach_ipfix_tcpudp_field                                          \
_(tcpudp->src_port, ((u16[]){0xFFFF}), sourceTransportPort, 2)              \
_(tcpudp->dst_port, ((u16[]){0xFFFF}), destinationTransportPort, 2)

#define foreach_ipfix_tcp_field                                             \
_(tcpudp->src_port, ((u16[]){0xFFFF}), tcpSourcePort, 2)                    \
_(tcpudp->dst_port, ((u16[]){0xFFFF}), tcpDestinationPort, 2)

#define foreach_ipfix_udp_field                                             \
_(tcpudp->src_port, ((u16[]){0xFFFF}), udpSourcePort, 2)                    \
_(tcpudp->dst_port, ((u16[]){0xFFFF}), udpDestinationPort, 2)

#define foreach_ipfix_transport_protocol_field                              \
  switch (transport_protocol) {                                             \
    case 255:                                                               \
      foreach_ipfix_tcpudp_field;                                           \
      break;                                                                \
    case 6:                                                                 \
      foreach_ipfix_tcp_field;                                              \
      break;                                                                \
    case 17:                                                                \
      foreach_ipfix_udp_field;                                              \
      break;                                                                \
  }

#define foreach_ipfix_field                                                 \
  if (ip_version == 4) {                                                    \
    ip = (ip4_header_t *)ip_start;                                          \
    tcpudp = (tcpudp_header_t *)(ip+1);                                     \
    foreach_ipfix_ip4_field;                                                \
  } else {                                                                  \
    ip6 = (ip6_header_t *)ip_start;                                         \
    tcpudp = (tcpudp_header_t *)(ip6+1);                                    \
    foreach_ipfix_ip6_field;                                                \
  }                                                                         \
  foreach_ipfix_transport_protocol_field

typedef struct {
  u32 classify_table_index;
  u8 ip_version;
  u8 transport_protocol;
} ipfix_classify_table_t;

typedef struct {
  u32 domain_id;
  u16 src_port;
  ipfix_classify_table_t * tables;
} flow_report_classify_main_t;

extern flow_report_classify_main_t flow_report_classify_main;

static_always_inline u8 ipfix_classify_table_index_valid (u32 index)
{
  flow_report_classify_main_t * fcm = &flow_report_classify_main;
  return index < vec_len(fcm->tables) &&
         fcm->tables[index].classify_table_index != ~0;
}

static_always_inline ipfix_classify_table_t * ipfix_classify_add_table (void)
{
  flow_report_classify_main_t * fcm = &flow_report_classify_main;
  u32 i;
  for (i = 0; i < vec_len(fcm->tables); i++)
    if (!ipfix_classify_table_index_valid(i))
      return &fcm->tables[i];
  u32 index = vec_len(fcm->tables);
  vec_validate(fcm->tables, index);
  return &fcm->tables[index];
}

static_always_inline void ipfix_classify_delete_table (u32 index)
{
  flow_report_classify_main_t * fcm = &flow_report_classify_main;
  ASSERT (index < vec_len(fcm->tables));
  ASSERT (fcm->tables[index].classify_table_index != ~0);
  fcm->tables[index].classify_table_index = ~0;
}

u8 * ipfix_classify_template_rewrite (flow_report_main_t * frm,
                                      flow_report_t * fr,
                                      ip4_address_t * collector_address,
                                      ip4_address_t * src_address,
                                      u16 collector_port);

vlib_frame_t * ipfix_classify_send_flows (flow_report_main_t * frm,
                                          flow_report_t * fr,
                                          vlib_frame_t * f,
                                          u32 * to_next,
                                          u32 node_index);

#endif /* __included_flow_report_classify_h__ */
