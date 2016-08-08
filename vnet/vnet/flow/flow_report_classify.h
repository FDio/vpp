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

/* Note: add +2 to udp (src,dst) port enum values to get TCP values */
#define foreach_ipfix_field                                             \
_(ip->src_address.as_u32, 0xffffffff, sourceIPv4Address, 4)             \
_(ip->dst_address.as_u32, 0xffffffff, destinationIPv4Address, 4)        \
_(ip->protocol, 0xFF, protocolIdentifier, 1)                            \
_(udp->src_port, 0xFFFF, udpSourcePort, 2)                              \
_(udp->dst_port, 0xFFFF, udpDestinationPort, 2)

#endif /* __included_flow_report_classify_h__ */
