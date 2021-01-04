/*
 *------------------------------------------------------------------
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
 *------------------------------------------------------------------
 */

#ifndef _ICMP_PROTO_H_
#define _ICMP_PROTO_H_

typedef enum
{
  ICMPR_FLOW_MODE_ETH = 0,
  ICMPR_FLOW_MODE_IP,
} icmpr_flow_mode_t;

int resolve_packet (void *in_pck, ssize_t in_size, void *out_pck,
		    uint32_t *out_size, uint8_t ip_addr[4],
		    uint8_t hw_addr[6]);

/* resolve packet in place */
int resolve_packet_zero_copy (void *pck, uint32_t *size, uint8_t ip_addr[4],
			      uint8_t hw_addr[6]);

/* resolve packet in place and add eth encap */
int resolve_packet_zero_copy_add_encap (void **pck, uint32_t *size,
					uint8_t ip_addr[4]);

int generate_packet (void *pck, uint32_t *size, uint8_t saddr[4],
		     uint8_t daddr[4], uint8_t hw_daddr[6], uint32_t seq);

int generate_packet2 (void *pck, uint32_t *size, uint8_t saddr[4],
		      uint8_t daddr[4], uint8_t hw_daddr[6], uint32_t seq,
		      icmpr_flow_mode_t);

int print_packet (void *pck);

#endif /* _ICMP_PROTO_H_ */
