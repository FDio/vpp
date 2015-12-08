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
#ifndef __included_ip6_hop_by_hop_packet_h__
#define __included_ip6_hop_by_hop_packet_h__

typedef struct {
  /* Protocol for next header */
  u8 protocol;
  /*
   * Length of hop_by_hop header in 8 octet units, 
   * not including the first 8 octets
   */
  u8 length;
} ip6_hop_by_hop_header_t;

typedef struct {
  /* Option Type */
#define HBH_OPTION_TYPE_SKIP_UNKNOWN (0x0 << 6)
#define HBH_OPTION_TYPE_DISCARD_UNKNOWN (0x1 << 6)
#define HBH_OPTION_TYPE_DISCARD_UNKNOWN_ICMP (0x2 << 6)
#define HBH_OPTION_TYPE_DISCARD_UNKNOWN_ICMP_NOT_MCAST (0x3 << 6)
#define HBH_OPTION_TYPE_DATA_CHANGE_ENROUTE (1<<5)
#define HBH_OPTION_TYPE_MASK (0x1F)
  u8 type;
  /* Length in octets of the option data field */
  u8 length;
} ip6_hop_by_hop_option_t;

/* $$$$ IANA banana constants */
#define HBH_OPTION_TYPE_IOAM_DATA_LIST 1
#define HBH_OPTION_TYPE_IOAM_PROOF_OF_WORK 2

typedef struct {
  u32 ttl_node_id;
  u16 ingress_if;
  u16 egress_if;
  u32 timestamp;
  u32 app_data;
} ioam_data_list_element_t;

typedef CLIB_PACKED(struct {
  ip6_hop_by_hop_option_t hdr;
  u8 data_list_elts_left;
  ioam_data_list_element_t elts[0];
}) ioam_trace_option_t;

typedef CLIB_PACKED(struct {
  ip6_hop_by_hop_option_t hdr;
  u8 pow_type;
  u8 reserved;
  u32 random[2];
  u32 cumulative[2];
}) ioam_pow_option_t;

#endif /* __included_ip6_hop_by_hop_packet_h__ */
