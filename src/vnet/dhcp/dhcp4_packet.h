#ifndef included_vnet_dhcp4_packet_h
#define included_vnet_dhcp4_packet_h

/*
 * DHCP packet format
 *
 * Copyright (c) 2013 Cisco and/or its affiliates.
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
#include <vnet/ip/ip4_packet.h>

typedef struct {
  u8 opcode;                    /* 1 = request, 2 = reply */
  u8 hardware_type;             /* 1 = ethernet */
  u8 hardware_address_length;
  u8 hops;
  u32 transaction_identifier;
  u16 seconds;
  u16 flags;
#define DHCP_FLAG_BROADCAST (1<<15)
  ip4_address_t client_ip_address;
  ip4_address_t your_ip_address; /* use this one */
  ip4_address_t server_ip_address;
  ip4_address_t gateway_ip_address; /* use option 3, not this one */
  u8 client_hardware_address[16];
  u8 server_name[64];
  u8 boot_filename[128];
  ip4_address_t magic_cookie;
  u8 options[0];
} dhcp_header_t;

typedef struct {
  u8 option;
  u8 length;
  union {
    u8 data[0];
    u32 data_as_u32[0];
  };
} __attribute__((packed)) dhcp_option_t;

typedef enum {
  DHCP_PACKET_DISCOVER=1,
  DHCP_PACKET_OFFER,
  DHCP_PACKET_REQUEST,
  DHCP_PACKET_ACK=5,
} dhcp_packet_type_t;

typedef enum dhcp_packet_option_t_
{
    DHCP_PACKET_OPTION_MSG_TYPE = 53,
} dhcp_packet_option_t;

/* charming antique: 99.130.83.99 is the dhcp magic cookie */
#define DHCP_MAGIC (clib_host_to_net_u32(0x63825363))

#endif /* included_vnet_dhcp4_packet_h */
