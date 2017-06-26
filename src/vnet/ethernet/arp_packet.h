/*
 * ethernet/arp.c: IP v4 ARP node
 *
 * Copyright (c) 2010 Cisco and/or its affiliates.
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

#ifndef included_ethernet_arp_packet_h
#define included_ethernet_arp_packet_h

#define foreach_ethernet_arp_hardware_type	\
  _ (0, reserved)				\
  _ (1, ethernet)				\
  _ (2, experimental_ethernet)			\
  _ (3, ax_25)					\
  _ (4, proteon_pronet_token_ring)		\
  _ (5, chaos)					\
  _ (6, ieee_802)				\
  _ (7, arcnet)					\
  _ (8, hyperchannel)				\
  _ (9, lanstar)				\
  _ (10, autonet)				\
  _ (11, localtalk)				\
  _ (12, localnet)				\
  _ (13, ultra_link)				\
  _ (14, smds)					\
  _ (15, frame_relay)				\
  _ (16, atm)					\
  _ (17, hdlc)					\
  _ (18, fibre_channel)				\
  _ (19, atm19)					\
  _ (20, serial_line)				\
  _ (21, atm21)					\
  _ (22, mil_std_188_220)			\
  _ (23, metricom)				\
  _ (24, ieee_1394)				\
  _ (25, mapos)					\
  _ (26, twinaxial)				\
  _ (27, eui_64)				\
  _ (28, hiparp)				\
  _ (29, iso_7816_3)				\
  _ (30, arpsec)				\
  _ (31, ipsec_tunnel)				\
  _ (32, infiniband)				\
  _ (33, cai)					\
  _ (34, wiegand)				\
  _ (35, pure_ip)				\
  _ (36, hw_exp1)				\
  _ (256, hw_exp2)

#define foreach_ethernet_arp_opcode		\
  _ (reserved)					\
  _ (request)					\
  _ (reply)					\
  _ (reverse_request)				\
  _ (reverse_reply)				\
  _ (drarp_request)				\
  _ (drarp_reply)				\
  _ (drarp_error)				\
  _ (inarp_request)				\
  _ (inarp_reply)				\
  _ (arp_nak)					\
  _ (mars_request)				\
  _ (mars_multi)				\
  _ (mars_mserv)				\
  _ (mars_join)					\
  _ (mars_leave)				\
  _ (mars_nak)					\
  _ (mars_unserv)				\
  _ (mars_sjoin)				\
  _ (mars_sleave)				\
  _ (mars_grouplist_request)			\
  _ (mars_grouplist_reply)			\
  _ (mars_redirect_map)				\
  _ (mapos_unarp)				\
  _ (exp1)					\
  _ (exp2)

typedef enum
{
#define _(n,f) ETHERNET_ARP_HARDWARE_TYPE_##f = (n),
  foreach_ethernet_arp_hardware_type
#undef _
} ethernet_arp_hardware_type_t;

typedef enum
{
#define _(f) ETHERNET_ARP_OPCODE_##f,
  foreach_ethernet_arp_opcode
#undef _
    ETHERNET_ARP_N_OPCODE,
} ethernet_arp_opcode_t;

typedef enum
{
  IP4_ARP_NEXT_DROP,
  IP4_ARP_N_NEXT,
} ip4_arp_next_t;

typedef enum
{
  IP4_ARP_ERROR_DROP,
  IP4_ARP_ERROR_REQUEST_SENT,
  IP4_ARP_ERROR_NON_ARP_ADJ,
  IP4_ARP_ERROR_REPLICATE_DROP,
  IP4_ARP_ERROR_REPLICATE_FAIL,
  IP4_ARP_ERROR_NO_SOURCE_ADDRESS,
} ip4_arp_error_t;

/* *INDENT-OFF* */
typedef CLIB_PACKED (struct {
  u8 ethernet[6];
  ip4_address_t ip4;
}) ethernet_arp_ip4_over_ethernet_address_t;
/* *INDENT-ON* */

typedef struct
{
  u16 l2_type;
  u16 l3_type;
  u8 n_l2_address_bytes;
  u8 n_l3_address_bytes;
  u16 opcode;
  union
  {
    ethernet_arp_ip4_over_ethernet_address_t ip4_over_ethernet[2];

    /* Others... */
    u8 data[0];
  };
} ethernet_arp_header_t;

typedef enum ethernet_arp_entry_flags_t_
{
  ETHERNET_ARP_IP4_ENTRY_FLAG_STATIC = (1 << 0),
  ETHERNET_ARP_IP4_ENTRY_FLAG_DYNAMIC = (1 << 1),
  ETHERNET_ARP_IP4_ENTRY_FLAG_NO_FIB_ENTRY = (1 << 2),
} __attribute__ ((packed)) ethernet_arp_entry_flags_t;

typedef struct
{
  u32 sw_if_index;
  ip4_address_t ip4_address;

  u8 ethernet_address[6];

  ethernet_arp_entry_flags_t flags;

  u64 cpu_time_last_updated;

  /**
   * The index of the adj-fib entry created
   */
  fib_node_index_t fib_entry_index;
} ethernet_arp_ip4_entry_t;

ethernet_arp_ip4_entry_t *ip4_neighbor_entries (u32 sw_if_index);
u8 *format_ethernet_arp_ip4_entry (u8 * s, va_list * va);

/* Node index for send_garp_na_process */
extern u32 send_garp_na_process_node_index;

/* Even type for send_garp_na_process */
enum
{
  SEND_GARP_NA = 1,
} dpdk_send_garp_na_process_event_t;

#endif /* included_ethernet_arp_packet_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
