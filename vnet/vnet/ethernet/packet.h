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
/*
 * ethernet/packet.h: ethernet packet format.
 *
 * Copyright (c) 2008 Eliot Dresselhaus
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 *  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 *  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 *  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 *  LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 *  OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 *  WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#ifndef included_ethernet_packet_h
#define included_ethernet_packet_h

typedef enum
{
#define ethernet_type(n,s) ETHERNET_TYPE_##s = n,
#include <vnet/ethernet/types.def>
#undef ethernet_type
} ethernet_type_t;

typedef struct
{
  /* Source/destination address. */
  u8 dst_address[6];
  u8 src_address[6];

  /* Ethernet type. */
  u16 type;
} ethernet_header_t;

#define ETHERNET_ADDRESS_UNICAST 0
#define ETHERNET_ADDRESS_MULTICAST 1

/* I/G bit: individual (unicast)/group (broadcast/multicast). */
always_inline uword
ethernet_address_cast (u8 * a)
{
  return (a[0] >> 0) & 1;
}

always_inline uword
ethernet_address_is_locally_administered (u8 * a)
{
  return (a[0] >> 1) & 1;
}

always_inline void
ethernet_address_set_locally_administered (u8 * a)
{
  a[0] |= 1 << 1;
}

/* For VLAN ethernet type. */
typedef struct
{
  /* 3 bit priority, 1 bit CFI and 12 bit vlan id. */
  u16 priority_cfi_and_id;

#define ETHERNET_N_VLAN (1 << 12)

  /* Inner ethernet type. */
  u16 type;
} ethernet_vlan_header_t;


/* VLAN with ethertype first and vlan id second */
typedef struct
{
  /* vlan type */
  u16 type;

  /* 3 bit priority, 1 bit CFI and 12 bit vlan id. */
  u16 priority_cfi_and_id;
} ethernet_vlan_header_tv_t;

/* PBB header with B-TAG - backbone VLAN indicator and I-TAG - service encapsulation */
typedef struct
{
  /* Backbone source/destination address. */
  u8 b_dst_address[6];
  u8 b_src_address[6];

  /* B-tag */
  u16 b_type;
  /* 3 bit priority, 1 bit DEI and 12 bit vlan id */
  u16 priority_dei_id;

  /* I-tag */
  u16 i_type;
  /* 3 bit priority, 1 bit DEI, 1 bit UCA, 3 bit RES and 24 bit I_SID (service identifier) */
  u32 priority_dei_uca_res_sid;

#define ETHERNET_N_PBB (1 << 24)
} ethernet_pbb_header_t;

/* *INDENT-OFF* */
typedef CLIB_PACKED (struct
{
  /* Backbone source/destination address. */
  u8 b_dst_address[6];
  u8 b_src_address[6];

  /* B-tag */
  u16 b_type;
  /* 3 bit priority, 1 bit DEI and 12 bit vlan id */
  u16 priority_dei_id;

  /* I-tag */
  u16 i_type;
  /* 3 bit priority, 1 bit DEI, 1 bit UCA, 3 bit RES and 24 bit I_SID (service identifier) */
  u32 priority_dei_uca_res_sid;
}) ethernet_pbb_header_packed_t;
/* *INDENT-ON* */

#endif /* included_ethernet_packet_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
