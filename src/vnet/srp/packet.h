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
 * srp/packet.h: srp packet format.
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

#ifndef included_srp_packet_h
#define included_srp_packet_h

#include <vppinfra/clib.h>
#include <vnet/ethernet/packet.h>

/* SRP version 2. */

#define foreach_srp_mode			\
  _ (reserved0)					\
  _ (reserved1)					\
  _ (reserved2)					\
  _ (reserved3)					\
  _ (control_pass_to_host)			\
  _ (control_locally_buffered_for_host)		\
  _ (keep_alive)				\
  _ (data)

typedef enum {
#define _(f) SRP_MODE_##f,
  foreach_srp_mode
#undef _
  SRP_N_MODE,
} srp_mode_t;

typedef union {
  /* For computing parity bit. */
  u16 as_u16;

  struct {
    u8 ttl;

#if CLIB_ARCH_IS_BIG_ENDIAN
    u8 is_inner_ring : 1;
    u8 mode : 3;
    u8 priority : 3;
    u8 parity : 1;
#endif
#if CLIB_ARCH_IS_LITTLE_ENDIAN
    u8 parity : 1;
    u8 priority : 3;
    u8 mode : 3;
    u8 is_inner_ring : 1;
#endif
  };
} srp_header_t;

always_inline void
srp_header_compute_parity (srp_header_t * h)
{
  h->parity = 0;
  h->parity = count_set_bits (h->as_u16) ^ 1; /* odd parity */
}

typedef struct {
  srp_header_t srp;
  ethernet_header_t ethernet;
} srp_and_ethernet_header_t;

#define foreach_srp_control_packet_type		\
  _ (reserved)					\
  _ (topology)					\
  _ (ips)

typedef enum {
#define _(f) SRP_CONTROL_PACKET_TYPE_##f,
  foreach_srp_control_packet_type
#undef _
  SRP_N_CONTROL_PACKET_TYPE,
} srp_control_packet_type_t;

typedef CLIB_PACKED (struct {
  /* Set to 0. */
  u8 version;

  srp_control_packet_type_t type : 8;

  /* IP4-like checksum of packet starting with start of control header. */
  u16 checksum;

  u16 ttl;
}) srp_control_header_t;

typedef struct {
  srp_header_t srp;
  ethernet_header_t ethernet;
  srp_control_header_t control;
} srp_generic_control_header_t;

typedef struct {
  u8 flags;
#define SRP_TOPOLOGY_MAC_BINDING_FLAG_IS_INNER_RING (1 << 6)
#define SRP_TOPOLOGY_MAC_BINDING_FLAG_IS_WRAPPED (1 << 5)

  /* MAC address. */
  u8 address[6];
} srp_topology_mac_binding_t;

typedef CLIB_PACKED (struct {
  srp_header_t srp;
  ethernet_header_t ethernet;
  srp_control_header_t control;

  /* Length in bytes of data that follows. */
  u16 n_bytes_of_data_that_follows;

  /* MAC address of originator of this topology request. */
  u8 originator_address[6];

  /* Bindings follow. */
  srp_topology_mac_binding_t bindings[0];
}) srp_topology_header_t;

#define foreach_srp_ips_request_type		\
  _ (idle, 0x0)					\
  _ (wait_to_restore, 0x5)			\
  _ (manual_switch, 0x6)			\
  _ (signal_degrade, 0x8)			\
  _ (signal_fail, 0xb)				\
  _ (forced_switch, 0xd)

typedef enum {
#define _(f,n) SRP_IPS_REQUEST_##f = n,
  foreach_srp_ips_request_type
#undef _
} srp_ips_request_type_t;

#define foreach_srp_ips_status			\
  _ (idle, 0x0)					\
  _ (wrapped, 0x2)

typedef enum {
#define _(f,n) SRP_IPS_STATUS_##f = n,
  foreach_srp_ips_status
#undef _
} srp_ips_status_t;

typedef struct {
  srp_header_t srp;
  ethernet_header_t ethernet;
  srp_control_header_t control;
  u8 originator_address[6];

  union {
    u8 ips_octet;

    struct {
#if CLIB_ARCH_IS_BIG_ENDIAN
      u8 request_type : 4;
      u8 is_long_path : 1;
      u8 status : 3;
#endif
#if CLIB_ARCH_IS_LITTLE_ENDIAN
      u8 status : 3;
      u8 is_long_path : 1;
      u8 request_type : 4;
#endif
    };
  };

  u8 reserved;
} srp_ips_header_t;

#endif /* included_srp_packet_h */
