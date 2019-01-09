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
 * pcap.h: libpcap packet capture format
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
/**
 * @file
 * @brief PCAP utility definitions
 */
#ifndef included_vppinfra_pcap_h
#define included_vppinfra_pcap_h

#include <vppinfra/types.h>
#include <vppinfra/cache.h>
#include <vppinfra/mem.h>
#include <vppinfra/lock.h>

/**
 * @brief Known libpcap encap types
 *
 * These codes end up in the pcap file header.
 * If you decide to build a wireshark dissector,
 * you'll need to know that these codes are mapped
 * through the pcap_to_wtap_map[] array in .../wiretap/pcap-common.c.
 *
 * For example:
 *
 *   { 280, 		WTAP_ENCAP_VPP },
 *
 * A file with the officially-allocated vpp packet type PCAP_PACKET_TYPE_vpp
 * aka 280, will need a top-level dissector registered to
 * deal with WTAP_ENCAP_VPP [=206].
 *
 * Something like so:
 *
 * dissector_add_uint("wtap_encap", WTAP_ENCAP_VPP, vpp_dissector_handle);
 *
 */
#define foreach_vnet_pcap_packet_type           \
  _ (null, 0)					\
  _ (ethernet, 1)				\
  _ (ppp, 9)					\
  _ (ip, 12)					\
  _ (hdlc, 104)                                 \
  _ (user0,    147)                             \
  _ (user1,    148)                             \
  _ (user2,    149)                             \
  _ (user3,    150)                             \
  _ (user4,    151)                             \
  _ (user5,    152)                             \
  _ (user6,    153)                             \
  _ (user7,    154)                             \
  _ (user8,    155)                             \
  _ (user9,    156)                             \
  _ (user10,   157)                             \
  _ (user11,   158)                             \
  _ (user12,   159)                             \
  _ (user13,   160)                             \
  _ (user14,   161)                             \
  _ (user15,   162)				\
  _ (vpp, 280)					\

typedef enum
{
#define _(f,n) PCAP_PACKET_TYPE_##f = (n),
  foreach_vnet_pcap_packet_type
#undef _
} pcap_packet_type_t;

#define foreach_pcap_file_header			\
  /** 0xa1b2c3d4 host byte order.			\
     0xd4c3b2a1 => need to byte swap everything. */	\
  _ (u32, magic)					\
							\
  /** Currently major 2 minor 4. */			\
  _ (u16, major_version)				\
  _ (u16, minor_version)				\
							\
  /** 0 for GMT. */					\
  _ (u32, time_zone)					\
							\
  /** Accuracy of timestamps.  Typically set to 0. */	\
  _ (u32, sigfigs)					\
							\
  /** Size of largest packet in file. */                \
  _ (u32, max_packet_size_in_bytes)			\
							\
  /** One of vnet_pcap_packet_type_t. */                \
  _ (u32, packet_type)

/** File header struct */
typedef struct
{
#define _(t, f) t f;
  foreach_pcap_file_header
#undef _
} pcap_file_header_t;

#define foreach_pcap_packet_header					\
  /** Time stamp in seconds  */                                         \
  _ (u32, time_in_sec)							\
  /** Time stamp in microseconds. */                                    \
  _ (u32, time_in_usec)							\
									\
  /** Number of bytes stored in file. */                                \
  _ (u32, n_packet_bytes_stored_in_file)				\
  /** Number of bytes in actual packet. */                              \
  _ (u32, n_bytes_in_packet)

/** Packet header. */
typedef struct
{
#define _(t, f) t f;
  foreach_pcap_packet_header
#undef _
  /** Packet data follows. */
  u8 data[0];
} pcap_packet_header_t;

/**
 * @brief PCAP main state data structure
 */
typedef struct
{
  /** spinlock to protect e.g. pcap_data */
  clib_spinlock_t lock;

  /** File name of pcap output. */
  char *file_name;

  /** Number of packets to capture. */
  u32 n_packets_to_capture;

  /** Packet type */
  pcap_packet_type_t packet_type;

  /** Number of packets currently captured. */
  u32 n_packets_captured;

  /** flags */
  u32 flags;
#define PCAP_MAIN_INIT_DONE (1 << 0)

  /** File descriptor for reading/writing. */
  int file_descriptor;

  /** Bytes written */
  u32 n_pcap_data_written;

  /** Vector of pcap data. */
  u8 *pcap_data;

  /** Packets read from file. */
  u8 **packets_read;

  /** Timestamps */
  u64 *timestamps;

  /** Min/Max Packet bytes */
  u32 min_packet_bytes, max_packet_bytes;
} pcap_main_t;

#endif /* included_vppinfra_pcap_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
