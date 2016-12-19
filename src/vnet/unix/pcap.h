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
#ifndef included_vnet_pcap_h
#define included_vnet_pcap_h

#include <vlib/vlib.h>

/**
 * @brief Packet types supported by PCAP
 *
 * null 0
 * ethernet 1
 * ppp 9
 * ip 12
 * hdlc 104
 */
#define foreach_vnet_pcap_packet_type           \
  _ (null, 0)					\
  _ (ethernet, 1)				\
  _ (ppp, 9)					\
  _ (ip, 12)					\
  _ (hdlc, 104)

typedef enum {
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
typedef struct {
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
typedef struct {
#define _(t, f) t f;
  foreach_pcap_packet_header
#undef _

  /** Packet data follows. */
  u8 data[0];
} pcap_packet_header_t;

/**
 * @brief PCAP main state data structure
 */
typedef struct {
  /** File name of pcap output. */
  char * file_name;

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
  u8 * pcap_data;

  /** Packets read from file. */
  u8 ** packets_read;

  /** Min/Max Packet bytes */
  u32 min_packet_bytes, max_packet_bytes;
} pcap_main_t;

/** Write out data to output file. */
clib_error_t * pcap_write (pcap_main_t * pm);

/** Read data from file. */
clib_error_t * pcap_read (pcap_main_t * pm);

/**
 * @brief Add packet
 *
 * @param *pm - pcap_main_t
 * @param time_now - f64
 * @param n_bytes_in_trace - u32
 * @param n_bytes_in_packet - u32
 *
 * @return Packet Data
 *
 */
static inline void *
pcap_add_packet (pcap_main_t * pm,
		 f64 time_now,
		 u32 n_bytes_in_trace,
		 u32 n_bytes_in_packet)
{
  pcap_packet_header_t * h;
  u8 * d;

  vec_add2 (pm->pcap_data, d, sizeof (h[0]) + n_bytes_in_trace);
  h = (void *) (d);
  h->time_in_sec = time_now;
  h->time_in_usec = 1e6*(time_now - h->time_in_sec);
  h->n_packet_bytes_stored_in_file = n_bytes_in_trace;
  h->n_bytes_in_packet = n_bytes_in_packet;
  pm->n_packets_captured++;
  return h->data;
}

/**
 * @brief Add buffer (vlib_buffer_t) to the trace
 *
 * @param *pm - pcap_main_t
 * @param *vm - vlib_main_t
 * @param buffer_index - u32
 * @param n_bytes_in_trace - u32
 *
 */
static inline void
pcap_add_buffer (pcap_main_t * pm,
		 vlib_main_t * vm, u32 buffer_index,
		 u32 n_bytes_in_trace)
{
  vlib_buffer_t * b = vlib_get_buffer (vm, buffer_index);
  u32 n = vlib_buffer_length_in_chain (vm, b);
  i32 n_left = clib_min (n_bytes_in_trace, n);
  f64 time_now = vlib_time_now (vm);
  void * d;

  d = pcap_add_packet (pm, time_now, n_left, n);
  while (1)
    {
      u32 copy_length = clib_min ((u32) n_left, b->current_length);
      clib_memcpy (d, b->data + b->current_data, copy_length);
      n_left -= b->current_length;
      if (n_left <= 0)
	break;
      d += b->current_length;
      ASSERT (b->flags & VLIB_BUFFER_NEXT_PRESENT);
      b = vlib_get_buffer (vm, b->next_buffer);
    }

  /** Flush output vector. */
  if (vec_len (pm->pcap_data) >= 64*1024
      || pm->n_packets_captured >= pm->n_packets_to_capture)
    pcap_write (pm);
}

#endif /* included_vnet_pcap_h */
