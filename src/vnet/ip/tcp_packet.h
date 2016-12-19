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
 * ip4/tcp_packet.h: TCP packet format (see RFC 793)
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

#ifndef included_tcp_packet_h
#define included_tcp_packet_h

/* TCP flags bit 0 first. */
#define foreach_tcp_flag			\
  _ (FIN)					\
  _ (SYN)					\
  _ (RST)					\
  _ (PSH)					\
  _ (ACK)					\
  _ (URG)					\
  _ (ECE)					\
  _ (CWR)

enum
{
#define _(f) TCP_FLAG_BIT_##f,
  foreach_tcp_flag
#undef _
    TCP_N_FLAG_BITS,

#define _(f) TCP_FLAG_##f = 1 << TCP_FLAG_BIT_##f,
  foreach_tcp_flag
#undef _
};

typedef struct
{
  /* Source and destination port. */
  union
  {
    union
    {
      struct
      {
	u16 src, dst;
      };
      u32 src_and_dst;
    } ports;
    u16 src_port, dst_port;
  };

  /* Sequence and acknowledgment number. */
  u32 seq_number, ack_number;

  /* Size of TCP header in 32-bit units plus 4 reserved bits. */
  u8 tcp_header_u32s_and_reserved;

  /* see foreach_tcp_flag for enumation of tcp flags. */
  u8 flags;

  /* Current window advertised by sender.
     This is the number of bytes sender is willing to receive
     right now. */
  u16 window;

  /* Checksum of TCP pseudo header and data. */
  u16 checksum;

  u16 urgent_pointer;
} tcp_header_t;

always_inline int
tcp_header_bytes (tcp_header_t * t)
{
  return (t->tcp_header_u32s_and_reserved >> 4) * sizeof (u32);
}

/* TCP options. */
typedef enum tcp_option_type
{
  TCP_OPTION_END = 0,
  TCP_OPTION_NOP = 1,
  TCP_OPTION_MSS = 2,
  TCP_OPTION_WINDOW_SCALE = 3,
  TCP_OPTION_SACK_PERMITTED = 4,
  TCP_OPTION_SACK_BLOCK = 5,
  TCP_OPTION_TIME_STAMP = 8,
} tcp_option_type_t;

/* All except NOP and END have 1 byte length field. */
typedef struct
{
  tcp_option_type_t type:8;

  /* Length of this option in bytes. */
  u8 length;
} tcp_option_with_length_t;

#endif /* included_tcp_packet_h */


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
