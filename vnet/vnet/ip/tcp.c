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
 * ip/tcp.c: tcp protocol
 *
 * Copyright (c) 2011 Eliot Dresselhaus
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

#include <vnet/ip/ip.h>
#include <vnet/ip/tcp.h>
#include <math.h>

static u8 my_zero_mask_table[256] = {
  [0xf0] = (1 << 1),
  [0x0f] = (1 << 0),
  [0xff] = (1 << 0) | (1 << 1),
};

static_always_inline u32 my_zero_mask (u32 x)
{
  return ((my_zero_mask_table[(x >> 0) & 0xff] << 0)
	  | (my_zero_mask_table[(x >> 8) & 0xff] << 2));
}

static u8 my_first_set_table[256] = {
  [0x00] = 4,
  [0xf0] = 1,
  [0x0f] = 0,
  [0xff] = 0,
};

static_always_inline u32 my_first_set (u32 zero_mask)
{
  u8 r0 = my_first_set_table[(zero_mask >> 0) & 0xff];
  u8 r1 = 2 + my_first_set_table[(zero_mask >> 8) & 0xff];
  return r0 != 4 ? r0 : r1;
}

static_always_inline void
ip4_tcp_udp_address_x4_set_from_headers (ip4_tcp_udp_address_x4_t * a,
					 ip4_header_t * ip,
					 tcp_header_t * tcp,
					 u32 i)
{
  a->src.as_ip4_address[i] = ip->src_address;
  a->dst.as_ip4_address[i] = ip->dst_address;
  a->ports.as_ports[i].as_u32 = tcp->ports.src_and_dst;
}

static_always_inline void
ip4_tcp_udp_address_x4_copy_and_invalidate (ip4_tcp_udp_address_x4_t * dst,
					    ip4_tcp_udp_address_x4_t * src,
					    u32 dst_i, u32 src_i)
{
#define _(d,s) d = s; s = 0;
  _ (dst->src.as_ip4_address[dst_i].as_u32, src->src.as_ip4_address[src_i].as_u32);
  _ (dst->dst.as_ip4_address[dst_i].as_u32, src->dst.as_ip4_address[src_i].as_u32);
  _ (dst->ports.as_ports[dst_i].as_u32, src->ports.as_ports[src_i].as_u32);
#undef _
}

static_always_inline void
ip4_tcp_udp_address_x4_invalidate (ip4_tcp_udp_address_x4_t * a, u32 i)
{
  a->src.as_ip4_address[i].as_u32 = 0;
  a->dst.as_ip4_address[i].as_u32 = 0;
  a->ports.as_ports[i].as_u32 = 0;
}

static_always_inline uword
ip4_tcp_udp_address_x4_is_valid (ip4_tcp_udp_address_x4_t * a, u32 i)
{
  return !(a->src.as_ip4_address[i].as_u32 == 0
	   && a->dst.as_ip4_address[i].as_u32 == 0
	   && a->ports.as_ports[i].as_u32 == 0);
}

#ifdef TCP_HAVE_VEC128
static_always_inline uword
ip4_tcp_udp_address_x4_match_helper (ip4_tcp_udp_address_x4_t * ax4,
				     u32x4 src, u32x4 dst, u32x4 ports)
{
  u32x4 r;
  u32 m;

  r = u32x4_is_equal (src, ax4->src.as_u32x4);
  r &= u32x4_is_equal (dst, ax4->dst.as_u32x4);
  r &= u32x4_is_equal (ports, ax4->ports.as_u32x4);

  /* At this point r will be either all zeros (if nothing matched)
     or have 32 1s in the position that did match. */
  m = u8x16_compare_byte_mask ((u8x16) r);

  return m;
}

static_always_inline uword
ip4_tcp_udp_address_x4_match (ip4_tcp_udp_address_x4_t * ax4,
			      ip4_header_t * ip,
			      tcp_header_t * tcp)
{
  u32x4 src = u32x4_splat (ip->src_address.as_u32);
  u32x4 dst = u32x4_splat (ip->dst_address.as_u32);
  u32x4 ports = u32x4_splat (tcp->ports.src_and_dst);
  return my_first_set (ip4_tcp_udp_address_x4_match_helper (ax4, src, dst, ports));
}

static_always_inline uword
ip4_tcp_udp_address_x4_first_empty (ip4_tcp_udp_address_x4_t * ax4)
{
  u32x4 zero = {0};
  return my_first_set (ip4_tcp_udp_address_x4_match_helper (ax4, zero, zero, zero));
}

static_always_inline uword
ip4_tcp_udp_address_x4_empty_mask (ip4_tcp_udp_address_x4_t * ax4)
{
  u32x4 zero = {0};
  return my_zero_mask (ip4_tcp_udp_address_x4_match_helper (ax4, zero, zero, zero));
}
#else /* TCP_HAVE_VEC128 */
static_always_inline uword
ip4_tcp_udp_address_x4_match_helper (ip4_tcp_udp_address_x4_t * ax4,
				     u32 src, u32 dst, u32 ports)
{
  u32 r0, r1, r2, r3;

#define _(i)						\
  r##i = (src == ax4->src.as_ip4_address[i].as_u32	\
	  && dst == ax4->dst.as_ip4_address[i].as_u32	\
	  && ports == ax4->ports.as_ports[i].as_u32)

  _ (0);
  _ (1);
  _ (2);
  _ (3);

#undef _

  return (((r0 ? 0xf : 0x0) << 0)
	  | ((r1 ? 0xf : 0x0) << 4)
	  | ((r2 ? 0xf : 0x0) << 8)
	  | ((r3 ? 0xf : 0x0) << 12));
}

static_always_inline uword
ip4_tcp_udp_address_x4_match (ip4_tcp_udp_address_x4_t * ax4,
			      ip4_header_t * ip,
			      tcp_header_t * tcp)
{
  return my_first_set (ip4_tcp_udp_address_x4_match_helper (ax4,
							    ip->src_address.as_u32,
							    ip->dst_address.as_u32,
							    tcp->ports.src_and_dst));
}

static_always_inline uword
ip4_tcp_udp_address_x4_first_empty (ip4_tcp_udp_address_x4_t * ax4)
{
  return my_first_set (ip4_tcp_udp_address_x4_match_helper (ax4, 0, 0, 0));
}

static_always_inline uword
ip4_tcp_udp_address_x4_empty_mask (ip4_tcp_udp_address_x4_t * ax4)
{
  return my_zero_mask (ip4_tcp_udp_address_x4_match_helper (ax4, 0, 0, 0));
}
#endif

static u8 * format_ip4_tcp_udp_address_x4 (u8 * s, va_list * va)
{
  ip4_tcp_udp_address_x4_t * a = va_arg (*va, ip4_tcp_udp_address_x4_t *);  
  u32 ai = va_arg (*va, u32);
  ASSERT (ai < 4);

  s = format (s, "%U:%d -> %U:%d",
	      format_ip4_address, &a->src.as_ip4_address[ai],
	      clib_net_to_host_u16 (a->ports.as_ports[ai].src),
	      format_ip4_address, &a->dst.as_ip4_address[ai],
	      clib_net_to_host_u16 (a->ports.as_ports[ai].dst));

  return s;
}

static_always_inline void
ip6_tcp_udp_address_x4_set_from_headers (ip6_tcp_udp_address_x4_t * a,
					 ip6_header_t * ip,
					 tcp_header_t * tcp,
					 u32 i)
{
  a->src.as_u32[0][i] = ip->src_address.as_u32[0];
  a->src.as_u32[1][i] = ip->src_address.as_u32[1];
  a->src.as_u32[2][i] = ip->src_address.as_u32[2];
  a->src.as_u32[3][i] = ip->src_address.as_u32[3];
  a->dst.as_u32[0][i] = ip->dst_address.as_u32[0];
  a->dst.as_u32[1][i] = ip->dst_address.as_u32[1];
  a->dst.as_u32[2][i] = ip->dst_address.as_u32[2];
  a->dst.as_u32[3][i] = ip->dst_address.as_u32[3];
  a->ports.as_ports[i].as_u32 = tcp->ports.src_and_dst;
}

static_always_inline void
ip6_tcp_udp_address_x4_copy_and_invalidate (ip6_tcp_udp_address_x4_t * dst,
					    ip6_tcp_udp_address_x4_t * src,
					    u32 dst_i, u32 src_i)
{
#define _(d,s) d = s; s = 0;
  _ (dst->src.as_u32[0][dst_i], src->src.as_u32[0][src_i]);
  _ (dst->src.as_u32[1][dst_i], src->src.as_u32[1][src_i]);
  _ (dst->src.as_u32[2][dst_i], src->src.as_u32[2][src_i]);
  _ (dst->src.as_u32[3][dst_i], src->src.as_u32[3][src_i]);
  _ (dst->dst.as_u32[0][dst_i], src->dst.as_u32[0][src_i]);
  _ (dst->dst.as_u32[1][dst_i], src->dst.as_u32[1][src_i]);
  _ (dst->dst.as_u32[2][dst_i], src->dst.as_u32[2][src_i]);
  _ (dst->dst.as_u32[3][dst_i], src->dst.as_u32[3][src_i]);
  _ (dst->ports.as_ports[dst_i].as_u32, src->ports.as_ports[src_i].as_u32);
#undef _
}

static_always_inline void
ip6_tcp_udp_address_x4_invalidate (ip6_tcp_udp_address_x4_t * a, u32 i)
{
  a->src.as_u32[0][i] = 0;
  a->src.as_u32[1][i] = 0;
  a->src.as_u32[2][i] = 0;
  a->src.as_u32[3][i] = 0;
  a->dst.as_u32[0][i] = 0;
  a->dst.as_u32[1][i] = 0;
  a->dst.as_u32[2][i] = 0;
  a->dst.as_u32[3][i] = 0;
  a->ports.as_ports[i].as_u32 = 0;
}

static_always_inline uword
ip6_tcp_udp_address_x4_is_valid (ip6_tcp_udp_address_x4_t * a, u32 i)
{
  return !(a->src.as_u32[0][i] == 0
	   && a->src.as_u32[1][i] == 0
	   && a->src.as_u32[2][i] == 0
	   && a->src.as_u32[3][i] == 0
	   && a->dst.as_u32[0][i] == 0
	   && a->dst.as_u32[1][i] == 0
	   && a->dst.as_u32[2][i] == 0
	   && a->dst.as_u32[3][i] == 0
	   && a->ports.as_ports[i].as_u32 == 0);
}

#ifdef TCP_HAVE_VEC128
static_always_inline uword
ip6_tcp_udp_address_x4_match_helper (ip6_tcp_udp_address_x4_t * ax4,
				     u32x4 src0, u32x4 src1, u32x4 src2, u32x4 src3,
				     u32x4 dst0, u32x4 dst1, u32x4 dst2, u32x4 dst3,
				     u32x4 ports)
{
  u32x4 r;
  u32 m;

  r = u32x4_is_equal (src0, ax4->src.as_u32x4[0]);
  r &= u32x4_is_equal (src1, ax4->src.as_u32x4[1]);
  r &= u32x4_is_equal (src2, ax4->src.as_u32x4[2]);
  r &= u32x4_is_equal (src3, ax4->src.as_u32x4[3]);
  r &= u32x4_is_equal (dst0, ax4->dst.as_u32x4[0]);
  r &= u32x4_is_equal (dst1, ax4->dst.as_u32x4[1]);
  r &= u32x4_is_equal (dst2, ax4->dst.as_u32x4[2]);
  r &= u32x4_is_equal (dst3, ax4->dst.as_u32x4[3]);
  r &= u32x4_is_equal (ports, ax4->ports.as_u32x4);

  /* At this point r will be either all zeros (if nothing matched)
     or have 32 1s in the position that did match. */
  m = u8x16_compare_byte_mask ((u8x16) r);

  return m;
}

static_always_inline uword
ip6_tcp_udp_address_x4_match (ip6_tcp_udp_address_x4_t * ax4,
			      ip6_header_t * ip,
			      tcp_header_t * tcp)
{
  u32x4 src0 = u32x4_splat (ip->src_address.as_u32[0]);
  u32x4 src1 = u32x4_splat (ip->src_address.as_u32[1]);
  u32x4 src2 = u32x4_splat (ip->src_address.as_u32[2]);
  u32x4 src3 = u32x4_splat (ip->src_address.as_u32[3]);
  u32x4 dst0 = u32x4_splat (ip->dst_address.as_u32[0]);
  u32x4 dst1 = u32x4_splat (ip->dst_address.as_u32[1]);
  u32x4 dst2 = u32x4_splat (ip->dst_address.as_u32[2]);
  u32x4 dst3 = u32x4_splat (ip->dst_address.as_u32[3]);
  u32x4 ports = u32x4_splat (tcp->ports.src_and_dst);
  return my_first_set (ip6_tcp_udp_address_x4_match_helper (ax4,
							    src0, src1, src2, src3,
							    dst0, dst1, dst2, dst3,
							    ports));
}

static_always_inline uword
ip6_tcp_udp_address_x4_first_empty (ip6_tcp_udp_address_x4_t * ax4)
{
  u32x4 zero = {0};
  return my_first_set (ip6_tcp_udp_address_x4_match_helper (ax4,
							    zero, zero, zero, zero,
							    zero, zero, zero, zero,
							    zero));
}

static_always_inline uword
ip6_tcp_udp_address_x4_empty_mask (ip6_tcp_udp_address_x4_t * ax4)
{
  u32x4 zero = {0};
  return my_zero_mask (ip6_tcp_udp_address_x4_match_helper (ax4,
							    zero, zero, zero, zero,
							    zero, zero, zero, zero,
							    zero));
}
#else /* TCP_HAVE_VEC128 */
static_always_inline uword
ip6_tcp_udp_address_x4_match_helper (ip6_tcp_udp_address_x4_t * ax4,
				     u32 src0, u32 src1, u32 src2, u32 src3,
				     u32 dst0, u32 dst1, u32 dst2, u32 dst3,
				     u32 ports)
{
  u32 r0, r1, r2, r3;

#define _(i)							\
  r##i = (src0 == ax4->src.as_u32[i][0]		\
	  && src1 == ax4->src.as_u32[i][1]	\
	  && src2 == ax4->src.as_u32[i][2]	\
	  && src3 == ax4->src.as_u32[i][3]	\
	  && dst0 == ax4->dst.as_u32[i][0]	\
	  && dst1 == ax4->dst.as_u32[i][1]	\
	  && dst2 == ax4->dst.as_u32[i][2]	\
	  && dst3 == ax4->dst.as_u32[i][3]	\
	  && ports == ax4->ports.as_ports[i].as_u32)

  _ (0);
  _ (1);
  _ (2);
  _ (3);

#undef _

  return (((r0 ? 0xf : 0x0) << 0)
	  | ((r1 ? 0xf : 0x0) << 4)
	  | ((r2 ? 0xf : 0x0) << 8)
	  | ((r3 ? 0xf : 0x0) << 12));
}

static_always_inline uword
ip6_tcp_udp_address_x4_match (ip6_tcp_udp_address_x4_t * ax4,
			      ip6_header_t * ip,
			      tcp_header_t * tcp)
{
  u32 src0 = ip->src_address.as_u32[0];
  u32 src1 = ip->src_address.as_u32[1];
  u32 src2 = ip->src_address.as_u32[2];
  u32 src3 = ip->src_address.as_u32[3];
  u32 dst0 = ip->dst_address.as_u32[0];
  u32 dst1 = ip->dst_address.as_u32[1];
  u32 dst2 = ip->dst_address.as_u32[2];
  u32 dst3 = ip->dst_address.as_u32[3];
  u32 ports = tcp->ports.src_and_dst;
  return my_first_set (ip6_tcp_udp_address_x4_match_helper (ax4,
							    src0, src1, src2, src3,
							    dst0, dst1, dst2, dst3,
							    ports));
}

static_always_inline uword
ip6_tcp_udp_address_x4_first_empty (ip6_tcp_udp_address_x4_t * ax4)
{
  return my_first_set (ip6_tcp_udp_address_x4_match_helper (ax4,
							    0, 0, 0, 0,
							    0, 0, 0, 0,
							    0));
}

static_always_inline uword
ip6_tcp_udp_address_x4_empty_mask (ip6_tcp_udp_address_x4_t * ax4)
{
  return my_zero_mask (ip6_tcp_udp_address_x4_match_helper (ax4,
							    0, 0, 0, 0,
							    0, 0, 0, 0,
							    0));
}
#endif /* ! TCP_HAVE_VEC128 */

static u8 * format_ip6_tcp_udp_address_x4 (u8 * s, va_list * va)
{
  ip6_tcp_udp_address_x4_t * a = va_arg (*va, ip6_tcp_udp_address_x4_t *);  
  u32 i, ai = va_arg (*va, u32);
  ip6_address_t src, dst;

  ASSERT (ai < 4);
  for (i = 0; i < 4; i++)
    {
      src.as_u32[i] = a->src.as_u32[i][ai];
      dst.as_u32[i] = a->dst.as_u32[i][ai];
    }

  s = format (s, "%U:%d -> %U:%d",
	      format_ip6_address, &src,
	      clib_net_to_host_u16 (a->ports.as_ports[ai].src),
	      format_ip6_address, &dst,
	      clib_net_to_host_u16 (a->ports.as_ports[ai].dst));

  return s;
}

static_always_inline u32
find_oldest_timestamp_x4 (u32 * time_stamps, u32 now)
{
  u32 dt0, dt_min0, i_min0;
  u32 dt1, dt_min1, i_min1;

  i_min0 = i_min1 = 0;
  dt_min0 = now - time_stamps[0];
  dt_min1 = now - time_stamps[2];
  dt0 = now - time_stamps[1];
  dt1 = now - time_stamps[3];

  i_min0 += dt0 > dt_min0;
  i_min1 += dt1 > dt_min1;

  dt_min0 = i_min0 > 0 ? dt0 : dt_min0;
  dt_min1 = i_min1 > 0 ? dt1 : dt_min1;

  return dt_min0 > dt_min1 ? i_min0 : (2 + i_min1);
}

static_always_inline uword
tcp_round_trip_time_stats_is_valid (tcp_round_trip_time_stats_t * s)
{ return s->count > 0; }

static_always_inline void
tcp_round_trip_time_stats_compute (tcp_round_trip_time_stats_t * s, f64 * r)
{
  f64 ave, rms;
  ASSERT (s->count > 0);
  ave = s->sum / s->count;
  rms = sqrt (s->sum2 / s->count - ave*ave);
  r[0] = ave;
  r[1] = rms;
}

typedef struct {
  tcp_option_type_t type : 8;
  u8 length;
  u32 my_time_stamp, his_time_stamp;
} __attribute__ ((packed)) tcp_time_stamp_option_t;

typedef struct {
  tcp_header_t header;

  struct {
    struct {
      tcp_option_type_t type : 8;
      u8 length;
      u16 value;
    } mss;

    struct {
      tcp_option_type_t type : 8;
      u8 length;
      u8 value;
    } __attribute__ ((packed)) window_scale;

    u8 nops[3];

    tcp_time_stamp_option_t time_stamp;
  } __attribute__ ((packed)) options;
} __attribute__ ((packed)) tcp_syn_packet_t;

typedef struct {
  tcp_header_t header;

  struct {
    u8 nops[2];

    tcp_time_stamp_option_t time_stamp;
  } options;
} __attribute__ ((packed)) tcp_ack_packet_t;

typedef struct {
  ip4_header_t ip4;
  tcp_syn_packet_t tcp;
} ip4_tcp_syn_packet_t;

typedef struct {
  ip4_header_t ip4;
  tcp_ack_packet_t tcp;
} ip4_tcp_ack_packet_t;

typedef struct {
  ip6_header_t ip6;
  tcp_syn_packet_t tcp;
} ip6_tcp_syn_packet_t;

typedef struct {
  ip6_header_t ip6;
  tcp_ack_packet_t tcp;
} ip6_tcp_ack_packet_t;

static_always_inline void
ip4_tcp_packet_init (ip4_header_t * ip, u32 n_bytes)
{
  ip->ip_version_and_header_length = 0x45;

  ip->tos = ip4_main.host_config.tos;
  ip->ttl = ip4_main.host_config.ttl;

  /* No need to set fragment ID due to DF bit. */
  ip->flags_and_fragment_offset = clib_host_to_net_u16 (IP4_HEADER_FLAG_DONT_FRAGMENT);

  ip->protocol = IP_PROTOCOL_TCP;

  ip->length = clib_host_to_net_u16 (n_bytes);

  ip->checksum = ip4_header_checksum (ip);
}

static_always_inline void
ip6_tcp_packet_init (ip6_header_t * ip, u32 n_bytes)
{
  ip->ip_version_traffic_class_and_flow_label = clib_host_to_net_u32 (0x6 << 28);

  ip->payload_length = clib_host_to_net_u16 (n_bytes - sizeof (ip[0]));

  ip->hop_limit = ip6_main.host_config.ttl;
}

static_always_inline u32
tcp_time_now (tcp_main_t * tm, tcp_timer_type_t t)
{
  ASSERT (t < ARRAY_LEN (tm->log2_clocks_per_tick));
  return clib_cpu_time_now () >> tm->log2_clocks_per_tick[t];
}

static void
tcp_time_init (vlib_main_t * vm, tcp_main_t * tm)
{
  int i;
  f64 log2 = .69314718055994530941;

  for (i = 0; i < ARRAY_LEN (tm->log2_clocks_per_tick); i++)
    {
      static f64 t[] = {
#define _(f,r) r,
	foreach_tcp_timer
#undef _
      };
      tm->log2_clocks_per_tick[i] =
	flt_round_nearest (log (t[i] / vm->clib_time.seconds_per_clock) / log2);
      tm->secs_per_tick[i] = vm->clib_time.seconds_per_clock * (1 << tm->log2_clocks_per_tick[i]);
    }
}

tcp_main_t tcp_main;

typedef enum {
  TCP_LOOKUP_NEXT_DROP,
  TCP_LOOKUP_NEXT_PUNT,
  TCP_LOOKUP_NEXT_LISTEN_SYN,
  TCP_LOOKUP_NEXT_LISTEN_ACK,
  TCP_LOOKUP_NEXT_CONNECT_SYN_ACK,
  TCP_LOOKUP_NEXT_ESTABLISHED,
  TCP_LOOKUP_N_NEXT,
} tcp_lookup_next_t;

#define foreach_tcp_error						\
  _ (NONE, "no error")							\
  _ (LOOKUP_DROPS, "lookup drops")					\
  _ (LISTEN_RESPONSES, "listen responses sent")				\
  _ (CONNECTS_SENT, "connects sent")					\
  _ (LISTENS_ESTABLISHED, "listens connected")				\
  _ (UNEXPECTED_SEQ_NUMBER, "unexpected sequence number drops")		\
  _ (UNEXPECTED_ACK_NUMBER, "unexpected acknowledgment number drops")	\
  _ (CONNECTS_ESTABLISHED, "connects established")			\
  _ (NO_LISTENER_FOR_PORT, "no listener for port")			\
  _ (WRONG_LOCAL_ADDRESS_FOR_PORT, "wrong local address for port")	\
  _ (ACKS_SENT, "acks sent for established connections")		\
  _ (NO_DATA, "acks with no data")					\
  _ (FINS_RECEIVED, "fins received")					\
  _ (SEGMENT_AFTER_FIN, "segments dropped after fin received")		\
  _ (CONNECTIONS_CLOSED, "connections closed")

typedef enum {
#define _(sym,str) TCP_ERROR_##sym,
  foreach_tcp_error
#undef _
  TCP_N_ERROR,
} tcp_error_t;

#ifdef TCP_HAVE_VEC128
static_always_inline u32x4 u32x4_splat_x2 (u32 x)
{
  u32x4 r = u32x4_set0 (x);
  return u32x4_interleave_lo (r, r);
}

static_always_inline u32x4 u32x4_set_x2 (u32 x, u32 y)
{
  u32x4 r0 = u32x4_set0 (x);
  u32x4 r1 = u32x4_set0 (y);
  return u32x4_interleave_lo (r0, r1);
}

/* FIXME */
#define u32x4_get(x,i)					\
  __builtin_ia32_vec_ext_v4si ((i32x4) (x), (int) (i))
#else /* TCP_HAVE_VEC128 */
#endif /* TCP_HAVE_VEC128 */

/* Dispatching on tcp/udp listeners (by dst port)
   and tcp/udp connections (by src/dst address/port). */
static_always_inline uword
ip46_tcp_lookup (vlib_main_t * vm,
		 vlib_node_runtime_t * node,
		 vlib_frame_t * frame,
		 uword is_ip6)
{
  tcp_main_t * tm = &tcp_main;
  ip46_tcp_main_t * tm46 = is_ip6 ? &tm->ip6 : &tm->ip4;
  uword n_packets = frame->n_vectors;
  u32 * from, * to_next;
  u32 n_left_from, n_left_to_next, next, mini_now;
  vlib_node_runtime_t * error_node = node;

  from = vlib_frame_vector_args (frame);
  n_left_from = n_packets;
  next = node->cached_next_index;
  mini_now = tcp_time_now (tm, TCP_TIMER_mini_connection);
  
  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  vlib_buffer_t * p0;
	  ip6_header_t * ip60;
	  ip4_header_t * ip40;
	  tcp_header_t * tcp0;
	  u32 bi0, imin0, iest0, li0;
	  tcp_connection_state_t state0;
	  u8 error0, next0;
	  u8 min_match0, est_match0, is_min_match0, is_est_match0;
	  u8 min_oldest0, est_first_empty0;
      
	  bi0 = to_next[0] = from[0];

	  from += 1;
	  n_left_from -= 1;
	  to_next += 1;
	  n_left_to_next -= 1;
      
	  p0 = vlib_get_buffer (vm, bi0);

#ifdef TCP_HAVE_VEC128
	  {
	    u32x4 a0, b0, c0;

	    a0 = tm->connection_hash_seeds[is_ip6][0].as_u32x4;
	    b0 = tm->connection_hash_seeds[is_ip6][1].as_u32x4;
	    c0 = tm->connection_hash_seeds[is_ip6][2].as_u32x4;

	    if (is_ip6)
	      {
		ip60 = vlib_buffer_get_current (p0);
		tcp0 = ip6_next_header (ip60);

		a0 ^= u32x4_splat_x2 (ip60->src_address.as_u32[0]);
		b0 ^= u32x4_splat_x2 (ip60->src_address.as_u32[1]);
		c0 ^= u32x4_splat_x2 (ip60->src_address.as_u32[2]);

		hash_v3_mix_u32x (a0, b0, c0);

		a0 ^= u32x4_splat_x2 (ip60->src_address.as_u32[3]);
		b0 ^= u32x4_splat_x2 (ip60->dst_address.as_u32[0]);
		c0 ^= u32x4_splat_x2 (ip60->dst_address.as_u32[1]);

		hash_v3_mix_u32x (a0, b0, c0);

		a0 ^= u32x4_splat_x2 (ip60->dst_address.as_u32[2]);
		b0 ^= u32x4_splat_x2 (ip60->dst_address.as_u32[3]);
		c0 ^= u32x4_splat_x2 (tcp0->ports.src_and_dst);
	      }
	    else
	      {
		ip40 = vlib_buffer_get_current (p0);
		tcp0 = ip4_next_header (ip40);

		a0 ^= u32x4_splat_x2 (ip40->src_address.as_u32);
		b0 ^= u32x4_splat_x2 (ip40->dst_address.as_u32);
		c0 ^= u32x4_splat_x2 (tcp0->ports.src_and_dst);
	      }

	    hash_v3_finalize_u32x (a0, b0, c0);

	    c0 &= tm->connection_hash_masks[is_ip6].as_u32x4;

	    imin0 = u32x4_get0 (c0);
	    iest0 = u32x4_get (c0, 1);
	  }
#else
	  {
	    u32 a00, a01, b00, b01, c00, c01;

	    a00 = tm->connection_hash_seeds[is_ip6][0].as_u32[0];
	    a01 = tm->connection_hash_seeds[is_ip6][0].as_u32[1];
	    b00 = tm->connection_hash_seeds[is_ip6][1].as_u32[0];
	    b01 = tm->connection_hash_seeds[is_ip6][1].as_u32[1];
	    c00 = tm->connection_hash_seeds[is_ip6][2].as_u32[0];
	    c01 = tm->connection_hash_seeds[is_ip6][2].as_u32[1];

	    if (is_ip6)
	      {
		ip60 = vlib_buffer_get_current (p0);
		tcp0 = ip6_next_header (ip60);

		a00 ^= ip60->src_address.as_u32[0];
		a01 ^= ip60->src_address.as_u32[0];
		b00 ^= ip60->src_address.as_u32[1];
		b01 ^= ip60->src_address.as_u32[1];
		c00 ^= ip60->src_address.as_u32[2];
		c01 ^= ip60->src_address.as_u32[2];

		hash_v3_mix32 (a00, b00, c00);
		hash_v3_mix32 (a01, b01, c01);

		a00 ^= ip60->src_address.as_u32[3];
		a01 ^= ip60->src_address.as_u32[3];
		b00 ^= ip60->dst_address.as_u32[0];
		b01 ^= ip60->dst_address.as_u32[0];
		c00 ^= ip60->dst_address.as_u32[1];
		c01 ^= ip60->dst_address.as_u32[1];

		hash_v3_mix32 (a00, b00, c00);
		hash_v3_mix32 (a01, b01, c01);

		a00 ^= ip60->dst_address.as_u32[2];
		a01 ^= ip60->dst_address.as_u32[2];
		b00 ^= ip60->dst_address.as_u32[3];
		b01 ^= ip60->dst_address.as_u32[3];
		c00 ^= tcp0->ports.src_and_dst;
		c01 ^= tcp0->ports.src_and_dst;
	      }
	    else
	      {
		ip40 = vlib_buffer_get_current (p0);
		tcp0 = ip4_next_header (ip40);

		a00 ^= ip40->src_address.as_u32;
		a01 ^= ip40->src_address.as_u32;
		b00 ^= ip40->dst_address.as_u32;
		b01 ^= ip40->dst_address.as_u32;
		c00 ^= tcp0->ports.src_and_dst;
		c01 ^= tcp0->ports.src_and_dst;
	      }

	    hash_v3_finalize32 (a00, b00, c00);
	    hash_v3_finalize32 (a01, b01, c01);

	    c00 &= tm->connection_hash_masks[is_ip6].as_u32[0];
	    c01 &= tm->connection_hash_masks[is_ip6].as_u32[1];

	    imin0 = c00;
	    iest0 = c01;
	  }
#endif

	  if (is_ip6)
	    {
	      ip6_tcp_udp_address_x4_and_timestamps_t * mina0;
	      ip6_tcp_udp_address_x4_t * esta0;

	      mina0 = vec_elt_at_index (tm->ip6_mini_connection_address_hash, imin0);
	      esta0 = vec_elt_at_index (tm->ip6_established_connection_address_hash, iest0);

	      min_match0 = ip6_tcp_udp_address_x4_match (&mina0->address_x4, ip60, tcp0);
	      est_match0 = ip6_tcp_udp_address_x4_match (esta0, ip60, tcp0);

	      min_oldest0 = find_oldest_timestamp_x4 (mina0->time_stamps, mini_now);
	      est_first_empty0 = ip6_tcp_udp_address_x4_first_empty (esta0);

	      if (PREDICT_FALSE (! est_match0 && est_first_empty0 >= 4 && ! min_match0))
		{
		  /* Lookup in overflow hash. */
		  ASSERT (0);
		}
	    }
	  else
	    {
	      ip4_tcp_udp_address_x4_and_timestamps_t * mina0;
	      ip4_tcp_udp_address_x4_t * esta0;

	      mina0 = vec_elt_at_index (tm->ip4_mini_connection_address_hash, imin0);
	      esta0 = vec_elt_at_index (tm->ip4_established_connection_address_hash, iest0);

	      min_match0 = ip4_tcp_udp_address_x4_match (&mina0->address_x4, ip40, tcp0);
	      est_match0 = ip4_tcp_udp_address_x4_match (esta0, ip40, tcp0);

	      min_oldest0 = find_oldest_timestamp_x4 (mina0->time_stamps, mini_now);
	      est_first_empty0 = ip4_tcp_udp_address_x4_first_empty (esta0);

	      if (PREDICT_FALSE (! est_match0 && est_first_empty0 >= 4 && ! min_match0))
		{
		  /* Lookup in overflow hash. */
		  ASSERT (0);
		}
	    }

	  is_min_match0 = min_match0 < 4;
	  is_est_match0 = est_match0 < 4;

	  imin0 = 4 * imin0 + (is_min_match0 ? min_match0 : min_oldest0);
	  iest0 = 4 * iest0 + (is_est_match0 ? est_match0 : est_first_empty0);

	  /* Should simultaneously not match both in mini and established connection tables. */
	  ASSERT (! (is_min_match0 && is_est_match0));

	  {
	    tcp_mini_connection_t * min0;
	    tcp_connection_t * est0;
	    tcp_sequence_pair_t * seq_pair0;
	    u8 flags0;

	    min0 = vec_elt_at_index (tm46->mini_connections, imin0);
	    est0 = vec_elt_at_index (tm46->established_connections, iest0);

	    if (min_match0 < 4)
	      {
		ASSERT (min0->state != TCP_CONNECTION_STATE_unused);
		ASSERT (min0->state != TCP_CONNECTION_STATE_established);
	      }

	    seq_pair0 = is_min_match0 ? &min0->sequence_numbers : &est0->sequence_numbers;

	    state0 = is_min_match0 ? min0->state : TCP_CONNECTION_STATE_unused;
	    state0 = is_est_match0 ? TCP_CONNECTION_STATE_established : state0;

	    vnet_buffer (p0)->ip.tcp.established_connection_index = iest0;
	    vnet_buffer (p0)->ip.tcp.mini_connection_index = imin0;
	    vnet_buffer (p0)->ip.tcp.listener_index = li0 = tm->listener_index_by_dst_port[tcp0->ports.dst];

	    flags0 = tcp0->flags & (TCP_FLAG_SYN | TCP_FLAG_ACK | TCP_FLAG_RST | TCP_FLAG_FIN);

	    next0 = tm->disposition_by_state_and_flags[state0][flags0].next;
	    error0 = tm->disposition_by_state_and_flags[state0][flags0].error;

	    next0 = li0 != 0 ? next0 : TCP_LOOKUP_NEXT_PUNT;
	    error0 = li0 != 0 ? error0 : TCP_ERROR_NO_LISTENER_FOR_PORT;
	  }

	  p0->error = error_node->errors[error0];

	  if (PREDICT_FALSE (next0 != next))
	    {
	      to_next -= 1;
	      n_left_to_next += 1;

	      vlib_put_next_frame (vm, node, next, n_left_to_next);

	      next = next0;
	      vlib_get_next_frame (vm, node, next, to_next, n_left_to_next);
	      to_next[0] = bi0;
	      to_next += 1;
	      n_left_to_next -= 1;
	    }
	}
  
      vlib_put_next_frame (vm, node, next, n_left_to_next);
    }

  if (node->flags & VLIB_NODE_FLAG_TRACE)
    /* FIXME */ ;

  return frame->n_vectors;
}

static uword
ip4_tcp_lookup (vlib_main_t * vm,
		vlib_node_runtime_t * node,
		vlib_frame_t * frame)
{ return ip46_tcp_lookup (vm, node, frame, /* is_ip6 */ 0); }

static uword
ip6_tcp_lookup (vlib_main_t * vm,
		vlib_node_runtime_t * node,
		vlib_frame_t * frame)
{ return ip46_tcp_lookup (vm, node, frame, /* is_ip6 */ 1); }

static void
ip46_size_hash_tables (ip46_tcp_main_t * m)
{
  m->mini_connection_hash_mask = pow2_mask (m->log2_n_mini_connection_hash_elts);
  vec_validate_aligned (m->mini_connections,
			m->mini_connection_hash_mask,
			CLIB_CACHE_LINE_BYTES);

  m->established_connection_hash_mask = pow2_mask (m->log2_n_established_connection_hash_elts);
  vec_validate_aligned (m->established_connections,
			m->established_connection_hash_mask,
			CLIB_CACHE_LINE_BYTES);
}

static void
ip46_tcp_lookup_init (vlib_main_t * vm, tcp_main_t * tm, int is_ip6)
{
  ip46_tcp_main_t * m = is_ip6 ? &tm->ip6 : &tm->ip4;

  m->is_ip6 = is_ip6;

  m->log2_n_mini_connection_hash_elts = 8;
  m->log2_n_established_connection_hash_elts = 8;
  ip46_size_hash_tables (m);

  if (is_ip6)
    {
      vec_validate_aligned (tm->ip6_mini_connection_address_hash,
			    m->mini_connection_hash_mask / 4,
			    CLIB_CACHE_LINE_BYTES);
      vec_validate_aligned (tm->ip6_established_connection_address_hash,
			    m->established_connection_hash_mask / 4,
			    CLIB_CACHE_LINE_BYTES);
    }
  else
    {
      vec_validate_aligned (tm->ip4_mini_connection_address_hash,
			    m->mini_connection_hash_mask / 4,
			    CLIB_CACHE_LINE_BYTES);
      vec_validate_aligned (tm->ip4_established_connection_address_hash,
			    m->established_connection_hash_mask / 4,
			    CLIB_CACHE_LINE_BYTES);
    }
  tm->connection_hash_masks[is_ip6].as_u32[0] = m->mini_connection_hash_mask / 4;
  tm->connection_hash_masks[is_ip6].as_u32[1] = m->established_connection_hash_mask / 4;
}

static void
tcp_lookup_init (vlib_main_t * vm, tcp_main_t * tm)
{
  int is_ip6;

  /* Initialize hash seeds. */
  for (is_ip6 = 0; is_ip6 < 2; is_ip6++)
    {
      u32 * r = clib_random_buffer_get_data (&vm->random_buffer, 3 * 2 * sizeof (r[0]));
      tm->connection_hash_seeds[is_ip6][0].as_u32[0] = r[0];
      tm->connection_hash_seeds[is_ip6][0].as_u32[1] = r[1];
      tm->connection_hash_seeds[is_ip6][1].as_u32[0] = r[2];
      tm->connection_hash_seeds[is_ip6][1].as_u32[1] = r[3];
      tm->connection_hash_seeds[is_ip6][2].as_u32[0] = r[4];
      tm->connection_hash_seeds[is_ip6][2].as_u32[1] = r[5];

      ip46_tcp_lookup_init (vm, tm, is_ip6);
    }

  {
    tcp_listener_t * l;

    pool_get_aligned (tm->listener_pool, l, CLIB_CACHE_LINE_BYTES);

    /* Null listener must always have zero index. */
    ASSERT (l - tm->listener_pool == 0);

    memset (l, 0, sizeof (l[0]));

    /* No adjacencies are valid. */
    l->valid_local_adjacency_bitmap = 0;

    vec_validate_init_empty (tm->listener_index_by_dst_port,
			     (1 << 16) - 1,
			     l - tm->listener_pool);
  }

  /* Initialize disposition table. */
  {
    int i, j;
    for (i = 0; i < ARRAY_LEN (tm->disposition_by_state_and_flags); i++)
      for (j = 0; j < ARRAY_LEN (tm->disposition_by_state_and_flags[i]); j++)
	{
	  tm->disposition_by_state_and_flags[i][j].next = TCP_LOOKUP_NEXT_DROP;
	  tm->disposition_by_state_and_flags[i][j].error = TCP_ERROR_LOOKUP_DROPS;
	}

#define _(t,f,n,e)							\
do {									\
    tm->disposition_by_state_and_flags[TCP_CONNECTION_STATE_##t][f].next = (n);	\
    tm->disposition_by_state_and_flags[TCP_CONNECTION_STATE_##t][f].error = (e); \
} while (0)

    /* SYNs for new connections -> tcp-listen. */
    _ (unused, TCP_FLAG_SYN,
       TCP_LOOKUP_NEXT_LISTEN_SYN, TCP_ERROR_NONE);
    _ (listen_ack_wait, TCP_FLAG_ACK,
       TCP_LOOKUP_NEXT_LISTEN_ACK, TCP_ERROR_NONE);
    _ (established, TCP_FLAG_ACK,
       TCP_LOOKUP_NEXT_ESTABLISHED, TCP_ERROR_NONE);
    _ (established, TCP_FLAG_FIN | TCP_FLAG_ACK,
       TCP_LOOKUP_NEXT_ESTABLISHED, TCP_ERROR_NONE);

#undef _
  }

  /* IP4 packet templates. */
  {
    ip4_tcp_syn_packet_t ip4_syn, ip4_syn_ack;
    ip4_tcp_ack_packet_t ip4_ack, ip4_fin_ack, ip4_rst_ack;
    ip6_tcp_syn_packet_t ip6_syn, ip6_syn_ack;
    ip6_tcp_ack_packet_t ip6_ack, ip6_fin_ack, ip6_rst_ack;

    memset (&ip4_syn, 0, sizeof (ip4_syn));
    memset (&ip4_syn_ack, 0, sizeof (ip4_syn_ack));
    memset (&ip4_ack, 0, sizeof (ip4_ack));
    memset (&ip4_fin_ack, 0, sizeof (ip4_fin_ack));
    memset (&ip4_rst_ack, 0, sizeof (ip4_rst_ack));
    memset (&ip6_syn, 0, sizeof (ip6_syn));
    memset (&ip6_syn_ack, 0, sizeof (ip6_syn_ack));
    memset (&ip6_ack, 0, sizeof (ip6_ack));
    memset (&ip6_fin_ack, 0, sizeof (ip6_fin_ack));
    memset (&ip6_rst_ack, 0, sizeof (ip6_rst_ack));

    ip4_tcp_packet_init (&ip4_syn.ip4, sizeof (ip4_syn));
    ip4_tcp_packet_init (&ip4_syn_ack.ip4, sizeof (ip4_syn_ack));
    ip4_tcp_packet_init (&ip4_ack.ip4, sizeof (ip4_ack));
    ip4_tcp_packet_init (&ip4_fin_ack.ip4, sizeof (ip4_fin_ack));
    ip4_tcp_packet_init (&ip4_rst_ack.ip4, sizeof (ip4_rst_ack));

    ip6_tcp_packet_init (&ip6_syn.ip6, sizeof (ip6_syn));
    ip6_tcp_packet_init (&ip6_syn_ack.ip6, sizeof (ip6_syn_ack));
    ip6_tcp_packet_init (&ip6_ack.ip6, sizeof (ip6_ack));
    ip6_tcp_packet_init (&ip6_fin_ack.ip6, sizeof (ip6_fin_ack));
    ip6_tcp_packet_init (&ip6_rst_ack.ip6, sizeof (ip6_rst_ack));

    /* TCP header. */
    {
      u8 window_scale = 7;
      tcp_syn_packet_t * s = &ip4_syn.tcp;
      tcp_syn_packet_t * sa = &ip4_syn_ack.tcp;
      tcp_ack_packet_t * a = &ip4_ack.tcp;
      tcp_ack_packet_t * fa = &ip4_fin_ack.tcp;
      tcp_ack_packet_t * ra = &ip4_rst_ack.tcp;

      s->header.tcp_header_u32s_and_reserved = (sizeof (s[0]) / sizeof (u32)) << 4;
      a->header.tcp_header_u32s_and_reserved = (sizeof (a[0]) / sizeof (u32)) << 4;

      s->header.flags = TCP_FLAG_SYN;
      a->header.flags = TCP_FLAG_ACK;

      s->header.window = clib_host_to_net_u16 (32 << (10 - window_scale));
      a->header.window = s->header.window;

      s->options.mss.type = TCP_OPTION_MSS;
      s->options.mss.length = 4;

      s->options.window_scale.type = TCP_OPTION_WINDOW_SCALE;
      s->options.window_scale.length = 3;
      s->options.window_scale.value = window_scale;

      s->options.time_stamp.type = TCP_OPTION_TIME_STAMP;
      s->options.time_stamp.length = 10;

      memset (&s->options.nops, TCP_OPTION_NOP, sizeof (s->options.nops));

      /* SYN-ACK is same as SYN but with ACK flag set. */
      sa[0] = s[0];
      sa->header.flags |= TCP_FLAG_ACK;

      a->options.time_stamp.type = TCP_OPTION_TIME_STAMP;
      a->options.time_stamp.length = 10;
      memset (&a->options.nops, TCP_OPTION_NOP, sizeof (a->options.nops));

      /* {FIN,RST}-ACK are same as ACK but with {FIN,RST} flag set. */
      fa[0] = a[0];
      fa->header.flags |= TCP_FLAG_FIN;
      ra[0] = a[0];
      ra->header.flags |= TCP_FLAG_RST;

      /* IP6 TCP headers are identical. */
      ip6_syn.tcp = s[0];
      ip6_syn_ack.tcp = sa[0];
      ip6_ack.tcp = a[0];
      ip6_fin_ack.tcp = fa[0];
      ip6_rst_ack.tcp = ra[0];

      /* TCP checksums. */
      {
	ip_csum_t sum;

	sum = clib_host_to_net_u32 (sizeof (ip4_ack.tcp) + (ip4_ack.ip4.protocol << 16));
	sum = ip_incremental_checksum (sum, &ip4_ack.tcp, sizeof (ip4_ack.tcp));
	ip4_ack.tcp.header.checksum = ~ ip_csum_fold (sum);

	sum = clib_host_to_net_u32 (sizeof (ip4_fin_ack.tcp) + (ip4_fin_ack.ip4.protocol << 16));
	sum = ip_incremental_checksum (sum, &ip4_fin_ack.tcp, sizeof (ip4_fin_ack.tcp));
	ip4_fin_ack.tcp.header.checksum = ~ ip_csum_fold (sum);

	sum = clib_host_to_net_u32 (sizeof (ip4_rst_ack.tcp) + (ip4_rst_ack.ip4.protocol << 16));
	sum = ip_incremental_checksum (sum, &ip4_rst_ack.tcp, sizeof (ip4_rst_ack.tcp));
	ip4_rst_ack.tcp.header.checksum = ~ ip_csum_fold (sum);

	sum = clib_host_to_net_u32 (sizeof (ip4_syn.tcp) + (ip4_syn.ip4.protocol << 16));
	sum = ip_incremental_checksum (sum, &ip4_syn.tcp, sizeof (ip4_syn.tcp));
	ip4_syn.tcp.header.checksum = ~ ip_csum_fold (sum);

	sum = clib_host_to_net_u32 (sizeof (ip4_syn_ack.tcp) + (ip4_syn_ack.ip4.protocol << 16));
	sum = ip_incremental_checksum (sum, &ip4_syn_ack.tcp, sizeof (ip4_syn_ack.tcp));
	ip4_syn_ack.tcp.header.checksum = ~ ip_csum_fold (sum);

	sum = clib_host_to_net_u32 (sizeof (ip6_ack.tcp)) + ip6_ack.ip6.protocol;
	sum = ip_incremental_checksum (sum, &ip6_ack.tcp, sizeof (ip6_ack.tcp));
	ip6_ack.tcp.header.checksum = ~ ip_csum_fold (sum);

	sum = clib_host_to_net_u32 (sizeof (ip6_fin_ack.tcp)) + ip6_fin_ack.ip6.protocol;
	sum = ip_incremental_checksum (sum, &ip6_fin_ack.tcp, sizeof (ip6_fin_ack.tcp));
	ip6_fin_ack.tcp.header.checksum = ~ ip_csum_fold (sum);

	sum = clib_host_to_net_u32 (sizeof (ip6_rst_ack.tcp)) + ip6_rst_ack.ip6.protocol;
	sum = ip_incremental_checksum (sum, &ip6_rst_ack.tcp, sizeof (ip6_rst_ack.tcp));
	ip6_rst_ack.tcp.header.checksum = ~ ip_csum_fold (sum);

	sum = clib_host_to_net_u32 (sizeof (ip6_syn.tcp)) + ip6_syn.ip6.protocol;
	sum = ip_incremental_checksum (sum, &ip6_syn.tcp, sizeof (ip6_syn.tcp));
	ip6_syn.tcp.header.checksum = ~ ip_csum_fold (sum);

	sum = clib_host_to_net_u32 (sizeof (ip6_syn_ack.tcp)) + ip6_syn_ack.ip6.protocol;
	sum = ip_incremental_checksum (sum, &ip6_syn_ack.tcp, sizeof (ip6_syn_ack.tcp));
	ip6_syn_ack.tcp.header.checksum = ~ ip_csum_fold (sum);
      }
    }

#define _(t,x,n)						\
do {								\
  vlib_packet_template_init					\
    (vm,							\
     &tm->ip4.packet_templates[t].vlib,				\
     &x, sizeof (x),						\
     /* alloc chunk size */ VLIB_FRAME_SIZE,			\
     (n));							\
  tm->ip4.packet_templates[t].tcp_checksum_net_byte_order	\
    = x.tcp.header.checksum;					\
  tm->ip4.packet_templates[t].ip4_checksum_net_byte_order	\
    = x.ip4.checksum;						\
} while (0)

    _ (TCP_PACKET_TEMPLATE_SYN, ip4_syn, "ip4 tcp syn");
    _ (TCP_PACKET_TEMPLATE_SYN_ACK, ip4_syn_ack, "ip4 tcp syn-ack");
    _ (TCP_PACKET_TEMPLATE_ACK, ip4_ack, "ip4 tcp ack");
    _ (TCP_PACKET_TEMPLATE_FIN_ACK, ip4_fin_ack, "ip4 tcp fin-ack");
    _ (TCP_PACKET_TEMPLATE_RST_ACK, ip4_rst_ack, "ip4 tcp rst-ack");

#undef _

#define _(t,x,n)						\
do {								\
  vlib_packet_template_init					\
    (vm,							\
     &tm->ip6.packet_templates[t].vlib,				\
     &x, sizeof (x),						\
     /* alloc chunk size */ VLIB_FRAME_SIZE,			\
     (n));							\
  tm->ip6.packet_templates[t].tcp_checksum_net_byte_order	\
    = x.tcp.header.checksum;					\
  tm->ip6.packet_templates[t].ip4_checksum_net_byte_order	\
    = 0xdead;							\
} while (0)

    _ (TCP_PACKET_TEMPLATE_SYN, ip6_syn, "ip6 tcp syn");
    _ (TCP_PACKET_TEMPLATE_SYN_ACK, ip6_syn_ack, "ip6 tcp syn-ack");
    _ (TCP_PACKET_TEMPLATE_ACK, ip6_ack, "ip6 tcp ack");
    _ (TCP_PACKET_TEMPLATE_FIN_ACK, ip6_fin_ack, "ip6 tcp fin-ack");
    _ (TCP_PACKET_TEMPLATE_RST_ACK, ip6_rst_ack, "ip6 tcp rst-ack");

#undef _
  }
}

static char * tcp_error_strings[] = {
#define _(sym,string) string,
  foreach_tcp_error
#undef _
};

VLIB_REGISTER_NODE (ip4_tcp_lookup_node,static) = {
  .function = ip4_tcp_lookup,
  .name = "ip4-tcp-lookup",

  .vector_size = sizeof (u32),

  .n_next_nodes = TCP_LOOKUP_N_NEXT,
  .next_nodes = {
    [TCP_LOOKUP_NEXT_DROP] = "error-drop",
    [TCP_LOOKUP_NEXT_PUNT] = "error-punt",
    [TCP_LOOKUP_NEXT_LISTEN_SYN] = "ip4-tcp-listen",
    [TCP_LOOKUP_NEXT_LISTEN_ACK] = "ip4-tcp-establish",
    [TCP_LOOKUP_NEXT_CONNECT_SYN_ACK] = "ip4-tcp-connect",
    [TCP_LOOKUP_NEXT_ESTABLISHED] = "ip4-tcp-established",
  },

  .n_errors = TCP_N_ERROR,
  .error_strings = tcp_error_strings,
};

VLIB_REGISTER_NODE (ip6_tcp_lookup_node,static) = {
  .function = ip6_tcp_lookup,
  .name = "ip6-tcp-lookup",

  .vector_size = sizeof (u32),

  .n_next_nodes = TCP_LOOKUP_N_NEXT,
  .next_nodes = {
    [TCP_LOOKUP_NEXT_DROP] = "error-drop",
    [TCP_LOOKUP_NEXT_PUNT] = "error-punt",
    [TCP_LOOKUP_NEXT_LISTEN_SYN] = "ip6-tcp-listen",
    [TCP_LOOKUP_NEXT_LISTEN_ACK] = "ip4-tcp-establish",
    [TCP_LOOKUP_NEXT_CONNECT_SYN_ACK] = "ip6-tcp-connect",
    [TCP_LOOKUP_NEXT_ESTABLISHED] = "ip6-tcp-established",
  },

  .n_errors = TCP_N_ERROR,
  .error_strings = tcp_error_strings,
};

static_always_inline void
tcp_options_decode_for_syn (tcp_main_t * tm, tcp_mini_connection_t * m, tcp_header_t * tcp)
{
  u8 * o = (void *) (tcp + 1);
  u32 n_bytes = (tcp->tcp_header_u32s_and_reserved >> 4) * sizeof (u32);
  u8 * e = o + n_bytes;
  tcp_mini_connection_t * tmpl = &tm->option_decode_mini_connection_template;
  tcp_option_type_t t;
  u8 i, l, * p;
  u8 * option_decode[16];

  /* Initialize defaults. */
  option_decode[TCP_OPTION_MSS] = (u8 *) &tmpl->max_segment_size;
  option_decode[TCP_OPTION_WINDOW_SCALE] = (u8 *) &tmpl->window_scale;
  option_decode[TCP_OPTION_TIME_STAMP] = (u8 *) &tmpl->time_stamps.his_net_byte_order;

  if (n_bytes > 0)
    {
#define _							\
do {								\
  t = o[0];							\
  i = t >= ARRAY_LEN (option_decode) ? TCP_OPTION_END : t;	\
  option_decode[i] = o + 2;					\
  /* Skip nop; don't skip end; else length from packet. */	\
  l = t < 2 ? t : o[1];						\
  p = o + l;							\
  o = p < e ? p : o;						\
} while (0)

      _; _; _;
      /* Fast path: NOP NOP TIMESTAMP. */
      if (o >= e) goto done;
      _; _;
      if (o >= e) goto done;
      _; _; _;

#undef _

    done:;
    }

  m->max_segment_size =
    clib_net_to_host_u16 (*(u16 *) option_decode[TCP_OPTION_MSS]);
  m->window_scale = *option_decode[TCP_OPTION_WINDOW_SCALE];
  m->time_stamps.his_net_byte_order = ((u32 *) option_decode[TCP_OPTION_TIME_STAMP])[0];
}

static_always_inline u32
tcp_options_decode_for_ack (tcp_main_t * tm, tcp_header_t * tcp,
			    u32 * his_time_stamp)
{
  u8 * o = (void *) (tcp + 1);
  u32 n_bytes = (tcp->tcp_header_u32s_and_reserved >> 4) * sizeof (u32);
  u8 * e = o + n_bytes;
  tcp_option_type_t t;
  u8 i, l, * p;
  u8 * option_decode[16];
  u32 default_time_stamps[2];

  /* Initialize defaults. */
  default_time_stamps[0] = default_time_stamps[1] = 0;
  option_decode[TCP_OPTION_TIME_STAMP] = (u8 *) &default_time_stamps;

  if (n_bytes > 0)
    {
#define _							\
do {								\
  t = o[0];							\
  i = t >= ARRAY_LEN (option_decode) ? TCP_OPTION_END : t;	\
  option_decode[i] = o + 2;					\
  /* Skip nop; don't skip end; else length from packet. */	\
  l = t < 2 ? t : o[1];						\
  p = o + l;							\
  o = p < e ? p : o;						\
} while (0)

      _; _; _;
      /* Fast path: NOP NOP TIMESTAMP. */
      if (o >= e) goto done;
      _; _;
      if (o >= e) goto done;
      _; _; _;
#undef _

    done:;
    }

  if (his_time_stamp)
    his_time_stamp[0] = ((u32 *) option_decode[TCP_OPTION_TIME_STAMP])[0];

  return clib_net_to_host_u32 (((u32 *) option_decode[TCP_OPTION_TIME_STAMP])[1]);
}

static void
tcp_options_decode_init (tcp_main_t * tm)
{
  tcp_mini_connection_t * m = &tm->option_decode_mini_connection_template;

  memset (m, 0, sizeof (m[0]));
  m->max_segment_size = clib_host_to_net_u16 (576 - 40);
  m->window_scale = 0;
  m->time_stamps.his_net_byte_order = 0;
}

/* Initialize target buffer as "related" to given buffer. */
always_inline void
vlib_buffer_copy_shared_fields (vlib_main_t * vm, vlib_buffer_t * b, u32 bi_target)
{
  vlib_buffer_t * b_target = vlib_get_buffer (vm, bi_target);
  vnet_buffer (b_target)->sw_if_index[VLIB_RX] = vnet_buffer (b)->sw_if_index[VLIB_RX];
  b_target->trace_index = b->trace_index;
  b_target->flags |= b->flags & VLIB_BUFFER_IS_TRACED;
}

typedef enum {
  TCP_LISTEN_NEXT_DROP,
  TCP_LISTEN_NEXT_REPLY,
  TCP_LISTEN_N_NEXT,
} tcp_listen_next_t;

static_always_inline uword
ip46_tcp_listen (vlib_main_t * vm,
		 vlib_node_runtime_t * node,
		 vlib_frame_t * frame,
		 uword is_ip6)
{
  tcp_main_t * tm = &tcp_main;
  ip46_tcp_main_t * tm46 = is_ip6 ? &tm->ip6 : &tm->ip4;
  uword n_packets = frame->n_vectors;
  u32 * from, * to_reply, * to_drop, * random_ack_numbers;
  u32 n_left_from, n_left_to_reply, n_left_to_drop, mini_now, timestamp_now;
  u16 * fid, * fragment_ids;
  vlib_node_runtime_t * error_node;

  error_node = vlib_node_get_runtime
    (vm, is_ip6 ? ip6_tcp_lookup_node.index : ip4_tcp_lookup_node.index);

  from = vlib_frame_vector_args (frame);
  n_left_from = n_packets;
  mini_now = tcp_time_now (tm, TCP_TIMER_mini_connection);
  timestamp_now = tcp_time_now (tm, TCP_TIMER_timestamp);
  
  random_ack_numbers = clib_random_buffer_get_data (&vm->random_buffer,
						    n_packets * sizeof (random_ack_numbers[0]));
  /* Get random fragment IDs for replies. */
  fid = fragment_ids = clib_random_buffer_get_data (&vm->random_buffer,
						    n_packets * sizeof (fragment_ids[0]));

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, TCP_LISTEN_NEXT_REPLY,
			   to_reply, n_left_to_reply);
      vlib_get_next_frame (vm, node, TCP_LISTEN_NEXT_DROP,
			   to_drop, n_left_to_drop);

      while (n_left_from > 0 && n_left_to_reply > 0 && n_left_to_drop > 0)
	{
	  vlib_buffer_t * p0;
	  ip6_header_t * ip60;
	  ip4_header_t * ip40;
	  tcp_header_t * tcp0;
	  tcp_mini_connection_t * min0;
	  tcp_syn_packet_t * tcp_reply0;
	  ip_csum_t tcp_sum0;
	  u32 bi0, bi_reply0, imin0, my_seq_net0, his_seq_host0, his_seq_net0;
	  u8 i0;
      
	  bi0 = to_drop[0] = from[0];

	  from += 1;
	  n_left_from -= 1;
	  to_drop += 1;
	  n_left_to_drop -= 1;
      
	  p0 = vlib_get_buffer (vm, bi0);

	  p0->error = error_node->errors[TCP_ERROR_LISTEN_RESPONSES];

	  imin0 = vnet_buffer (p0)->ip.tcp.mini_connection_index;
	  i0 = imin0 % 4;

	  if (is_ip6)
	    {
	      ip6_tcp_udp_address_x4_and_timestamps_t * mina0;

	      ip60 = vlib_buffer_get_current (p0);
	      tcp0 = ip6_next_header (ip60);

	      mina0 = vec_elt_at_index (tm->ip6_mini_connection_address_hash, imin0 / 4);

	      ip6_tcp_udp_address_x4_set_from_headers (&mina0->address_x4,
						       ip60, tcp0, i0);
	      mina0->time_stamps[i0] = mini_now;
	    }
	  else
	    {
	      ip4_tcp_udp_address_x4_and_timestamps_t * mina0;

	      ip40 = vlib_buffer_get_current (p0);
	      tcp0 = ip4_next_header (ip40);

	      mina0 = vec_elt_at_index (tm->ip4_mini_connection_address_hash, imin0 / 4);

	      ip4_tcp_udp_address_x4_set_from_headers (&mina0->address_x4,
						       ip40, tcp0, i0);
	      mina0->time_stamps[i0] = mini_now;
	    }

	  min0 = vec_elt_at_index (tm46->mini_connections, imin0);

	  min0->state = TCP_CONNECTION_STATE_listen_ack_wait;
	  min0->time_stamps.ours_host_byte_order = timestamp_now;
	  tcp_options_decode_for_syn (tm, min0, tcp0);

	  my_seq_net0 = *random_ack_numbers++;
	  his_seq_host0 = 1 + clib_net_to_host_u32 (tcp0->seq_number);

	  min0->sequence_numbers.ours = 1 + clib_net_to_host_u32 (my_seq_net0);
	  min0->sequence_numbers.his = his_seq_host0;

	  if (is_ip6)
	    {
	      ip6_tcp_syn_packet_t * r0;
	      uword tmp0, i;

	      r0 = vlib_packet_template_get_packet
		(vm,
		 &tm->ip6.packet_templates[TCP_PACKET_TEMPLATE_SYN_ACK].vlib,
		 &bi_reply0);
	      tcp_reply0 = &r0->tcp;

	      tcp_sum0 = (tm->ip6.packet_templates[TCP_PACKET_TEMPLATE_SYN_ACK]
			  .tcp_checksum_net_byte_order);

	      for (i = 0; i < ARRAY_LEN (ip60->dst_address.as_uword); i++)
		{
		  tmp0 = r0->ip6.src_address.as_uword[i] = ip60->dst_address.as_uword[i];
		  tcp_sum0 = ip_csum_add_even (tcp_sum0, tmp0);

		  tmp0 = r0->ip6.dst_address.as_uword[i] = ip60->src_address.as_uword[i];
		  tcp_sum0 = ip_csum_add_even (tcp_sum0, tmp0);
		}
	    }
	  else
	    {
	      ip4_tcp_syn_packet_t * r0;
	      ip_csum_t ip_sum0;
	      u32 src0, dst0;

	      r0 = vlib_packet_template_get_packet
		(vm,
		 &tm->ip4.packet_templates[TCP_PACKET_TEMPLATE_SYN_ACK].vlib,
		 &bi_reply0);
	      tcp_reply0 = &r0->tcp;

	      tcp_sum0 = (tm->ip4.packet_templates[TCP_PACKET_TEMPLATE_SYN_ACK]
			  .tcp_checksum_net_byte_order);
	      ip_sum0 = (tm->ip4.packet_templates[TCP_PACKET_TEMPLATE_SYN_ACK]
			 .ip4_checksum_net_byte_order);

	      src0 = r0->ip4.src_address.as_u32 = ip40->dst_address.as_u32;
	      dst0 = r0->ip4.dst_address.as_u32 = ip40->src_address.as_u32;

	      ip_sum0 = ip_csum_add_even (ip_sum0, src0);
	      tcp_sum0 = ip_csum_add_even (tcp_sum0, src0);

	      ip_sum0 = ip_csum_add_even (ip_sum0, dst0);
	      tcp_sum0 = ip_csum_add_even (tcp_sum0, dst0);

	      r0->ip4.checksum = ip_csum_fold (ip_sum0);

	      ASSERT (r0->ip4.checksum == ip4_header_checksum (&r0->ip4));
	    }

	  tcp_reply0->header.ports.src = tcp0->ports.dst;
	  tcp_reply0->header.ports.dst = tcp0->ports.src;
	  tcp_sum0 = ip_csum_add_even (tcp_sum0, tcp_reply0->header.ports.src_and_dst);

	  tcp_reply0->header.seq_number = my_seq_net0;
	  tcp_sum0 = ip_csum_add_even (tcp_sum0, my_seq_net0);

	  his_seq_net0 = clib_host_to_net_u32 (his_seq_host0);
	  tcp_reply0->header.ack_number = his_seq_net0;
	  tcp_sum0 = ip_csum_add_even (tcp_sum0, his_seq_net0);

	  {
	    ip_adjacency_t * adj0 = ip_get_adjacency (&ip4_main.lookup_main, vnet_buffer (p0)->ip.adj_index[VLIB_RX]);
	    u16 my_mss =
	      (adj0->rewrite_header.max_l3_packet_bytes
	       - (is_ip6 ? sizeof (ip60[0]) : sizeof (ip40[0]))
	       - sizeof (tcp0[0]));

	    my_mss = clib_min (my_mss, min0->max_segment_size);
	    min0->max_segment_size = my_mss;

	    tcp_reply0->options.mss.value = clib_host_to_net_u16 (my_mss);
	    tcp_sum0 = ip_csum_add_even (tcp_sum0, tcp_reply0->options.mss.value);
	  }

	  tcp_reply0->options.time_stamp.my_time_stamp = clib_host_to_net_u32 (timestamp_now);
	  tcp_sum0 = ip_csum_add_even (tcp_sum0, tcp_reply0->options.time_stamp.my_time_stamp);

	  tcp_reply0->options.time_stamp.his_time_stamp = min0->time_stamps.his_net_byte_order;
	  tcp_sum0 = ip_csum_add_even (tcp_sum0, tcp_reply0->options.time_stamp.his_time_stamp);

	  tcp_reply0->header.checksum = ip_csum_fold (tcp_sum0);

	  vlib_buffer_copy_shared_fields (vm, p0, bi_reply0);

	  to_reply[0] = bi_reply0;
	  n_left_to_reply -= 1;
	  to_reply += 1;
	}

      vlib_put_next_frame (vm, node, TCP_LISTEN_NEXT_REPLY, n_left_to_reply);
      vlib_put_next_frame (vm, node, TCP_LISTEN_NEXT_DROP, n_left_to_drop);
    }

  if (node->flags & VLIB_NODE_FLAG_TRACE)
    /* FIXME */ ;

  return frame->n_vectors;
}

static uword
ip4_tcp_listen (vlib_main_t * vm,
		vlib_node_runtime_t * node,
		vlib_frame_t * frame)
{ return ip46_tcp_listen (vm, node, frame, /* is_ip6 */ 0); }

static uword
ip6_tcp_listen (vlib_main_t * vm,
		vlib_node_runtime_t * node,
		vlib_frame_t * frame)
{ return ip46_tcp_listen (vm, node, frame, /* is_ip6 */ 1); }

VLIB_REGISTER_NODE (ip4_tcp_listen_node,static) = {
  .function = ip4_tcp_listen,
  .name = "ip4-tcp-listen",

  .vector_size = sizeof (u32),

  .n_next_nodes = TCP_LISTEN_N_NEXT,
  .next_nodes = {
    [TCP_LISTEN_NEXT_DROP] = "error-drop",
    [TCP_LISTEN_NEXT_REPLY] = CLIB_DEBUG > 0 ? "ip4-input" : "ip4-lookup",
  },
};

VLIB_REGISTER_NODE (ip6_tcp_listen_node,static) = {
  .function = ip6_tcp_listen,
  .name = "ip6-tcp-listen",

  .vector_size = sizeof (u32),

  .n_next_nodes = TCP_LISTEN_N_NEXT,
  .next_nodes = {
    [TCP_LISTEN_NEXT_DROP] = "error-drop",
    [TCP_LISTEN_NEXT_REPLY] = CLIB_DEBUG > 0 ? "ip6-input" : "ip6-lookup",
  },
};

typedef enum {
  TCP_CONNECT_NEXT_DROP,
  TCP_CONNECT_NEXT_REPLY,
  TCP_CONNECT_N_NEXT,
} tcp_connect_next_t;

static_always_inline uword
ip46_tcp_connect (vlib_main_t * vm,
		 vlib_node_runtime_t * node,
		 vlib_frame_t * frame,
		 uword is_ip6)
{
  tcp_main_t * tm = &tcp_main;
  ip46_tcp_main_t * tm46 = is_ip6 ? &tm->ip6 : &tm->ip4;
  uword n_packets = frame->n_vectors;
  u32 * from, * to_next;
  u32 n_left_from, n_left_to_next, next;
  vlib_node_runtime_t * error_node;

  /* FIXME */
  clib_warning ("%p", tm46);

  error_node = vlib_node_get_runtime
    (vm, is_ip6 ? ip6_tcp_lookup_node.index : ip4_tcp_lookup_node.index);

  from = vlib_frame_vector_args (frame);
  n_left_from = n_packets;
  next = node->cached_next_index;
  
  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  vlib_buffer_t * p0;
	  ip6_header_t * ip60;
	  ip4_header_t * ip40;
	  tcp_header_t * tcp0;
	  u32 bi0;
	  u8 error0, next0;
      
	  bi0 = to_next[0] = from[0];

	  from += 1;
	  n_left_from -= 1;
	  to_next += 1;
	  n_left_to_next -= 1;
      
	  p0 = vlib_get_buffer (vm, bi0);

	  if (is_ip6)
	    {
	      ip60 = vlib_buffer_get_current (p0);
	      tcp0 = ip6_next_header (ip60);
	    }
	  else
	    {
	      ip40 = vlib_buffer_get_current (p0);
	      tcp0 = ip4_next_header (ip40);
	    }

	  ASSERT (0);

	  error0 = next0 = 0;
	  p0->error = error_node->errors[error0];

	  if (PREDICT_FALSE (next0 != next))
	    {
	      to_next -= 1;
	      n_left_to_next += 1;

	      vlib_put_next_frame (vm, node, next, n_left_to_next);

	      next = next0;
	      vlib_get_next_frame (vm, node, next, to_next, n_left_to_next);
	      to_next[0] = bi0;
	      to_next += 1;
	      n_left_to_next -= 1;
	    }
	}
  
      vlib_put_next_frame (vm, node, next, n_left_to_next);
    }

  if (node->flags & VLIB_NODE_FLAG_TRACE)
    /* FIXME */ ;

  return frame->n_vectors;
}

static uword
ip4_tcp_connect (vlib_main_t * vm,
		vlib_node_runtime_t * node,
		vlib_frame_t * frame)
{ return ip46_tcp_connect (vm, node, frame, /* is_ip6 */ 0); }

static uword
ip6_tcp_connect (vlib_main_t * vm,
		vlib_node_runtime_t * node,
		vlib_frame_t * frame)
{ return ip46_tcp_connect (vm, node, frame, /* is_ip6 */ 1); }

VLIB_REGISTER_NODE (ip4_tcp_connect_node,static) = {
  .function = ip4_tcp_connect,
  .name = "ip4-tcp-connect",

  .vector_size = sizeof (u32),

  .n_next_nodes = TCP_CONNECT_N_NEXT,
  .next_nodes = {
    [TCP_CONNECT_NEXT_DROP] = "error-drop",
    [TCP_CONNECT_NEXT_REPLY] = CLIB_DEBUG > 0 ? "ip4-input" : "ip4-lookup",
  },
};

VLIB_REGISTER_NODE (ip6_tcp_connect_node,static) = {
  .function = ip6_tcp_connect,
  .name = "ip6-tcp-connect",

  .vector_size = sizeof (u32),

  .n_next_nodes = TCP_CONNECT_N_NEXT,
  .next_nodes = {
    [TCP_CONNECT_NEXT_DROP] = "error-drop",
    [TCP_CONNECT_NEXT_REPLY] = CLIB_DEBUG > 0 ? "ip6-input" : "ip6-lookup",
  },
};

typedef enum {
  TCP_ESTABLISH_NEXT_DROP,
  TCP_ESTABLISH_NEXT_ESTABLISHED,
  TCP_ESTABLISH_N_NEXT,
} tcp_establish_next_t;

static_always_inline uword
ip46_tcp_establish (vlib_main_t * vm,
		    vlib_node_runtime_t * node,
		    vlib_frame_t * frame,
		    uword is_ip6)
{
  tcp_main_t * tm = &tcp_main;
  ip46_tcp_main_t * tm46 = is_ip6 ? &tm->ip6 : &tm->ip4;
  uword n_packets = frame->n_vectors;
  u32 * from, * to_next;
  u32 n_left_from, n_left_to_next, next, mini_long_long_ago, timestamp_now;
  vlib_node_runtime_t * error_node;

  error_node = vlib_node_get_runtime
    (vm, is_ip6 ? ip6_tcp_lookup_node.index : ip4_tcp_lookup_node.index);

  from = vlib_frame_vector_args (frame);
  n_left_from = n_packets;
  next = node->cached_next_index;
  mini_long_long_ago =
    (tcp_time_now (tm, TCP_TIMER_mini_connection)
     + (1 << (BITS (mini_long_long_ago) - 1)));
  timestamp_now = tcp_time_now (tm, TCP_TIMER_timestamp);
  
  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  vlib_buffer_t * p0;
	  ip6_header_t * ip60;
	  ip4_header_t * ip40;
	  tcp_header_t * tcp0;
	  tcp_mini_connection_t * min0;
	  tcp_connection_t * est0;
	  tcp_listener_t * l0;
	  u32 bi0, imin0, iest0;
	  u8 error0, next0, i0, e0;
      
	  bi0 = to_next[0] = from[0];

	  from += 1;
	  n_left_from -= 1;
	  to_next += 1;
	  n_left_to_next -= 1;
      
	  p0 = vlib_get_buffer (vm, bi0);

	  imin0 = vnet_buffer (p0)->ip.tcp.mini_connection_index;
	  iest0 = vnet_buffer (p0)->ip.tcp.established_connection_index;

	  i0 = imin0 % 4;
	  e0 = iest0 % 4;

	  min0 = vec_elt_at_index (tm46->mini_connections, imin0);
	  if (PREDICT_FALSE (min0->state == TCP_CONNECTION_STATE_unused))
	    goto already_established0;
	  min0->state = TCP_CONNECTION_STATE_unused;

	  if (is_ip6)
	    {
	      ip60 = vlib_buffer_get_current (p0);
	      tcp0 = ip6_next_header (ip60);
	    }
	  else
	    {
	      ip40 = vlib_buffer_get_current (p0);
	      tcp0 = ip4_next_header (ip40);
	    }

	  if (PREDICT_FALSE (clib_net_to_host_u32 (tcp0->seq_number)
			     != min0->sequence_numbers.his))
	    goto unexpected_seq_number0;
	  if (PREDICT_FALSE (clib_net_to_host_u32 (tcp0->ack_number)
			     != min0->sequence_numbers.ours))
	    goto unexpected_ack_number0;

	  if (is_ip6)
	    {
	      ip6_tcp_udp_address_x4_and_timestamps_t * mina0;
	      ip6_tcp_udp_address_x4_t * esta0;

	      mina0 = vec_elt_at_index (tm->ip6_mini_connection_address_hash, imin0 / 4);
	      esta0 = vec_elt_at_index (tm->ip6_established_connection_address_hash, iest0 / 4);

	      ip6_tcp_udp_address_x4_copy_and_invalidate (esta0, &mina0->address_x4, e0, i0);

	      mina0->time_stamps[i0] = mini_long_long_ago;
	    }
	  else
	    {
	      ip4_tcp_udp_address_x4_and_timestamps_t * mina0;
	      ip4_tcp_udp_address_x4_t * esta0;

	      mina0 = vec_elt_at_index (tm->ip4_mini_connection_address_hash, imin0 / 4);
	      esta0 = vec_elt_at_index (tm->ip4_established_connection_address_hash, iest0 / 4);

	      ip4_tcp_udp_address_x4_copy_and_invalidate (esta0, &mina0->address_x4, e0, i0);

	      mina0->time_stamps[i0] = mini_long_long_ago;
	    }

	  est0 = vec_elt_at_index (tm46->established_connections, iest0);

	  est0->sequence_numbers = min0->sequence_numbers;
	  est0->max_segment_size = (min0->max_segment_size
				    - STRUCT_SIZE_OF (tcp_ack_packet_t, options));
	  est0->his_window_scale = min0->window_scale;
	  est0->his_window = clib_net_to_host_u16 (tcp0->window);
	  est0->time_stamps.ours_host_byte_order = min0->time_stamps.ours_host_byte_order;

	  /* Compute first measurement of round trip time. */
	  {
	    u32 t = tcp_options_decode_for_ack (tm, tcp0, &est0->time_stamps.his_net_byte_order);
	    f64 dt = (timestamp_now - t) * tm->secs_per_tick[TCP_TIMER_timestamp];
	    est0->round_trip_time_stats.sum = dt;
	    est0->round_trip_time_stats.sum2 = dt*dt;
	    est0->round_trip_time_stats.count = 1;

	    {
	      ELOG_TYPE_DECLARE (e) = {
		.format = "establish ack rtt: %.4e",
		.format_args = "f8",
	      };
	      struct { f64 dt; } * ed;
	      ed = ELOG_DATA (&vm->elog_main, e);
	      ed->dt = dt;
	    }
	  }

	  est0->my_window_scale = 7;
	  est0->my_window = 256;

	  l0 = pool_elt_at_index (tm->listener_pool, vnet_buffer (p0)->ip.tcp.listener_index);
	  vec_add1 (l0->event_connections[is_ip6], tcp_connection_handle_set (iest0, is_ip6));

	  next0 = TCP_ESTABLISH_NEXT_DROP;
	  error0 = TCP_ERROR_LISTENS_ESTABLISHED;

	enqueue0:
	  p0->error = error_node->errors[error0];
	  if (PREDICT_FALSE (next0 != next))
	    {
	      to_next -= 1;
	      n_left_to_next += 1;

	      vlib_put_next_frame (vm, node, next, n_left_to_next);

	      next = next0;
	      vlib_get_next_frame (vm, node, next, to_next, n_left_to_next);
	      to_next[0] = bi0;
	      to_next += 1;
	      n_left_to_next -= 1;
	    }
	  continue;

	already_established0:
	  next0 = TCP_ESTABLISH_NEXT_ESTABLISHED;
	  error0 = TCP_ERROR_NONE;
	  goto enqueue0;

	unexpected_seq_number0:
	  next0 = TCP_ESTABLISH_NEXT_DROP;
	  error0 = TCP_ERROR_UNEXPECTED_SEQ_NUMBER;
	  goto enqueue0;

	unexpected_ack_number0:
	  next0 = TCP_ESTABLISH_NEXT_DROP;
	  error0 = TCP_ERROR_UNEXPECTED_ACK_NUMBER;
	  goto enqueue0;
	}
  
      vlib_put_next_frame (vm, node, next, n_left_to_next);
    }

  if (node->flags & VLIB_NODE_FLAG_TRACE)
    /* FIXME */ ;

  /* Inform listeners of new connections. */
  {
    tcp_listener_t * l;
    uword n;
    pool_foreach (l, tm->listener_pool, ({
      if ((n = vec_len (l->event_connections[is_ip6])) > 0)
	{
	  if (l->event_function)
	    l->event_function (l->event_connections[is_ip6],
			       TCP_EVENT_connection_established);
	  if (tm->n_established_connections[is_ip6] == 0)
	    vlib_node_set_state (vm, tm46->output_node_index, VLIB_NODE_STATE_POLLING);
	  tm->n_established_connections[is_ip6] += n;
	  _vec_len (l->event_connections[is_ip6]) = 0;
	}
    }));
  }

  return frame->n_vectors;
}

static uword
ip4_tcp_establish (vlib_main_t * vm,
		vlib_node_runtime_t * node,
		vlib_frame_t * frame)
{ return ip46_tcp_establish (vm, node, frame, /* is_ip6 */ 0); }

static uword
ip6_tcp_establish (vlib_main_t * vm,
		vlib_node_runtime_t * node,
		vlib_frame_t * frame)
{ return ip46_tcp_establish (vm, node, frame, /* is_ip6 */ 1); }

VLIB_REGISTER_NODE (ip4_tcp_establish_node,static) = {
  .function = ip4_tcp_establish,
  .name = "ip4-tcp-establish",

  .vector_size = sizeof (u32),

  .n_next_nodes = TCP_ESTABLISH_N_NEXT,
  .next_nodes = {
    [TCP_ESTABLISH_NEXT_DROP] = "error-drop",
    [TCP_ESTABLISH_NEXT_ESTABLISHED] = "ip4-tcp-established",
  },
};

VLIB_REGISTER_NODE (ip6_tcp_establish_node,static) = {
  .function = ip6_tcp_establish,
  .name = "ip6-tcp-establish",

  .vector_size = sizeof (u32),

  .n_next_nodes = TCP_ESTABLISH_N_NEXT,
  .next_nodes = {
    [TCP_ESTABLISH_NEXT_DROP] = "error-drop",
    [TCP_ESTABLISH_NEXT_ESTABLISHED] = "ip6-tcp-established",
  },
};

static_always_inline void
tcp_free_connection_x1 (vlib_main_t * vm, tcp_main_t * tm,
			tcp_ip_4_or_6_t is_ip6,
			u32 iest0)
{
  ip46_tcp_main_t * tm46 = is_ip6 ? &tm->ip6 : &tm->ip4;
  tcp_connection_t * est0;
  u32 iest_div0, iest_mod0;
  
  iest_div0 = iest0 / 4;
  iest_mod0 = iest0 % 4;

  if (is_ip6)
    {
      ip6_tcp_udp_address_x4_t * esta0;
      esta0 = vec_elt_at_index (tm->ip6_established_connection_address_hash, iest_div0);
      ip6_tcp_udp_address_x4_invalidate (esta0, iest_mod0);
    }
  else
    {
      ip4_tcp_udp_address_x4_t * esta0;
      esta0 = vec_elt_at_index (tm->ip4_established_connection_address_hash, iest_div0);
      ip4_tcp_udp_address_x4_invalidate (esta0, iest_mod0);
    }

  est0 = vec_elt_at_index (tm46->established_connections, iest0);
}

static_always_inline void
tcp_free_connection_x2 (vlib_main_t * vm, tcp_main_t * tm,
			tcp_ip_4_or_6_t is_ip6,
			u32 iest0, u32 iest1)
{
  tcp_free_connection_x1 (vm, tm, is_ip6, iest0);
  tcp_free_connection_x1 (vm, tm, is_ip6, iest1);
}

static_always_inline uword
ip46_tcp_output (vlib_main_t * vm,
		 vlib_node_runtime_t * node,
		 vlib_frame_t * frame,
		 tcp_ip_4_or_6_t is_ip6)
{
  tcp_main_t * tm = &tcp_main;
  ip46_tcp_main_t * tm46 = is_ip6 ? &tm->ip6 : &tm->ip4;
  u32 * cis, * to_next, n_left_to_next, n_connections_left;
  u32 timestamp_now_host_byte_order, timestamp_now_net_byte_order;
  vlib_node_runtime_t * error_node;
  const u32 next = 0;
  uword n_acks;

  /* Inform listeners of new connections. */
  {
    tcp_listener_t * l;
    pool_foreach (l, tm->listener_pool, ({
      if (vec_len (l->eof_connections) > 0)
	{
	  if (l->event_function)
	    l->event_function (l->eof_connections[is_ip6], TCP_EVENT_fin_received);
	  else
	    {
	      uword i;
	      for (i = 0; i < vec_len (l->eof_connections[is_ip6]); i++)
		{
		  tcp_connection_t * c = tcp_get_connection (l->eof_connections[is_ip6][i]);
		  c->flags |= TCP_CONNECTION_FLAG_application_requested_close;
		}
	    }
	  _vec_len (l->eof_connections[is_ip6]) = 0;
	}

      if (vec_len (l->close_connections[is_ip6]) > 0)
	{
	  uword n_left;
	  u32 * cis;

	  if (l->event_function)
	    l->event_function (l->close_connections[is_ip6], TCP_EVENT_connection_closed);

	  cis = l->close_connections[is_ip6];
	  n_left = vec_len (cis);
	  ASSERT (tm->n_established_connections[is_ip6] >= n_left);
	  tm->n_established_connections[is_ip6] -= n_left;
	  if (tm->n_established_connections[is_ip6] == 0)
	    vlib_node_set_state (vm, tm46->output_node_index, VLIB_NODE_STATE_DISABLED);
	  while (n_left >= 2)
	    {
	      tcp_free_connection_x2 (vm, tm, is_ip6, cis[0], cis[1]);
	      n_left -= 2;
	      cis += 2;
	    }

	  while (n_left > 0)
	    {
	      tcp_free_connection_x1 (vm, tm, is_ip6, cis[0]);
	      n_left -= 1;
	      cis += 1;
	    }

	  _vec_len (l->close_connections[is_ip6]) = 0;
	}
    }));
  }

  n_acks = 0;
  cis = tm46->connections_pending_acks;
  n_connections_left = vec_len (cis);
  if (n_connections_left == 0)
    return n_acks;
  _vec_len (tm46->connections_pending_acks) = 0;
  error_node = vlib_node_get_runtime
    (vm, is_ip6 ? ip6_tcp_lookup_node.index : ip4_tcp_lookup_node.index);

  timestamp_now_host_byte_order = tcp_time_now (tm, TCP_TIMER_timestamp);
  timestamp_now_net_byte_order = clib_host_to_net_u32 (timestamp_now_host_byte_order);

  while (n_connections_left > 0)
    {
      vlib_get_next_frame (vm, node, next, to_next, n_left_to_next);

      while (n_connections_left > 0 && n_left_to_next > 0)
	{
	  tcp_connection_t * est0;
	  tcp_ack_packet_t * tcp0;
	  tcp_udp_ports_t * ports0;
	  ip_csum_t tcp_sum0;
	  tcp_packet_template_type_t template_type0;
	  u32 bi0, iest0, iest_div0, iest_mod0, my_seq_net0, his_seq_net0;
	  u8 is_fin0;

	  iest0 = cis[0];
	  cis += 1;
	  iest_div0 = iest0 / 4;
	  iest_mod0 = iest0 % 4;
	  est0 = vec_elt_at_index (tm46->established_connections, iest0);

	  /* Send a FIN along with our ACK if application closed connection. */
	  {
	    u8 is_closed0, fin_sent0;

	    is_closed0 = (est0->flags & TCP_CONNECTION_FLAG_application_requested_close) != 0;
	    fin_sent0 = (est0->flags & TCP_CONNECTION_FLAG_fin_sent) != 0;

	    is_fin0 = is_closed0 && ! fin_sent0;
	    template_type0 = 
	      (is_fin0
	       ? TCP_PACKET_TEMPLATE_FIN_ACK
	       : TCP_PACKET_TEMPLATE_ACK);
	    est0->flags |= is_closed0 << LOG2_TCP_CONNECTION_FLAG_fin_sent;
	  }

	  if (is_ip6)
	    {
	      ip6_tcp_ack_packet_t * r0;
	      ip6_tcp_udp_address_x4_t * esta0;
	      uword tmp0, i;

	      esta0 = vec_elt_at_index (tm->ip6_established_connection_address_hash, iest_div0);
	      r0 = vlib_packet_template_get_packet
		(vm, &tm->ip6.packet_templates[template_type0].vlib, &bi0);
	      tcp0 = &r0->tcp;

	      tcp_sum0 = (tm->ip6.packet_templates[template_type0]
			  .tcp_checksum_net_byte_order);

	      for (i = 0; i < ARRAY_LEN (r0->ip6.src_address.as_u32); i++)
		{
		  tmp0 = r0->ip6.src_address.as_u32[i] = esta0->dst.as_u32[i][iest_mod0];
		  tcp_sum0 = ip_csum_add_even (tcp_sum0, tmp0);

		  tmp0 = r0->ip6.dst_address.as_u32[i] = esta0->src.as_u32[i][iest_mod0];
		  tcp_sum0 = ip_csum_add_even (tcp_sum0, tmp0);
		}

	      ports0 = &esta0->ports.as_ports[iest_mod0];
	    }
	  else
	    {
	      ip4_tcp_ack_packet_t * r0;
	      ip4_tcp_udp_address_x4_t * esta0;
	      ip_csum_t ip_sum0;
	      u32 src0, dst0;

	      esta0 = vec_elt_at_index (tm->ip4_established_connection_address_hash, iest_div0);
	      r0 = vlib_packet_template_get_packet
		(vm, &tm->ip4.packet_templates[template_type0].vlib, &bi0);
	      tcp0 = &r0->tcp;

	      ip_sum0 = (tm->ip4.packet_templates[template_type0]
			  .ip4_checksum_net_byte_order);
	      tcp_sum0 = (tm->ip4.packet_templates[template_type0]
			  .tcp_checksum_net_byte_order);

	      src0 = r0->ip4.src_address.as_u32 = esta0->dst.as_ip4_address[iest_mod0].as_u32;
	      dst0 = r0->ip4.dst_address.as_u32 = esta0->src.as_ip4_address[iest_mod0].as_u32;

	      ip_sum0 = ip_csum_add_even (ip_sum0, src0);
	      tcp_sum0 = ip_csum_add_even (tcp_sum0, src0);

	      ip_sum0 = ip_csum_add_even (ip_sum0, dst0);
	      tcp_sum0 = ip_csum_add_even (tcp_sum0, dst0);

	      r0->ip4.checksum = ip_csum_fold (ip_sum0);

	      ASSERT (r0->ip4.checksum == ip4_header_checksum (&r0->ip4));
	      ports0 = &esta0->ports.as_ports[iest_mod0];
	    }

	  tcp_sum0 = ip_csum_add_even (tcp_sum0, ports0->as_u32);
	  tcp0->header.ports.src = ports0->dst;
	  tcp0->header.ports.dst = ports0->src;

	  my_seq_net0 = clib_host_to_net_u32 (est0->sequence_numbers.ours);
	  his_seq_net0 = clib_host_to_net_u32 (est0->sequence_numbers.his);

	  /* FIN accounts for 1 sequence number. */
	  est0->sequence_numbers.ours += is_fin0;

	  tcp0->header.seq_number = my_seq_net0;
	  tcp_sum0 = ip_csum_add_even (tcp_sum0, my_seq_net0);

	  tcp0->header.ack_number = his_seq_net0;
	  tcp_sum0 = ip_csum_add_even (tcp_sum0, his_seq_net0);

	  est0->time_stamps.ours_host_byte_order = timestamp_now_host_byte_order;
	  tcp0->options.time_stamp.my_time_stamp = timestamp_now_net_byte_order;
	  tcp_sum0 = ip_csum_add_even (tcp_sum0, timestamp_now_net_byte_order);

	  tcp0->options.time_stamp.his_time_stamp = est0->time_stamps.his_net_byte_order;
	  tcp_sum0 = ip_csum_add_even (tcp_sum0, est0->time_stamps.his_net_byte_order);

	  tcp0->header.checksum = ip_csum_fold (tcp_sum0);

	  est0->flags &= ~TCP_CONNECTION_FLAG_ack_pending;

	  to_next[0] = bi0;
	  to_next += 1;
	  n_left_to_next -= 1;
	  n_connections_left -= 1;
	  n_acks += 1;
	}

      vlib_put_next_frame (vm, node, next, n_left_to_next);
    }

  vlib_error_count (vm, error_node->node_index, TCP_ERROR_ACKS_SENT, n_acks);

  return n_acks;
}

static uword
ip4_tcp_output (vlib_main_t * vm,
		vlib_node_runtime_t * node,
		vlib_frame_t * frame)
{ return ip46_tcp_output (vm, node, frame, /* is_ip6 */ 0); }

static uword
ip6_tcp_output (vlib_main_t * vm,
		vlib_node_runtime_t * node,
		vlib_frame_t * frame)
{ return ip46_tcp_output (vm, node, frame, /* is_ip6 */ 1); }

VLIB_REGISTER_NODE (ip4_tcp_output_node,static) = {
  .function = ip4_tcp_output,
  .name = "ip4-tcp-output",
  .state = VLIB_NODE_STATE_DISABLED,
  .type = VLIB_NODE_TYPE_INPUT,

  .vector_size = sizeof (u32),

  .n_next_nodes = 1,
  .next_nodes = {
    [0] = CLIB_DEBUG > 0 ? "ip4-input" : "ip4-lookup",
  },
};

VLIB_REGISTER_NODE (ip6_tcp_output_node,static) = {
  .function = ip6_tcp_output,
  .name = "ip6-tcp-output",
  .state = VLIB_NODE_STATE_DISABLED,
  .type = VLIB_NODE_TYPE_INPUT,

  .vector_size = sizeof (u32),

  .n_next_nodes = 1,
  .next_nodes = {
    [0] = CLIB_DEBUG > 0 ? "ip6-input" : "ip6-lookup",
  },
};

static_always_inline void
tcp_ack (tcp_main_t * tm, tcp_connection_t * c, u32 n_bytes)
{
  ASSERT (n_bytes == 0);
}

typedef enum {
  TCP_ESTABLISHED_NEXT_DROP,
  TCP_ESTABLISHED_N_NEXT,
} tcp_established_next_t;

static_always_inline uword
ip46_tcp_established (vlib_main_t * vm,
		      vlib_node_runtime_t * node,
		      vlib_frame_t * frame,
		      tcp_ip_4_or_6_t is_ip6)
{
  tcp_main_t * tm = &tcp_main;
  ip46_tcp_main_t * tm46 = is_ip6 ? &tm->ip6 : &tm->ip4;
  uword n_packets = frame->n_vectors;
  u32 * from, * to_next;
  u32 n_left_from, n_left_to_next, next, timestamp_now;
  vlib_node_runtime_t * error_node;

  error_node = vlib_node_get_runtime
    (vm, is_ip6 ? ip6_tcp_lookup_node.index : ip4_tcp_lookup_node.index);

  from = vlib_frame_vector_args (frame);
  n_left_from = n_packets;
  next = node->cached_next_index;
  timestamp_now = tcp_time_now (tm, TCP_TIMER_timestamp);
  
  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  vlib_buffer_t * p0;
	  ip6_header_t * ip60;
	  ip4_header_t * ip40;
	  tcp_header_t * tcp0;
	  tcp_connection_t * est0;
	  tcp_listener_t * l0;
	  u32 bi0, iest0, n_data_bytes0, his_ack_host0, n_ack0;
	  u8 error0, next0, n_advance_bytes0, is_fin0, send_ack0;
      
	  bi0 = to_next[0] = from[0];

	  from += 1;
	  n_left_from -= 1;
	  to_next += 1;
	  n_left_to_next -= 1;
      
	  p0 = vlib_get_buffer (vm, bi0);

	  if (is_ip6)
	    {
	      ip60 = vlib_buffer_get_current (p0);
	      tcp0 = ip6_next_header (ip60);
	      ASSERT (ip60->protocol == IP_PROTOCOL_TCP);
	      n_advance_bytes0 = tcp_header_bytes (tcp0);
	      n_data_bytes0 = clib_net_to_host_u16 (ip60->payload_length) - n_advance_bytes0;
	      n_advance_bytes0 += sizeof (ip60[0]);
	    }
	  else
	    {
	      ip40 = vlib_buffer_get_current (p0);
	      tcp0 = ip4_next_header (ip40);
	      n_advance_bytes0 = (ip4_header_bytes (ip40)
				  + tcp_header_bytes (tcp0));
	      n_data_bytes0 = clib_net_to_host_u16 (ip40->length) - n_advance_bytes0;
	    }

	  iest0 = vnet_buffer (p0)->ip.tcp.established_connection_index;
	  est0 = vec_elt_at_index (tm46->established_connections, iest0);

	  error0 = TCP_ERROR_NO_DATA;
	  next0 = TCP_ESTABLISHED_NEXT_DROP;

	  if (PREDICT_FALSE (clib_net_to_host_u32 (tcp0->seq_number)
			     != est0->sequence_numbers.his))
	    goto unexpected_seq_number0;
	  if (PREDICT_FALSE (clib_net_to_host_u32 (tcp0->ack_number) - est0->sequence_numbers.ours
			     > est0->n_tx_unacked_bytes))
	    goto unexpected_ack_number0;

	  is_fin0 = (tcp0->flags & TCP_FLAG_FIN) != 0;

	  if (PREDICT_FALSE ((est0->flags & TCP_CONNECTION_FLAG_fin_received)
			     && (is_fin0 || n_data_bytes0 > 0)))
	    goto already_received_fin0;

	  /* Update window. */
	  est0->his_window = clib_net_to_host_u16 (tcp0->window);

	  /* Update his sequence number to account for data he's just sent. */
	  est0->sequence_numbers.his += n_data_bytes0 + is_fin0;

	  his_ack_host0 = clib_net_to_host_u32 (tcp0->ack_number);
	  n_ack0 = his_ack_host0 - est0->sequence_numbers.ours;
	  tcp_ack (tm, est0, n_ack0);
	  est0->sequence_numbers.ours = his_ack_host0;

	  {
	    u32 t = tcp_options_decode_for_ack (tm, tcp0, &est0->time_stamps.his_net_byte_order);
	    if (t != est0->time_stamps.ours_host_byte_order)
	      {
		f64 dt = (timestamp_now - t) * tm->secs_per_tick[TCP_TIMER_timestamp];
		est0->round_trip_time_stats.sum += dt;
		est0->round_trip_time_stats.sum2 += dt*dt;
		est0->round_trip_time_stats.count += 1;
		est0->time_stamps.ours_host_byte_order = t;

		{
		  ELOG_TYPE_DECLARE (e) = {
		    .format = "ack rtt: %.4e",
		    .format_args = "f8",
		  };
		  struct { f64 dt; } * ed;
		  ed = ELOG_DATA (&vm->elog_main, e);
		  ed->dt = dt;
		}
	      }
	  }
	  
	  send_ack0 = ((est0->flags & TCP_CONNECTION_FLAG_ack_pending) == 0
		       && (n_data_bytes0 > 0 || is_fin0));
	  vec_add1 (tm46->connections_pending_acks, vnet_buffer (p0)->ip.tcp.established_connection_index);
	  _vec_len (tm46->connections_pending_acks) -= ! send_ack0;
	  est0->flags |= send_ack0 << LOG2_TCP_CONNECTION_FLAG_ack_pending;

	  est0->flags |= is_fin0 << LOG2_TCP_CONNECTION_FLAG_fin_received;

	  l0 = pool_elt_at_index (tm->listener_pool, vnet_buffer (p0)->ip.tcp.listener_index);

	  {
	    u32 ch0 = tcp_connection_handle_set (iest0, is_ip6);

	    vec_add1 (l0->eof_connections[is_ip6], ch0);
	    _vec_len (l0->eof_connections[is_ip6]) -= ! is_fin0;

	    vec_add1 (l0->close_connections[is_ip6], ch0);
	    _vec_len (l0->close_connections[is_ip6]) -= !(est0->flags & TCP_CONNECTION_FLAG_fin_sent);
	  }

	  next0 = n_data_bytes0 > 0 ? l0->next_index : next0;

	  vlib_buffer_advance (p0, n_advance_bytes0);

	enqueue0:
	  p0->error = error_node->errors[error0];
	  if (PREDICT_FALSE (next0 != next))
	    {
	      to_next -= 1;
	      n_left_to_next += 1;

	      vlib_put_next_frame (vm, node, next, n_left_to_next);

	      next = next0;
	      vlib_get_next_frame (vm, node, next, to_next, n_left_to_next);
	      to_next[0] = bi0;
	      to_next += 1;
	      n_left_to_next -= 1;
	    }
	  continue;

	unexpected_seq_number0:
	  next0 = TCP_ESTABLISHED_NEXT_DROP;
	  error0 = TCP_ERROR_UNEXPECTED_SEQ_NUMBER;
	  goto enqueue0;

	unexpected_ack_number0:
	  next0 = TCP_ESTABLISHED_NEXT_DROP;
	  error0 = TCP_ERROR_UNEXPECTED_ACK_NUMBER;
	  goto enqueue0;

	already_received_fin0:
	  next0 = TCP_ESTABLISHED_NEXT_DROP;
	  error0 = TCP_ERROR_SEGMENT_AFTER_FIN;
	  goto enqueue0;
	}
  
      vlib_put_next_frame (vm, node, next, n_left_to_next);
    }

  if (node->flags & VLIB_NODE_FLAG_TRACE)
    /* FIXME */ ;

  return frame->n_vectors;
}

static uword
ip4_tcp_established (vlib_main_t * vm,
		vlib_node_runtime_t * node,
		vlib_frame_t * frame)
{ return ip46_tcp_established (vm, node, frame, /* is_ip6 */ 0); }

static uword
ip6_tcp_established (vlib_main_t * vm,
		vlib_node_runtime_t * node,
		vlib_frame_t * frame)
{ return ip46_tcp_established (vm, node, frame, /* is_ip6 */ 1); }

VLIB_REGISTER_NODE (ip4_tcp_established_node,static) = {
  .function = ip4_tcp_established,
  .name = "ip4-tcp-established",

  .vector_size = sizeof (u32),

  .n_next_nodes = TCP_ESTABLISHED_N_NEXT,
  .next_nodes = {
    [TCP_ESTABLISHED_NEXT_DROP] = "error-drop",
  },
};

VLIB_REGISTER_NODE (ip6_tcp_established_node,static) = {
  .function = ip6_tcp_established,
  .name = "ip6-tcp-established",

  .vector_size = sizeof (u32),

  .n_next_nodes = TCP_ESTABLISHED_N_NEXT,
  .next_nodes = {
    [TCP_ESTABLISHED_NEXT_DROP] = "error-drop",
  },
};

uword
tcp_register_listener (vlib_main_t * vm,
		       tcp_listener_registration_t * r)
{
  tcp_main_t * tm = &tcp_main;
  tcp_listener_t * l;

  {
    clib_error_t * error;

    if ((error = vlib_call_init_function (vm, tcp_udp_lookup_init)))
      clib_error_report (error);
  }

  pool_get_aligned (tm->listener_pool, l, CLIB_CACHE_LINE_BYTES);

  memset (l, 0, sizeof (l[0]));

  l->dst_port = r->port;
  l->next_index = vlib_node_add_next (vm, ip4_tcp_established_node.index, r->data_node_index);
  l->valid_local_adjacency_bitmap = 0;
  l->flags = r->flags & (TCP_LISTENER_IP4 | TCP_LISTENER_IP6);

  tm->listener_index_by_dst_port[clib_host_to_net_u16 (l->dst_port)] = l - tm->listener_pool;

  return l - tm->listener_pool;
}

static void
tcp_udp_lookup_ip4_add_del_interface_address (ip4_main_t * im,
					      uword opaque,
					      u32 sw_if_index,
					      ip4_address_t * address,
					      u32 address_length,
					      u32 if_address_index,
					      u32 is_delete)
{
  tcp_main_t * tm = &tcp_main;

  tm->ip4.default_valid_local_adjacency_bitmap
    = clib_bitmap_set (tm->ip4.default_valid_local_adjacency_bitmap,
		       if_address_index,
		       is_delete ? 0 : 1);
}

static void
tcp_udp_lookup_ip6_add_del_interface_address (ip6_main_t * im,
					      uword opaque,
					      u32 sw_if_index,
					      ip6_address_t * address,
					      u32 address_length,
					      u32 if_address_index,
					      u32 is_delete)
{
  tcp_main_t * tm = &tcp_main;

  tm->ip6.default_valid_local_adjacency_bitmap
    = clib_bitmap_set (tm->ip6.default_valid_local_adjacency_bitmap,
		       if_address_index,
		       is_delete ? 0 : 1);
}

static clib_error_t *
tcp_udp_lookup_init (vlib_main_t * vm)
{
  tcp_main_t * tm = &tcp_main;
  ip4_main_t * im4 = &ip4_main;
  ip6_main_t * im6 = &ip6_main;
  clib_error_t * error;

  if ((error = vlib_call_init_function (vm, ip4_lookup_init)))
    return error;
  if ((error = vlib_call_init_function (vm, ip6_lookup_init)))
    return error;

  tcp_time_init (vm, tm);

  {
    ip4_add_del_interface_address_callback_t cb;

    cb.function = tcp_udp_lookup_ip4_add_del_interface_address;
    cb.function_opaque = 0;
    vec_add1 (im4->add_del_interface_address_callbacks, cb);
  }

  {
    ip6_add_del_interface_address_callback_t cb;

    cb.function = tcp_udp_lookup_ip6_add_del_interface_address;
    cb.function_opaque = 0;
    vec_add1 (im6->add_del_interface_address_callbacks, cb);
  }

  tm->ip4.output_node_index = ip4_tcp_output_node.index;
  tm->ip6.output_node_index = ip6_tcp_output_node.index;

  tcp_lookup_init (vm, tm);
  tcp_options_decode_init (tm);

  tm->tx_buffer_free_list = VLIB_BUFFER_DEFAULT_FREE_LIST_INDEX;
  tm->tx_buffer_free_list_n_buffer_bytes = VLIB_BUFFER_DEFAULT_FREE_LIST_BYTES;

  return 0;
}

VLIB_INIT_FUNCTION (tcp_udp_lookup_init);

static u8 * format_tcp_time_stamp (u8 * s, va_list * va)
{
  tcp_timer_type_t type = va_arg (*va, tcp_timer_type_t);
  u32 value = va_arg (*va, u32);
  vlib_main_t * vm = vlib_get_main();
  tcp_main_t * tm = &tcp_main;
  u64 now;
  f64 dt;

  now = clib_cpu_time_now ();
  dt = vm->clib_time.seconds_per_clock * (now - (value << tm->log2_clocks_per_tick[type]));
  return format (s, "%.4e sec", dt);
}

static u8 * format_tcp_connection_state (u8 * s, va_list * va)
{
  tcp_connection_state_t st = va_arg (*va, tcp_connection_state_t);
  char * t = 0;
  switch (st)
    {
#define _(f) case TCP_CONNECTION_STATE_##f: t = #f; break;
      foreach_tcp_connection_state
#undef _
    default: break;
    }
  if (t)
    s = format (s, "%s", t);
  else
    s = format (s, "unknown 0x%x", st);

  return s;
}

static u8 * format_tcp_ip_4_or_6 (u8 * s, va_list * va)
{
  tcp_ip_4_or_6_t is_ip6 = va_arg (*va, tcp_ip_4_or_6_t);
  return format (s, "%s", is_ip6 ? "ip6" : "ip4");
}

static u8 * format_tcp_mini_connection (u8 * s, va_list * va)
{
  tcp_mini_connection_t * c = va_arg (*va, tcp_mini_connection_t *);

  s = format (s, "state %U, window scale %d, mss %d",
	      format_tcp_connection_state, c->state,
	      c->window_scale, c->max_segment_size);

  return s;
}

static u8 * format_ip4_tcp_mini_connection (u8 * s, va_list * va)
{
  u32 imin = va_arg (*va, u32);
  u32 imin_div, imin_mod;
  tcp_main_t * tm = &tcp_main;
  tcp_mini_connection_t * min;
  ip4_tcp_udp_address_x4_and_timestamps_t * mina;
  
  imin_div = imin / 4;
  imin_mod = imin % 4;

  mina = vec_elt_at_index (tm->ip4_mini_connection_address_hash, imin_div);

  s = format (s, "%U, age %U",
	      format_ip4_tcp_udp_address_x4, &mina->address_x4, imin_div,
	      format_tcp_time_stamp, TCP_TIMER_mini_connection, mina->time_stamps[imin_div]);

  min = vec_elt_at_index (tm->ip4.mini_connections, imin);

  s = format (s, "%U", format_tcp_mini_connection, min);

  return s;
}

static u8 * format_ip6_tcp_mini_connection (u8 * s, va_list * va)
{
  u32 imin = va_arg (*va, u32);
  u32 imin_div, imin_mod;
  tcp_main_t * tm = &tcp_main;
  tcp_mini_connection_t * min;
  ip6_tcp_udp_address_x4_and_timestamps_t * mina;
  
  imin_div = imin / 4;
  imin_mod = imin % 4;

  mina = vec_elt_at_index (tm->ip6_mini_connection_address_hash, imin_div);

  s = format (s, "%U, age %U",
	      format_ip6_tcp_udp_address_x4, &mina->address_x4, imin_div,
	      format_tcp_time_stamp, TCP_TIMER_mini_connection, mina->time_stamps[imin_div]);

  min = vec_elt_at_index (tm->ip6.mini_connections, imin);

  s = format (s, "%U", format_tcp_mini_connection, min);

  return s;
}

static u8 * format_tcp_established_connection (u8 * s, va_list * va)
{
  tcp_connection_t * c = va_arg (*va, tcp_connection_t *);

  if (c->flags != 0)
    {
      s = format (s, ", flags: ");
#define _(f) if (c->flags & TCP_CONNECTION_FLAG_##f) s = format (s, "%s, ", #f);
      foreach_tcp_connection_flag;
#undef _
    }

  if (tcp_round_trip_time_stats_is_valid (&c->round_trip_time_stats))
    {
      f64 r[2];
      tcp_round_trip_time_stats_compute (&c->round_trip_time_stats, r);
      s = format (s, ", rtt %.4e +- %.4e",
		  r[0], r[1]);
    }

  return s;
}

static u8 * format_ip4_tcp_established_connection (u8 * s, va_list * va)
{
  u32 iest = va_arg (*va, u32);
  u32 iest_div, iest_mod;
  tcp_main_t * tm = &tcp_main;
  tcp_connection_t * est;
  ip4_tcp_udp_address_x4_t * esta;
  
  iest_div = iest / 4;
  iest_mod = iest % 4;

  esta = vec_elt_at_index (tm->ip4_established_connection_address_hash, iest_div);
  est = vec_elt_at_index (tm->ip4.established_connections, iest);

  s = format (s, "%U%U",
	      format_ip4_tcp_udp_address_x4, esta, iest_mod,
	      format_tcp_established_connection, est);

  return s;
}

static u8 * format_ip6_tcp_established_connection (u8 * s, va_list * va)
{
  u32 iest = va_arg (*va, u32);
  u32 iest_div, iest_mod;
  tcp_main_t * tm = &tcp_main;
  tcp_connection_t * est;
  ip6_tcp_udp_address_x4_t * esta;
  
  iest_div = iest / 4;
  iest_mod = iest % 4;

  esta = vec_elt_at_index (tm->ip6_established_connection_address_hash, iest_div);
  est = vec_elt_at_index (tm->ip6.established_connections, iest);

  s = format (s, "%U%U",
	      format_ip6_tcp_udp_address_x4, esta, iest_mod,
	      format_tcp_established_connection, est);

  return s;
}

VLIB_CLI_COMMAND (vlib_cli_show_tcp_command, static) = {
  .path = "show tcp",
  .short_help = "Transmission control protocol (TCP) show commands",
};

static clib_error_t *
show_mini_connections (vlib_main_t * vm, unformat_input_t * input, vlib_cli_command_t * cmd)
{
  tcp_main_t * tm = &tcp_main;
  ip46_tcp_main_t * tm46;
  tcp_ip_4_or_6_t is_ip6 = TCP_IP4;
  tcp_mini_connection_t * min;
  ip6_tcp_udp_address_x4_and_timestamps_t * mina6;
  ip4_tcp_udp_address_x4_and_timestamps_t * mina4;
  clib_error_t * error = 0;
  uword i, i0, i1, n_valid;

  if (unformat (input, "4"))
    is_ip6 = TCP_IP4;
  if (unformat (input, "6"))
    is_ip6 = TCP_IP6;

  n_valid = 0;
  tm46 = is_ip6 ? &tm->ip6 : &tm->ip4;
  for (i = 0; i <= tm46->mini_connection_hash_mask; i++)
    {
      i0 = i / 4;
      i1 = i % 4;

      min = vec_elt_at_index (tm46->mini_connections, i);
      if (is_ip6)
	{
	  mina6 = vec_elt_at_index (tm->ip6_mini_connection_address_hash, i0);
	  if (ip6_tcp_udp_address_x4_is_valid (&mina6->address_x4, i1))
	    {
	      vlib_cli_output (vm, "%U", format_ip4_tcp_mini_connection, i);
	      n_valid += 1;
	    }
	}
      else
	{
	  mina4 = vec_elt_at_index (tm->ip4_mini_connection_address_hash, i0);
	  if (ip4_tcp_udp_address_x4_is_valid (&mina4->address_x4, i1))
	    {
	      vlib_cli_output (vm, "%U", format_ip6_tcp_mini_connection, i);
	      n_valid += 1;
	    }
	}
    }

  if (n_valid == 0)
    vlib_cli_output (vm, "no %U mini tcp connections", format_tcp_ip_4_or_6, is_ip6);

  return error;
}

VLIB_CLI_COMMAND (vlib_cli_show_tcp_mini_connections_command) = {
  .path = "show tcp mini-connections",
  .short_help = "Show not-yet established TCP connections",
  .function = show_mini_connections,
};

static clib_error_t *
show_established_connections (vlib_main_t * vm, unformat_input_t * input, vlib_cli_command_t * cmd)
{
  tcp_main_t * tm = &tcp_main;
  ip46_tcp_main_t * tm46;
  tcp_ip_4_or_6_t is_ip6 = TCP_IP4;
  tcp_connection_t * est;
  ip6_tcp_udp_address_x4_t * esta6;
  ip4_tcp_udp_address_x4_t * esta4;
  clib_error_t * error = 0;
  uword i, i0, i1, n_valid;

  if (unformat (input, "4"))
    is_ip6 = TCP_IP4;
  if (unformat (input, "6"))
    is_ip6 = TCP_IP6;

  n_valid = 0;
  tm46 = is_ip6 ? &tm->ip6 : &tm->ip4;
  for (i = 0; i < vec_len (tm46->established_connections); i++)
    {
      i0 = i / 4;
      i1 = i % 4;

      est = vec_elt_at_index (tm46->established_connections, i);
      if (is_ip6)
	{
	  esta6 = vec_elt_at_index (tm->ip6_established_connection_address_hash, i0);
	  if (ip6_tcp_udp_address_x4_is_valid (esta6, i1))
	    {
	      vlib_cli_output (vm, "%U", format_ip6_tcp_established_connection, i);
	      n_valid += 1;
	    }
	}
      else
	{
	  esta4 = vec_elt_at_index (tm->ip4_established_connection_address_hash, i0);
	  if (ip4_tcp_udp_address_x4_is_valid (esta4, i1))
	    {
	      vlib_cli_output (vm, "%U", format_ip4_tcp_established_connection, i);
	      n_valid += 1;
	    }
	}
    }

  if (n_valid == 0)
    vlib_cli_output (vm, "no %U established tcp connections", format_tcp_ip_4_or_6, is_ip6);

  return error;
}

VLIB_CLI_COMMAND (vlib_cli_show_tcp_established_connections_command, static) = {
  .path = "show tcp connections",
  .short_help = "Show established TCP connections",
  .function = show_established_connections,
};

#if 0
uword
tcp_write (vlib_main_t * vm, u32 connection_handle, void * data, uword n_data_bytes)
{
  tcp_main_t * tm = &tcp_main;
  tcp_ip_4_or_6_t is_ip6 = tcp_connection_is_ip6 (connection_handle);
  ip46_tcp_main_t * tm46 = is_ip6 ? &tm->ip6 : &tm->ip4;
  tcp_connection_t * c = vec_elt_at_index (tm46->established_connections, connection_handle / 2);
  vlib_buffer_t * b;
  u32 bi, bi_next, bi_start_of_packet;
  ip_csum_t sum;

  b = 0;
  bi = c->write_tail_buffer_index;
  n_bytes_left_tail = 0;
  if (bi != 0)
    {
      b = vlib_get_buffer (vm, bi);
      n_bytes_left_tail = tm->tx_buffer_free_list_n_buffer_bytes - b->current_length;
    }

  n_bytes_this_packet = c->write_tail_packet.n_data_bytes;
  n_bytes_left_packet = c->max_segment_size - n_bytes_this_packet;

  n_data_left = n_data_bytes;
  sum = c->write_tail_packet.data_ip_checksum;

  while (n_data_left > 0)
    {
      u32 n_copy;

      if (n_bytes_left_tail == 0)
	{
	  if (! vlib_buffer_alloc_from_free_list (vm, &bi_next, 1,
						  tm->tx_buffer_free_list))
	    return n_data_bytes - n_data_left;

	  bi_start_of_packet = bi_next;
	  if (b)
	    {
	      b->flags |= VLIB_BUFFER_NEXT_PRESENT;
	      b->next_buffer = bi_next;
	      bi_start_of_packet = b->opaque[0];
	    }
	  bi = bi_next;
	  b = vlib_get_buffer (vm, bi);

	  /* Save away start of packet buffer in opaque. */
	  b->opaque[0] = bi_start_of_packet;

	  c->tail_buffer.buffer_index = bi;
	  n_bytes_left_tail = tm->tx_buffer_free_list_n_buffer_bytes;
	}

      n_copy = n_data_left;
      n_copy = clib_min (n_copy, n_bytes_left_tail);
      n_copy = clib_min (n_copy, n_bytes_left_packet);

      sum = ip_csum_and_memcpy (sum, b->data + b->current_length,
				data, n_copy);

      b->current_length += n_copy;
      n_bytes_left_tail -= n_copy;
      n_bytes_left_packet -= n_copy;
      n_data_left -=- n_copy;
      n_bytes_this_packet += n_copy;

      if (n_bytes_left_packet == 0)
	{
	  bi_start_of_packet = b->opaque[0];

	  if (c->tail_packet.buffer_index != 0)
	    {
	      vlib_buffer_t * p = vlib_get_buffer (vm, c->tail_packet.buffer_index);
	      tcp_buffer_t * next = vlib_get_buffer_opaque (p);
	      next[0] = c->;
	    }
	  c->tail_packet.buffer_index = bi_start_of_packet;
	}
    }

  c->tail_buffer.buffer_index = bi;
  c->tail_buffer.n_data_bytes = n_bytes_this_packet;
  c->tail_buffer.data_ip_checksum = ip_csum_fold (sum);

  return 0;
}
#endif
