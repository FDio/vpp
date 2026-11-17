/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 FastNetMon
 */

#include <vnet/ip/ip.h>
#include <vnet/udp/udp_packet.h>
#include <vnet/sfdp/sfdp.h>

enum
{
  SAMPLE_FILTER_DISCARD,
  SAMPLE_FILTER_ECHO,
  SAMPLE_FILTER_N,
};

static vlib_simple_counter_main_t sample_filter_calls = {
  .name = "sample-filter-calls",
  .stat_segment_name = "/sfdp/sample/filter-calls",
};

static_always_inline u16
sample_filter_dst_port (vlib_buffer_t *b)
{
  u8 *p = vlib_buffer_get_current (b);
  udp_header_t *udp;
  u8 protocol;

  if ((p[0] >> 4) == 4)
    {
      ip4_header_t *ip4 = (ip4_header_t *) p;
      protocol = ip4->protocol;
      udp = (udp_header_t *) (p + ip4_header_bytes (ip4));
    }
  else
    {
      ip6_header_t *ip6 = (ip6_header_t *) p;
      protocol = ip6->protocol;
      udp = (udp_header_t *) (ip6 + 1);
    }
  if (protocol != IP_PROTOCOL_UDP && protocol != IP_PROTOCOL_TCP)
    return 0;
  return clib_net_to_host_u16 (udp->dst_port);
}

static u32
sample_filter_discard (vlib_buffer_t *b, u32 tenant_index, u32 thread_index)
{
  vlib_increment_simple_counter (&sample_filter_calls, thread_index, SAMPLE_FILTER_DISCARD, 1);
  return sample_filter_dst_port (b) == 9;
}

static u32
sample_filter_echo (vlib_buffer_t *b, u32 tenant_index, u32 thread_index)
{
  vlib_increment_simple_counter (&sample_filter_calls, thread_index, SAMPLE_FILTER_ECHO, 1);
  return sample_filter_dst_port (b) == 7;
}

static clib_error_t *
sample_filter_init (vlib_main_t *vm)
{
  vlib_validate_simple_counter (&sample_filter_calls, SAMPLE_FILTER_N - 1);
  for (u32 i = 0; i < SAMPLE_FILTER_N; i++)
    vlib_zero_simple_counter (&sample_filter_calls, i);
  return 0;
}

VLIB_INIT_FUNCTION (sample_filter_init);

SFDP_FILTER_DEFINE (sample_discard, "sample-discard", sample_filter_discard);
SFDP_FILTER_DEFINE (sample_echo, "sample-echo", sample_filter_echo);
