/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 FastNetMon
 */

#include <vnet/ip/ip.h>
#include <vnet/udp/udp_packet.h>
#include <vnet/sfdp/sfdp.h>

#define SAMPLE_PRE_FILTER_DISCARD_PORT 9
#define SAMPLE_PRE_FILTER_ECHO_PORT    7

enum
{
  SAMPLE_PRE_FILTER_DISCARD,
  SAMPLE_PRE_FILTER_ECHO,
  SAMPLE_PRE_FILTER_N,
};

static vlib_simple_counter_main_t sample_pre_filter_calls = {
  .name = "sample-pre-filter-calls",
  .stat_segment_name = "/sfdp/sample/pre-filter-calls",
};

static_always_inline u16
sample_pre_filter_dst_port (vlib_buffer_t *b, u8 is_ip6)
{
  udp_header_t *udp;
  u8 protocol;

  if (is_ip6)
    {
      ip6_header_t *ip6 = vlib_buffer_get_current (b);
      protocol = ip6->protocol;
      udp = (udp_header_t *) (ip6 + 1);
    }
  else
    {
      ip4_header_t *ip4 = vlib_buffer_get_current (b);
      protocol = ip4->protocol;
      udp = ip4_next_header (ip4);
    }
  if (protocol != IP_PROTOCOL_UDP && protocol != IP_PROTOCOL_TCP)
    return 0;
  return clib_net_to_host_u16 (udp->dst_port);
}

static u32
sample_pre_filter_discard (vlib_main_t *vm, vlib_buffer_t *b, u32 tenant_index, u8 is_ip6)
{
  vlib_increment_simple_counter (&sample_pre_filter_calls, vm->thread_index,
				 SAMPLE_PRE_FILTER_DISCARD, 1);
  return sample_pre_filter_dst_port (b, is_ip6) != SAMPLE_PRE_FILTER_DISCARD_PORT;
}

static u32
sample_pre_filter_echo (vlib_main_t *vm, vlib_buffer_t *b, u32 tenant_index, u8 is_ip6)
{
  vlib_increment_simple_counter (&sample_pre_filter_calls, vm->thread_index, SAMPLE_PRE_FILTER_ECHO,
				 1);
  return sample_pre_filter_dst_port (b, is_ip6) != SAMPLE_PRE_FILTER_ECHO_PORT;
}

static clib_error_t *
sample_pre_filter_init (vlib_main_t *vm)
{
  vlib_validate_simple_counter (&sample_pre_filter_calls, SAMPLE_PRE_FILTER_N - 1);
  for (u32 i = 0; i < SAMPLE_PRE_FILTER_N; i++)
    vlib_zero_simple_counter (&sample_pre_filter_calls, i);
  return 0;
}

VLIB_INIT_FUNCTION (sample_pre_filter_init);

SFDP_PRE_FILTER_DEFINE (sample_discard, "sample-discard", sample_pre_filter_discard);
SFDP_PRE_FILTER_DEFINE (sample_echo, "sample-echo", sample_pre_filter_echo);
