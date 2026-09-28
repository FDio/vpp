/* SPDX-License-Identifier: Apache-2.0 OR MIT
 * Copyright (c) 2017 Cisco and/or its affiliates.
 * Copyright (c) 2008 Eliot Dresselhaus
 */

/* ip/ip6_input.c: IP v6 input node */

#ifndef included_ip6_input_h
#define included_ip6_input_h

#include <vnet/ip/ip.h>
#include <vnet/ip/icmp6.h>

typedef enum
{
  IP6_INPUT_NEXT_DROP,
  IP6_INPUT_NEXT_LOOKUP,
  IP6_INPUT_NEXT_LOOKUP_MULTICAST,
  IP6_INPUT_NEXT_ICMP_ERROR,
  IP6_INPUT_N_NEXT,
} ip6_input_next_t;

__clib_export u32 ip6_input_trim_slow (vlib_main_t *vm, vlib_buffer_t *b, ip6_header_t *ip);

/* Cut the buffer to the datagram; non-zero if it is shorter. */
static_always_inline u32
ip6_input_trim (vlib_main_t *vm, vlib_buffer_t *b, ip6_header_t *ip)
{
  u32 len = clib_net_to_host_u16 (ip->payload_length) + sizeof (ip[0]);
  u32 cur;

  if (PREDICT_FALSE ((b->flags & VLIB_BUFFER_NEXT_PRESENT) || len == sizeof (ip[0])))
    return ip6_input_trim_slow (vm, b, ip);
  cur = clib_min (b->current_length, len);
  b->current_length = cur;
  return cur < len;
}

always_inline void
ip6_input_check_x2 (vlib_main_t *vm, vlib_node_runtime_t *error_node,
		    vlib_buffer_t *p0, vlib_buffer_t *p1, ip6_header_t *ip0,
		    ip6_header_t *ip1, u32 *next0, u32 *next1)
{
  u8 error0, error1;
  u32 plen0, len0, cur_len0, short0;
  u32 plen1, len1, cur_len1, short1;

  error0 = error1 = IP6_ERROR_NONE;

  /* Version != 6?  Drop it. */
  error0 =
    (clib_net_to_host_u32 (ip0->ip_version_traffic_class_and_flow_label) >>
     28) != 6 ?
	    IP6_ERROR_VERSION :
	    error0;
  error1 =
    (clib_net_to_host_u32 (ip1->ip_version_traffic_class_and_flow_label) >>
     28) != 6 ?
	    IP6_ERROR_VERSION :
	    error1;

  /* hop limit < 1? Drop it.  for link-local broadcast packets,
   * like dhcpv6 packets from client has hop-limit 1, which should not
   * be dropped.
   */
  error0 = ip0->hop_limit < 1 ? IP6_ERROR_TIME_EXPIRED : error0;
  error1 = ip1->hop_limit < 1 ? IP6_ERROR_TIME_EXPIRED : error1;

  plen0 = clib_net_to_host_u16 (ip0->payload_length);
  plen1 = clib_net_to_host_u16 (ip1->payload_length);

  if (PREDICT_TRUE (!((p0->flags | p1->flags) & VLIB_BUFFER_NEXT_PRESENT) & (plen0 != 0) &
		    (plen1 != 0)))
    {
      len0 = plen0 + sizeof (ip0[0]);
      len1 = plen1 + sizeof (ip1[0]);
      cur_len0 = clib_min (p0->current_length, len0);
      cur_len1 = clib_min (p1->current_length, len1);
      p0->current_length = cur_len0;
      p1->current_length = cur_len1;
      short0 = cur_len0 < len0;
      short1 = cur_len1 < len1;
    }
  else
    {
      short0 = ip6_input_trim_slow (vm, p0, ip0);
      short1 = ip6_input_trim_slow (vm, p1, ip1);
    }

  error0 = short0 ? IP6_ERROR_BAD_LENGTH : error0;
  error1 = short1 ? IP6_ERROR_BAD_LENGTH : error1;

  /* L2 length must be at least minimal IP header. */
  error0 = p0->current_length < sizeof (ip0[0]) ? IP6_ERROR_TOO_SHORT : error0;
  error1 = p1->current_length < sizeof (ip1[0]) ? IP6_ERROR_TOO_SHORT : error1;

  if (PREDICT_FALSE (error0 != IP6_ERROR_NONE))
    {
      p0->error = error_node->errors[error0];

      if (error0 == IP6_ERROR_TIME_EXPIRED)
	{
	  icmp6_error_set_vnet_buffer (
	    p0, ICMP6_time_exceeded,
	    ICMP6_time_exceeded_ttl_exceeded_in_transit, 0);
	  *next0 = IP6_INPUT_NEXT_ICMP_ERROR;
	}
      else
	{
	  *next0 = IP6_INPUT_NEXT_DROP;
	}
    }
  if (PREDICT_FALSE (error1 != IP6_ERROR_NONE))
    {
      p1->error = error_node->errors[error1];

      if (error1 == IP6_ERROR_TIME_EXPIRED)
	{
	  icmp6_error_set_vnet_buffer (
	    p1, ICMP6_time_exceeded,
	    ICMP6_time_exceeded_ttl_exceeded_in_transit, 0);
	  *next1 = IP6_INPUT_NEXT_ICMP_ERROR;
	}
      else
	{
	  *next1 = IP6_INPUT_NEXT_DROP;
	}
    }
}

always_inline void
ip6_input_check_x1 (vlib_main_t *vm, vlib_node_runtime_t *error_node,
		    vlib_buffer_t *p0, ip6_header_t *ip0, u32 *next0)
{
  u8 error0;

  error0 = IP6_ERROR_NONE;

  /* Version != 6?  Drop it. */
  error0 =
    (clib_net_to_host_u32 (ip0->ip_version_traffic_class_and_flow_label) >>
     28) != 6 ?
	    IP6_ERROR_VERSION :
	    error0;

  /* hop limit < 1? Drop it.  for link-local broadcast packets,
   * like dhcpv6 packets from client has hop-limit 1, which should not
   * be dropped.
   */
  error0 = ip0->hop_limit < 1 ? IP6_ERROR_TIME_EXPIRED : error0;

  error0 = ip6_input_trim (vm, p0, ip0) ? IP6_ERROR_BAD_LENGTH : error0;

  /* L2 length must be at least minimal IP header. */
  error0 = p0->current_length < sizeof (ip0[0]) ? IP6_ERROR_TOO_SHORT : error0;

  if (PREDICT_FALSE (error0 != IP6_ERROR_NONE))
    {
      p0->error = error_node->errors[error0];
      if (error0 == IP6_ERROR_TIME_EXPIRED)
	{
	  icmp6_error_set_vnet_buffer (
	    p0, ICMP6_time_exceeded,
	    ICMP6_time_exceeded_ttl_exceeded_in_transit, 0);
	  *next0 = IP6_INPUT_NEXT_ICMP_ERROR;
	}
      else
	{
	  *next0 = IP6_INPUT_NEXT_DROP;
	}
    }
}

#endif
