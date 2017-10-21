/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
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
 * ip/ip6_input.c: IP v6 input node
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

#ifndef included_ip6_input_h
#define included_ip6_input_h

#include <vnet/ip/ip.h>

extern char *ip6_error_strings[];

typedef enum
{
  IP6_INPUT_NEXT_DROP,
  IP6_INPUT_NEXT_LOOKUP,
  IP6_INPUT_NEXT_LOOKUP_MULTICAST,
  IP6_INPUT_NEXT_ICMP_ERROR,
  IP6_INPUT_N_NEXT,
} ip6_input_next_t;

always_inline void
ip6_input_check_x2 (vlib_main_t * vm,
		    vlib_node_runtime_t * error_node,
		    vlib_buffer_t * p0, vlib_buffer_t * p1,
		    ip6_header_t * ip0, ip6_header_t * ip1,
		    u32 * next0, u32 * next1)
{
  u8 error0, error1;

  error0 = error1 = IP6_ERROR_NONE;

  /* Version != 6?  Drop it. */
  error0 =
    (clib_net_to_host_u32
     (ip0->ip_version_traffic_class_and_flow_label) >> 28) !=
    6 ? IP6_ERROR_VERSION : error0;
  error1 =
    (clib_net_to_host_u32
     (ip1->ip_version_traffic_class_and_flow_label) >> 28) !=
    6 ? IP6_ERROR_VERSION : error1;

  /* hop limit < 1? Drop it.  for link-local broadcast packets,
   * like dhcpv6 packets from client has hop-limit 1, which should not
   * be dropped.
   */
  error0 = ip0->hop_limit < 1 ? IP6_ERROR_TIME_EXPIRED : error0;
  error1 = ip1->hop_limit < 1 ? IP6_ERROR_TIME_EXPIRED : error1;

  /* L2 length must be at least minimal IP header. */
  error0 =
    p0->current_length < sizeof (ip0[0]) ? IP6_ERROR_TOO_SHORT : error0;
  error1 =
    p1->current_length < sizeof (ip1[0]) ? IP6_ERROR_TOO_SHORT : error1;

  if (PREDICT_FALSE (error0 != IP6_ERROR_NONE))
    {
      if (error0 == IP6_ERROR_TIME_EXPIRED)
	{
	  icmp6_error_set_vnet_buffer (p0, ICMP6_time_exceeded,
				       ICMP6_time_exceeded_ttl_exceeded_in_transit,
				       0);
	  *next0 = IP6_INPUT_NEXT_ICMP_ERROR;
	}
      else
	{
	  *next0 = IP6_INPUT_NEXT_DROP;
	}
    }
  if (PREDICT_FALSE (error1 != IP6_ERROR_NONE))
    {
      if (error1 == IP6_ERROR_TIME_EXPIRED)
	{
	  icmp6_error_set_vnet_buffer (p1, ICMP6_time_exceeded,
				       ICMP6_time_exceeded_ttl_exceeded_in_transit,
				       0);
	  *next1 = IP6_INPUT_NEXT_ICMP_ERROR;
	}
      else
	{
	  *next1 = IP6_INPUT_NEXT_DROP;
	}
    }
}

always_inline void
ip6_input_check_x1 (vlib_main_t * vm,
		    vlib_node_runtime_t * error_node,
		    vlib_buffer_t * p0, ip6_header_t * ip0, u32 * next0)
{
  u8 error0;

  error0 = IP6_ERROR_NONE;

  /* Version != 6?  Drop it. */
  error0 =
    (clib_net_to_host_u32
     (ip0->ip_version_traffic_class_and_flow_label) >> 28) !=
    6 ? IP6_ERROR_VERSION : error0;

  /* hop limit < 1? Drop it.  for link-local broadcast packets,
   * like dhcpv6 packets from client has hop-limit 1, which should not
   * be dropped.
   */
  error0 = ip0->hop_limit < 1 ? IP6_ERROR_TIME_EXPIRED : error0;

  /* L2 length must be at least minimal IP header. */
  error0 =
    p0->current_length < sizeof (ip0[0]) ? IP6_ERROR_TOO_SHORT : error0;

  if (PREDICT_FALSE (error0 != IP6_ERROR_NONE))
    {
      if (error0 == IP6_ERROR_TIME_EXPIRED)
	{
	  icmp6_error_set_vnet_buffer (p0, ICMP6_time_exceeded,
				       ICMP6_time_exceeded_ttl_exceeded_in_transit,
				       0);
	  *next0 = IP6_INPUT_NEXT_ICMP_ERROR;
	}
      else
	{
	  *next0 = IP6_INPUT_NEXT_DROP;
	}
    }
}

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
