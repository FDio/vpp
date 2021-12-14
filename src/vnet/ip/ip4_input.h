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
 * ip/ip4_input.c: IP v4 input node
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

#ifndef included_ip_input_h
#define included_ip_input_h

#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>
#include <vppinfra/vector/ip_csum.h>

typedef enum
{
  IP4_INPUT_NEXT_DROP,
  IP4_INPUT_NEXT_PUNT,
  IP4_INPUT_NEXT_OPTIONS,
  IP4_INPUT_NEXT_LOOKUP,
  IP4_INPUT_NEXT_LOOKUP_MULTICAST,
  IP4_INPUT_NEXT_ICMP_ERROR,
  IP4_INPUT_N_NEXT,
} ip4_input_next_t;

static_always_inline void
check_ver_opt_csum (ip4_header_t * ip, u8 * error, int verify_checksum)
{
  if (PREDICT_FALSE (ip->ip_version_and_header_length != 0x45))
    {
      if ((ip->ip_version_and_header_length & 0xf) != 5)
	{
	  *error = IP4_ERROR_OPTIONS;
	  if (verify_checksum &&
	      clib_ip_csum ((u8 *) ip, ip4_header_bytes (ip)) != 0)
	    *error = IP4_ERROR_BAD_CHECKSUM;
	}
      else
	*error = IP4_ERROR_VERSION;
    }
  else if (PREDICT_FALSE (verify_checksum &&
			  clib_ip_csum ((u8 *) ip, sizeof (ip4_header_t)) !=
			    0))
    *error = IP4_ERROR_BAD_CHECKSUM;
}

always_inline void
ip4_input_check_x4 (vlib_main_t * vm,
		    vlib_node_runtime_t * error_node,
		    vlib_buffer_t ** p, ip4_header_t ** ip,
		    u16 * next, int verify_checksum)
{
  u8 error0, error1, error2, error3;
  u32 ip_len0, cur_len0;
  u32 ip_len1, cur_len1;
  u32 ip_len2, cur_len2;
  u32 ip_len3, cur_len3;
  i32 len_diff0, len_diff1, len_diff2, len_diff3;

  error0 = error1 = error2 = error3 = IP4_ERROR_NONE;

  check_ver_opt_csum (ip[0], &error0, verify_checksum);
  check_ver_opt_csum (ip[1], &error1, verify_checksum);
  check_ver_opt_csum (ip[2], &error2, verify_checksum);
  check_ver_opt_csum (ip[3], &error3, verify_checksum);

  if (PREDICT_FALSE (ip[0]->ttl < 1))
    error0 = IP4_ERROR_TIME_EXPIRED;
  if (PREDICT_FALSE (ip[1]->ttl < 1))
    error1 = IP4_ERROR_TIME_EXPIRED;
  if (PREDICT_FALSE (ip[2]->ttl < 1))
    error2 = IP4_ERROR_TIME_EXPIRED;
  if (PREDICT_FALSE (ip[3]->ttl < 1))
    error3 = IP4_ERROR_TIME_EXPIRED;

  /* Drop fragmentation offset 1 packets. */
  error0 = ip4_get_fragment_offset (ip[0]) == 1 ?
    IP4_ERROR_FRAGMENT_OFFSET_ONE : error0;
  error1 = ip4_get_fragment_offset (ip[1]) == 1 ?
    IP4_ERROR_FRAGMENT_OFFSET_ONE : error1;
  error2 = ip4_get_fragment_offset (ip[2]) == 1 ?
    IP4_ERROR_FRAGMENT_OFFSET_ONE : error2;
  error3 = ip4_get_fragment_offset (ip[3]) == 1 ?
    IP4_ERROR_FRAGMENT_OFFSET_ONE : error3;

  /* Verify lengths. */
  ip_len0 = clib_net_to_host_u16 (ip[0]->length);
  ip_len1 = clib_net_to_host_u16 (ip[1]->length);
  ip_len2 = clib_net_to_host_u16 (ip[2]->length);
  ip_len3 = clib_net_to_host_u16 (ip[3]->length);

  /* IP length must be at least minimal IP header. */
  error0 = ip_len0 < sizeof (ip[0][0]) ? IP4_ERROR_TOO_SHORT : error0;
  error1 = ip_len1 < sizeof (ip[1][0]) ? IP4_ERROR_TOO_SHORT : error1;
  error2 = ip_len2 < sizeof (ip[2][0]) ? IP4_ERROR_TOO_SHORT : error2;
  error3 = ip_len3 < sizeof (ip[3][0]) ? IP4_ERROR_TOO_SHORT : error3;

  cur_len0 = vlib_buffer_length_in_chain (vm, p[0]);
  cur_len1 = vlib_buffer_length_in_chain (vm, p[1]);
  cur_len2 = vlib_buffer_length_in_chain (vm, p[2]);
  cur_len3 = vlib_buffer_length_in_chain (vm, p[3]);

  len_diff0 = cur_len0 - ip_len0;
  len_diff1 = cur_len1 - ip_len1;
  len_diff2 = cur_len2 - ip_len2;
  len_diff3 = cur_len3 - ip_len3;

  error0 = len_diff0 < 0 ? IP4_ERROR_BAD_LENGTH : error0;
  error1 = len_diff1 < 0 ? IP4_ERROR_BAD_LENGTH : error1;
  error2 = len_diff2 < 0 ? IP4_ERROR_BAD_LENGTH : error2;
  error3 = len_diff3 < 0 ? IP4_ERROR_BAD_LENGTH : error3;

  if (PREDICT_FALSE (error0 != IP4_ERROR_NONE))
    {
      if (error0 == IP4_ERROR_TIME_EXPIRED)
	{
	  icmp4_error_set_vnet_buffer (p[0], ICMP4_time_exceeded,
				       ICMP4_time_exceeded_ttl_exceeded_in_transit,
				       0);
	  next[0] = IP4_INPUT_NEXT_ICMP_ERROR;
	}
      else
	next[0] = error0 != IP4_ERROR_OPTIONS ?
	  IP4_INPUT_NEXT_DROP : IP4_INPUT_NEXT_OPTIONS;
      p[0]->error = error_node->errors[error0];
    }
  if (PREDICT_FALSE (error1 != IP4_ERROR_NONE))
    {
      if (error1 == IP4_ERROR_TIME_EXPIRED)
	{
	  icmp4_error_set_vnet_buffer (p[1], ICMP4_time_exceeded,
				       ICMP4_time_exceeded_ttl_exceeded_in_transit,
				       0);
	  next[1] = IP4_INPUT_NEXT_ICMP_ERROR;
	}
      else
	next[1] = error1 != IP4_ERROR_OPTIONS ?
	  IP4_INPUT_NEXT_DROP : IP4_INPUT_NEXT_OPTIONS;
      p[1]->error = error_node->errors[error1];
    }
  if (PREDICT_FALSE (error2 != IP4_ERROR_NONE))
    {
      if (error2 == IP4_ERROR_TIME_EXPIRED)
	{
	  icmp4_error_set_vnet_buffer (p[2], ICMP4_time_exceeded,
				       ICMP4_time_exceeded_ttl_exceeded_in_transit,
				       0);
	  next[2] = IP4_INPUT_NEXT_ICMP_ERROR;
	}
      else
	next[2] = error2 != IP4_ERROR_OPTIONS ?
	  IP4_INPUT_NEXT_DROP : IP4_INPUT_NEXT_OPTIONS;
      p[2]->error = error_node->errors[error2];
    }
  if (PREDICT_FALSE (error3 != IP4_ERROR_NONE))
    {
      if (error3 == IP4_ERROR_TIME_EXPIRED)
	{
	  icmp4_error_set_vnet_buffer (p[3], ICMP4_time_exceeded,
				       ICMP4_time_exceeded_ttl_exceeded_in_transit,
				       0);
	  next[3] = IP4_INPUT_NEXT_ICMP_ERROR;
	}
      else
	next[3] = error3 != IP4_ERROR_OPTIONS ?
	  IP4_INPUT_NEXT_DROP : IP4_INPUT_NEXT_OPTIONS;
      p[3]->error = error_node->errors[error3];
    }
}

always_inline void
ip4_input_check_x2 (vlib_main_t * vm,
		    vlib_node_runtime_t * error_node,
		    vlib_buffer_t * p0, vlib_buffer_t * p1,
		    ip4_header_t * ip0, ip4_header_t * ip1,
		    u32 * next0, u32 * next1, int verify_checksum)
{
  u8 error0, error1;
  u32 ip_len0, cur_len0;
  u32 ip_len1, cur_len1;
  i32 len_diff0, len_diff1;

  error0 = error1 = IP4_ERROR_NONE;

  check_ver_opt_csum (ip0, &error0, verify_checksum);
  check_ver_opt_csum (ip1, &error1, verify_checksum);

  if (PREDICT_FALSE (ip0->ttl < 1))
    error0 = IP4_ERROR_TIME_EXPIRED;
  if (PREDICT_FALSE (ip1->ttl < 1))
    error1 = IP4_ERROR_TIME_EXPIRED;

  /* Drop fragmentation offset 1 packets. */
  error0 = ip4_get_fragment_offset (ip0) == 1 ?
    IP4_ERROR_FRAGMENT_OFFSET_ONE : error0;
  error1 = ip4_get_fragment_offset (ip1) == 1 ?
    IP4_ERROR_FRAGMENT_OFFSET_ONE : error1;

  /* Verify lengths. */
  ip_len0 = clib_net_to_host_u16 (ip0->length);
  ip_len1 = clib_net_to_host_u16 (ip1->length);

  /* IP length must be at least minimal IP header. */
  error0 = ip_len0 < sizeof (ip0[0]) ? IP4_ERROR_TOO_SHORT : error0;
  error1 = ip_len1 < sizeof (ip1[0]) ? IP4_ERROR_TOO_SHORT : error1;

  cur_len0 = vlib_buffer_length_in_chain (vm, p0);
  cur_len1 = vlib_buffer_length_in_chain (vm, p1);

  len_diff0 = cur_len0 - ip_len0;
  len_diff1 = cur_len1 - ip_len1;

  error0 = len_diff0 < 0 ? IP4_ERROR_BAD_LENGTH : error0;
  error1 = len_diff1 < 0 ? IP4_ERROR_BAD_LENGTH : error1;

  if (PREDICT_FALSE (error0 != IP4_ERROR_NONE))
    {
      if (error0 == IP4_ERROR_TIME_EXPIRED)
	{
	  icmp4_error_set_vnet_buffer (p0, ICMP4_time_exceeded,
				       ICMP4_time_exceeded_ttl_exceeded_in_transit,
				       0);
	  *next0 = IP4_INPUT_NEXT_ICMP_ERROR;
	}
      else
	*next0 = error0 != IP4_ERROR_OPTIONS ?
	  IP4_INPUT_NEXT_DROP : IP4_INPUT_NEXT_OPTIONS;
      p0->error = error_node->errors[error0];
    }
  if (PREDICT_FALSE (error1 != IP4_ERROR_NONE))
    {
      if (error1 == IP4_ERROR_TIME_EXPIRED)
	{
	  icmp4_error_set_vnet_buffer (p1, ICMP4_time_exceeded,
				       ICMP4_time_exceeded_ttl_exceeded_in_transit,
				       0);
	  *next1 = IP4_INPUT_NEXT_ICMP_ERROR;
	}
      else
	*next1 = error1 != IP4_ERROR_OPTIONS ?
	  IP4_INPUT_NEXT_DROP : IP4_INPUT_NEXT_OPTIONS;
      p1->error = error_node->errors[error1];
    }
}

always_inline void
ip4_input_check_x1 (vlib_main_t * vm,
		    vlib_node_runtime_t * error_node,
		    vlib_buffer_t * p0,
		    ip4_header_t * ip0, u32 * next0, int verify_checksum)
{
  u32 ip_len0, cur_len0;
  i32 len_diff0;
  u8 error0;

  error0 = IP4_ERROR_NONE;

  check_ver_opt_csum (ip0, &error0, verify_checksum);

  if (PREDICT_FALSE (ip0->ttl < 1))
    error0 = IP4_ERROR_TIME_EXPIRED;

  /* Drop fragmentation offset 1 packets. */
  error0 = ip4_get_fragment_offset (ip0) == 1 ?
    IP4_ERROR_FRAGMENT_OFFSET_ONE : error0;

  /* Verify lengths. */
  ip_len0 = clib_net_to_host_u16 (ip0->length);

  /* IP length must be at least minimal IP header. */
  error0 = ip_len0 < sizeof (ip0[0]) ? IP4_ERROR_TOO_SHORT : error0;

  cur_len0 = vlib_buffer_length_in_chain (vm, p0);

  len_diff0 = cur_len0 - ip_len0;

  error0 = len_diff0 < 0 ? IP4_ERROR_BAD_LENGTH : error0;

  if (PREDICT_FALSE (error0 != IP4_ERROR_NONE))
    {
      if (error0 == IP4_ERROR_TIME_EXPIRED)
	{
	  icmp4_error_set_vnet_buffer (p0, ICMP4_time_exceeded,
				       ICMP4_time_exceeded_ttl_exceeded_in_transit,
				       0);
	  *next0 = IP4_INPUT_NEXT_ICMP_ERROR;
	}
      else
	*next0 = error0 != IP4_ERROR_OPTIONS ?
	  IP4_INPUT_NEXT_DROP : IP4_INPUT_NEXT_OPTIONS;
      p0->error = error_node->errors[error0];
    }
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

#endif
