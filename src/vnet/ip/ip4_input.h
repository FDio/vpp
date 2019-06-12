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

#include <vppinfra/vector_funcs.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>

extern char *ip4_error_strings[];

typedef enum
{
  IP4_INPUT_NEXT_DROP,
  IP4_INPUT_NEXT_PUNT,
  IP4_INPUT_NEXT_OPTIONS,
  IP4_INPUT_NEXT_LOOKUP,
  IP4_INPUT_NEXT_LOOKUP_MULTICAST,
  IP4_INPUT_NEXT_ICMP_ERROR,
  IP4_INPUT_NEXT_REASSEMBLY,
  IP4_INPUT_N_NEXT,
} ip4_input_next_t;

static_always_inline void
check_ver_opt_csum (ip4_header_t * ip, i32 * error, int verify_checksum)
{
  if (PREDICT_FALSE (ip->ip_version_and_header_length != 0x45))
    {
      if ((ip->ip_version_and_header_length & 0xf) != 5)
	{
	  *error = IP4_ERROR_OPTIONS;
	  if (verify_checksum && ip_csum (ip, ip4_header_bytes (ip)) != 0)
	    *error = IP4_ERROR_BAD_CHECKSUM;
	}
      else
	*error = IP4_ERROR_VERSION;
    }
  else
    if (PREDICT_FALSE (verify_checksum &&
		       ip_csum (ip, sizeof (ip4_header_t)) != 0))
    *error = IP4_ERROR_BAD_CHECKSUM;
}

/* *INDENT-OFF* */
const static i32x4 all_1s = { 1,1,1,1 };
const static i32x4 all_0s = { 0,0,0,0 };
const static i32x4 ip_version_and_len = { 0x45, 0x45, 0x45, 0x45 };
const static i32x4 ip_no_optnios = { 0x5, 0x5, 0x5, 0x5 };
const static i32x4 ip_len_mask = { 0x0f, 0x0f, 0x0f, 0x0f };
const static i32x4 ip_hdr_sizes = {
  sizeof(ip4_header_t),
  sizeof(ip4_header_t),
  sizeof(ip4_header_t),
  sizeof(ip4_header_t)
};
const static i32x4 err_time_exp = {
  IP4_ERROR_TIME_EXPIRED,
  IP4_ERROR_TIME_EXPIRED,
  IP4_ERROR_TIME_EXPIRED,
  IP4_ERROR_TIME_EXPIRED,
};
const static i32x4 err_frag_one = {
  IP4_ERROR_FRAGMENT_OFFSET_ONE,
  IP4_ERROR_FRAGMENT_OFFSET_ONE,
  IP4_ERROR_FRAGMENT_OFFSET_ONE,
  IP4_ERROR_FRAGMENT_OFFSET_ONE,
};
const static i32x4 err_too_short = {
  IP4_ERROR_TOO_SHORT,
  IP4_ERROR_TOO_SHORT,
  IP4_ERROR_TOO_SHORT,
  IP4_ERROR_TOO_SHORT,
};
const static i32x4 err_bad_length = {
  IP4_ERROR_BAD_LENGTH,
  IP4_ERROR_BAD_LENGTH,
  IP4_ERROR_BAD_LENGTH,
  IP4_ERROR_BAD_LENGTH,
};
const static i32x4 err_version = {
  IP4_ERROR_VERSION,
  IP4_ERROR_VERSION,
  IP4_ERROR_VERSION,
  IP4_ERROR_VERSION,
};
const static i32x4 err_options = {
  IP4_ERROR_OPTIONS,
  IP4_ERROR_OPTIONS,
  IP4_ERROR_OPTIONS,
  IP4_ERROR_OPTIONS,
};
const static i32x4 err_chksum = {
  IP4_ERROR_BAD_CHECKSUM,
  IP4_ERROR_BAD_CHECKSUM,
  IP4_ERROR_BAD_CHECKSUM,
  IP4_ERROR_BAD_CHECKSUM,
};
/* *INDENT-ON* */

always_inline void
ip4_input_check_x4 (vlib_main_t * vm,
		    vlib_node_runtime_t * error_node,
		    vlib_buffer_t ** p, ip4_header_t ** ip,
		    u16 * next, int verify_checksum)
{
  i32x4 errors, ip_lens, ip_len_errors, cur_lens, buff_len_errors, ttls,
    ttl_errors, frag_offsets, frag_errors, versions, version_errors, chksums,
    chksum_errors, option_errors;

  versions[0] = ip[0]->ip_version_and_header_length;
  versions[1] = ip[1]->ip_version_and_header_length;
  versions[2] = ip[2]->ip_version_and_header_length;
  versions[3] = ip[3]->ip_version_and_header_length;

  /* Drop if version or header length unexpected */
  version_errors = versions != ip_version_and_len;

  if (verify_checksum)
    {
      chksums[0] = ip_csum (ip[0], sizeof (ip4_header_t));
      chksums[1] = ip_csum (ip[1], sizeof (ip4_header_t));
      chksums[2] = ip_csum (ip[2], sizeof (ip4_header_t));
      chksums[3] = ip_csum (ip[3], sizeof (ip4_header_t));

      /* drop incorrect chksums */
      chksum_errors = chksums != all_0s;
    }

  ttls[0] = ip[0]->ttl;
  ttls[1] = ip[1]->ttl;
  ttls[2] = ip[2]->ttl;
  ttls[3] = ip[3]->ttl;

  /* Drop TTL expired. */
  ttl_errors = ttls < all_1s;

  frag_offsets[0] = ip4_get_fragment_offset_network_order (ip[0]);
  frag_offsets[1] = ip4_get_fragment_offset_network_order (ip[1]);
  frag_offsets[2] = ip4_get_fragment_offset_network_order (ip[2]);
  frag_offsets[3] = ip4_get_fragment_offset_network_order (ip[3]);

#if CLIB_ARCH_IS_LITTLE_ENDIAN
  frag_offsets = i32x4_byte_swap_as_u16 (frag_offsets);
#endif

  /* Drop fragmentation offset 1 packets. */
  frag_errors = frag_offsets == all_1s;

  /* Verify lengths. */
  ip_lens[0] = ip[0]->length;
  ip_lens[1] = ip[1]->length;
  ip_lens[2] = ip[2]->length;
  ip_lens[3] = ip[3]->length;

#if CLIB_ARCH_IS_LITTLE_ENDIAN
  ip_lens = i32x4_byte_swap_as_u16 (ip_lens);
#endif

  /* IP length must be at least minimal IP header. */
  ip_len_errors = ip_lens < ip_hdr_sizes;

  cur_lens[0] = vlib_buffer_length_in_chain (vm, p[0]);
  cur_lens[1] = vlib_buffer_length_in_chain (vm, p[1]);
  cur_lens[2] = vlib_buffer_length_in_chain (vm, p[2]);
  cur_lens[3] = vlib_buffer_length_in_chain (vm, p[3]);

  /* IP header legth must not be longer than the buffer length */
  buff_len_errors = ip_lens > cur_lens;

  if (verify_checksum)
    errors = buff_len_errors | ip_len_errors |
      frag_errors | ttl_errors | chksum_errors | version_errors;
  else
    errors = buff_len_errors | ip_len_errors |
      frag_errors | ttl_errors | version_errors;

  if (!i32x4_is_all_zero (errors))
    {
      /* flush out the packet with options */
      option_errors =
	((versions & ip_len_mask) != (ip_version_and_len & ip_len_mask));

      errors = i32x4_splat (IP4_ERROR_NONE);
      errors = i32x4_blend (errors, err_version, version_errors);
      errors = i32x4_blend (errors, err_options, option_errors);
      errors = i32x4_blend (errors, err_chksum, chksum_errors);
      errors = i32x4_blend (errors, err_time_exp, ttl_errors);
      errors = i32x4_blend (errors, err_frag_one, frag_errors);
      errors = i32x4_blend (errors, err_too_short, ip_len_errors);
      errors = i32x4_blend (errors, err_bad_length, buff_len_errors);

      if (PREDICT_FALSE (errors[0] != IP4_ERROR_NONE))
	{
	  if (errors[0] == IP4_ERROR_TIME_EXPIRED)
	    {
	      icmp4_error_set_vnet_buffer (p[0], ICMP4_time_exceeded,
					   ICMP4_time_exceeded_ttl_exceeded_in_transit,
					   0);
	      next[0] = IP4_INPUT_NEXT_ICMP_ERROR;
	    }
	  else
	    next[0] = errors[0] != IP4_ERROR_OPTIONS ?
	      IP4_INPUT_NEXT_DROP : IP4_INPUT_NEXT_OPTIONS;
	  p[0]->error = error_node->errors[errors[0]];
	}
      if (PREDICT_FALSE (errors[1] != IP4_ERROR_NONE))
	{
	  if (errors[1] == IP4_ERROR_TIME_EXPIRED)
	    {
	      icmp4_error_set_vnet_buffer (p[1], ICMP4_time_exceeded,
					   ICMP4_time_exceeded_ttl_exceeded_in_transit,
					   0);
	      next[1] = IP4_INPUT_NEXT_ICMP_ERROR;
	    }
	  else
	    next[1] = errors[1] != IP4_ERROR_OPTIONS ?
	      IP4_INPUT_NEXT_DROP : IP4_INPUT_NEXT_OPTIONS;
	  p[1]->error = error_node->errors[errors[1]];
	}
      if (PREDICT_FALSE (errors[2] != IP4_ERROR_NONE))
	{
	  if (errors[2] == IP4_ERROR_TIME_EXPIRED)
	    {
	      icmp4_error_set_vnet_buffer (p[2], ICMP4_time_exceeded,
					   ICMP4_time_exceeded_ttl_exceeded_in_transit,
					   0);
	      next[2] = IP4_INPUT_NEXT_ICMP_ERROR;
	    }
	  else
	    next[2] = errors[2] != IP4_ERROR_OPTIONS ?
	      IP4_INPUT_NEXT_DROP : IP4_INPUT_NEXT_OPTIONS;
	  p[2]->error = error_node->errors[errors[2]];
	}
      if (PREDICT_FALSE (errors[3] != IP4_ERROR_NONE))
	{
	  if (errors[3] == IP4_ERROR_TIME_EXPIRED)
	    {
	      icmp4_error_set_vnet_buffer (p[3], ICMP4_time_exceeded,
					   ICMP4_time_exceeded_ttl_exceeded_in_transit,
					   0);
	      next[3] = IP4_INPUT_NEXT_ICMP_ERROR;
	    }
	  else
	    next[3] = errors[3] != IP4_ERROR_OPTIONS ?
	      IP4_INPUT_NEXT_DROP : IP4_INPUT_NEXT_OPTIONS;
	  p[3]->error = error_node->errors[errors[3]];
	}
    }
}

always_inline void
ip4_input_check_x2 (vlib_main_t * vm,
		    vlib_node_runtime_t * error_node,
		    vlib_buffer_t * p0, vlib_buffer_t * p1,
		    ip4_header_t * ip0, ip4_header_t * ip1,
		    u32 * next0, u32 * next1, int verify_checksum)
{
  i32 error0, error1;
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
  i32 len_diff0, error0;

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
