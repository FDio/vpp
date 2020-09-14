/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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

#ifndef __included_lib_nat_inlines_h__
#define __included_lib_nat_inlines_h__

#include <vnet/tcp/tcp_packet.h>
#include <vnet/ip/ip4_packet.h>

static inline void
increment_v4_address (ip4_address_t * a)
{
  u32 v;

  v = clib_net_to_host_u32 (a->as_u32) + 1;
  a->as_u32 = clib_host_to_net_u32 (v);
}

always_inline void
mss_clamping (u16 mss_clamping, tcp_header_t * tcp, ip_csum_t * sum)
{
  u8 *data;
  u8 opt_len, opts_len, kind;
  u16 mss;

  if (!(mss_clamping && tcp_syn (tcp)))
    return;

  opts_len = (tcp_doff (tcp) << 2) - sizeof (tcp_header_t);
  data = (u8 *) (tcp + 1);
  for (; opts_len > 0; opts_len -= opt_len, data += opt_len)
    {
      kind = data[0];

      if (kind == TCP_OPTION_EOL)
	break;
      else if (kind == TCP_OPTION_NOOP)
	{
	  opt_len = 1;
	  continue;
	}
      else
	{
	  if (opts_len < 2)
	    return;
	  opt_len = data[1];

	  if (opt_len < 2 || opt_len > opts_len)
	    return;
	}

      if (kind == TCP_OPTION_MSS)
	{
	  mss = *(u16 *) (data + 2);
	  if (clib_net_to_host_u16 (mss) > mss_clamping)
	    {
	      u16 mss_value_net = clib_host_to_net_u16 (mss_clamping);
	      *sum =
		ip_csum_update (*sum, mss, mss_value_net, ip4_header_t,
				length);
	      clib_memcpy_fast (data + 2, &mss_value_net, 2);
	    }
	  return;
	}
    }
}

#endif /* __included_lib_nat_inlines_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
