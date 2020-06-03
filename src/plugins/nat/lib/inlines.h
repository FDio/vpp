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
/**
 * @brief Common NAT inline functions
 */
#ifndef included_nat_lib_inlines_h
#define included_nat_lib_inlines_h

#include <vnet/fib/ip4_fib.h>

always_inline nat_protocol_t
ip_proto_to_nat_proto (u8 ip_proto)
{
  static const nat_protocol_t lookup_table[256] = {
    [IP_PROTOCOL_TCP] = NAT_PROTOCOL_TCP,
    [IP_PROTOCOL_UDP] = NAT_PROTOCOL_UDP,
    [IP_PROTOCOL_ICMP] = NAT_PROTOCOL_ICMP,
    [IP_PROTOCOL_ICMP6] = NAT_PROTOCOL_ICMP,
  };

  return lookup_table[ip_proto];
}

static_always_inline u8
nat_proto_to_ip_proto (nat_protocol_t nat_proto)
{
  ASSERT (nat_proto <= NAT_PROTOCOL_ICMP);

  static const u8 lookup_table[256] = {
    [NAT_PROTOCOL_OTHER] = ~0,
    [NAT_PROTOCOL_TCP] = IP_PROTOCOL_TCP,
    [NAT_PROTOCOL_UDP] = IP_PROTOCOL_UDP,
    [NAT_PROTOCOL_ICMP] = IP_PROTOCOL_ICMP,
  };

  ASSERT (NAT_PROTOCOL_OTHER == nat_proto || NAT_PROTOCOL_TCP == nat_proto
	  || NAT_PROTOCOL_UDP == nat_proto || NAT_PROTOCOL_ICMP == nat_proto);

  return lookup_table[nat_proto];
}

static_always_inline u8
icmp_type_is_error_message (u8 icmp_type)
{
  switch (icmp_type)
    {
    case ICMP4_destination_unreachable:
    case ICMP4_time_exceeded:
    case ICMP4_parameter_problem:
    case ICMP4_source_quench:
    case ICMP4_redirect:
    case ICMP4_alternate_host_address:
      return 1;
    }
  return 0;
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
	      u16 mss_value_net = clib_host_to_net_u16(mss_clamping);
	      *sum =
		ip_csum_update (*sum, mss, mss_value_net, ip4_header_t,
				length);
	      clib_memcpy_fast (data + 2, &mss_value_net, 2);
	    }
	  return;
	}
    }
}

/**
 * @brief Add/del NAT address to FIB.
 *
 * Add the external NAT address to the FIB as receive entries. This ensures
 * that VPP will reply to ARP for this address and we don't need to enable
 * proxy ARP on the outside interface.
 *
 * @param addr        IPv4 address
 * @param plen        address prefix length
 * @param sw_if_index software index of the outside interface
 * @param is_add      0 = delete, 1 = add.
 */
static inline void
snat_add_del_addr_to_fib (ip4_address_t * addr, u8 p_len, u32 sw_if_index,
			  int is_add, fib_source_t fib_src)
{
  fib_prefix_t prefix = {
    .fp_len = p_len,
    .fp_proto = FIB_PROTOCOL_IP4,
    .fp_addr = {
		.ip4.as_u32 = addr->as_u32,
		},
  };
  u32 fib_index = ip4_fib_table_get_index_for_sw_if_index (sw_if_index);

  if (is_add)
    fib_table_entry_update_one_path (fib_index,
				     &prefix,
				     fib_src,
				     (FIB_ENTRY_FLAG_CONNECTED |
				      FIB_ENTRY_FLAG_LOCAL |
				      FIB_ENTRY_FLAG_EXCLUSIVE),
				     DPO_PROTO_IP4,
				     NULL,
				     sw_if_index,
				     ~0, 1, NULL, FIB_ROUTE_PATH_FLAG_NONE);
  else
    fib_table_entry_delete (fib_index, &prefix, fib_src);
}

static inline void
increment_v4_address (ip4_address_t * a)
{
  u32 v;

  v = clib_net_to_host_u32 (a->as_u32) + 1;
  a->as_u32 = clib_host_to_net_u32 (v);
}

#endif /* included_nat_lib_inlines_h__ */
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
