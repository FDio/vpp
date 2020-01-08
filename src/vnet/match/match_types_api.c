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

#include <vnet/match/match_types_api.h>

#include <vnet/ip/ip_types_api.h>

void
match_ip_prefix_decode (const vl_api_prefix_t * in, match_ip_prefix_t * out)
{
  ip_prefix_decode2 (in, &out->mip_ip);

  if (out->mip_ip.addr.version == AF_IP4)
    ip4_preflen_to_mask (out->mip_ip.len, &ip_addr_v4 (&out->mip_mask));
  else
    ip6_preflen_to_mask (out->mip_ip.len, &ip_addr_v6 (&out->mip_mask));
}

void
match_ip_prefix_encode (const match_ip_prefix_t * in, vl_api_prefix_t * out)
{
  ip_prefix_encode2 (&in->mip_ip, out);
}

void
match_port_range_decode (const vl_api_match_port_range_t * in,
			 match_port_range_t * out)
{
  /* leave the ports in network order for faster matching */
  out->mpr_begin = in->mpr_begin;
  out->mpr_end = in->mpr_end;
}

void
match_mac_mask_decode (const vl_api_match_mac_mask_t * in,
		       match_mac_mask_t * out)
{
  mac_address_from_bytes (&out->mmm_mac, in->mmm_mac);
  mac_address_from_bytes (&out->mmm_mask, in->mmm_mask);
}

void
match_mac_mask_encode (const match_mac_mask_t * in,
		       vl_api_match_mac_mask_t * out)
{
  mac_address_to_bytes (&in->mmm_mac, out->mmm_mac);
  mac_address_to_bytes (&in->mmm_mask, out->mmm_mask);
}

int
match_type_decode (vl_api_match_type_t in, match_type_t * out)
{
  // FIXME
  *out = in;

  return (0);
}

vl_api_match_type_t
match_type_encode (match_type_t in)
{
  // FIXME
  return (in);
}

void
match_rule_mask_ip_mac_decode (const vl_api_match_mask_ip_mac_t * mmim_in,
			       match_rule_t * out)
{
  match_mask_ip_mac_t *mmim_out = &out->mr_mask_src_ip_mac;

  out->mr_type = MATCH_TYPE_MASK_SRC_IP_MAC;

  match_ip_prefix_decode (&mmim_in->mmim_ip, &mmim_out->mmim_ip);
  match_mac_mask_decode (&mmim_in->mmim_mac, &mmim_out->mmim_mac);
}

void
match_rule_mask_ip_mac_encode (const match_rule_t * in,
			       vl_api_match_mask_ip_mac_t * mmim_out)
{
  const match_mask_ip_mac_t *mmim_in = &in->mr_mask_src_ip_mac;

  match_ip_prefix_encode (&mmim_in->mmim_ip, &mmim_out->mmim_ip);
  match_mac_mask_encode (&mmim_in->mmim_mac, &mmim_out->mmim_mac);
}

int
match_rule_decode (const vl_api_match_rule_t * in, match_rule_t * out)
{
  int rv;

  rv = match_type_decode (in->mr_type, &out->mr_type);

  if (rv)
    return (rv);

  switch (out->mr_type)
    {
    case MATCH_TYPE_MASK_SRC_IP_MAC:
      match_rule_mask_ip_mac_decode (&in->mr_union.mask_ip_mac, out);
      break;
    case MATCH_TYPE_MASK_N_TUPLE:
      {
	const vl_api_match_mask_n_tuple_t *mnt_in =
	  &in->mr_union.mask_n_tuple;
	match_mask_n_tuple_t *mnt_out = &out->mr_mask_n_tuple;
	int rv;

	match_ip_prefix_decode (&mnt_in->mnt_src_ip, &mnt_out->mnt_src_ip);
	match_ip_prefix_decode (&mnt_in->mnt_dst_ip, &mnt_out->mnt_dst_ip);
	rv = ip_proto_decode (mnt_in->mnt_proto, &mnt_out->mnt_ip_proto);

	if (rv)
	  return (rv);

	match_port_range_decode (&mnt_in->mnt_src_port,
				 &mnt_out->mnt_src_port);
	match_port_range_decode (&mnt_in->mnt_dst_port,
				 &mnt_out->mnt_dst_port);

	clib_memset (&mnt_out->mnt_tcp, 0, sizeof (mnt_out->mnt_tcp));
	break;
      }
    }

  return (rv);
}

void
match_rule_encode (const match_rule_t * in, vl_api_match_rule_t * out)
{
  // FIXME
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
