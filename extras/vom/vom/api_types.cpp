/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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

#include <vom/api_types.hpp>

namespace VOM {

vapi_enum_ip_neighbor_flags
to_api(const neighbour::flags_t& f)
{
  vapi_enum_ip_neighbor_flags out = IP_API_NEIGHBOR_FLAG_NONE;

  if (f & neighbour::flags_t::STATIC)
    out = static_cast<vapi_enum_ip_neighbor_flags>(out |
                                                   IP_API_NEIGHBOR_FLAG_STATIC);
  if (f & neighbour::flags_t::NO_FIB_ENTRY)
    out = static_cast<vapi_enum_ip_neighbor_flags>(
      out | IP_API_NEIGHBOR_FLAG_NO_FIB_ENTRY);

  return (out);
}

const neighbour::flags_t
from_api(vapi_enum_ip_neighbor_flags f)
{
  neighbour::flags_t out = neighbour::flags_t::NONE;

  if (f & IP_API_NEIGHBOR_FLAG_STATIC)
    out |= neighbour::flags_t::STATIC;
  if (f & IP_API_NEIGHBOR_FLAG_NO_FIB_ENTRY)
    out |= neighbour::flags_t::NO_FIB_ENTRY;

  return out;
}

invalid_decode::invalid_decode(const std::string reason)
  : reason(reason)
{}

void
to_api(const boost::asio::ip::address_v4& a, vapi_type_ip4_address& v)
{
  std::copy_n(std::begin(a.to_bytes()), a.to_bytes().size(), v);
}
void
to_api(const boost::asio::ip::address_v6& a, vapi_type_ip6_address& v)
{
  std::copy_n(std::begin(a.to_bytes()), a.to_bytes().size(), v);
}

void
to_api(const ip_address_t& a, vapi_type_address& v)
{
  if (a.is_v4()) {
    v.af = ADDRESS_IP4;
    memcpy(v.un.ip4, a.to_v4().to_bytes().data(), 4);
  } else {
    v.af = ADDRESS_IP6;
    memcpy(v.un.ip6, a.to_v6().to_bytes().data(), 16);
  }
}

void
to_api(const ip_address_t& a,
       vapi_union_address_union& u,
       vapi_enum_address_family& af)
{
  if (a.is_v4()) {
    af = ADDRESS_IP4;
    memcpy(u.ip4, a.to_v4().to_bytes().data(), 4);
  } else {
    af = ADDRESS_IP6;
    memcpy(u.ip6, a.to_v6().to_bytes().data(), 16);
  }
}

void
to_api(const ip_address_t& a, vapi_union_address_union& u)
{
  if (a.is_v4()) {
    memcpy(u.ip4, a.to_v4().to_bytes().data(), 4);
  } else {
    memcpy(u.ip6, a.to_v6().to_bytes().data(), 16);
  }
}

boost::asio::ip::address_v6
from_api(const vapi_type_ip6_address& v)
{
  std::array<uint8_t, 16> a;
  std::copy(v, v + 16, std::begin(a));
  boost::asio::ip::address_v6 v6(a);

  return v6;
}

boost::asio::ip::address_v4
from_api(const vapi_type_ip4_address& v)
{
  std::array<uint8_t, 4> a;
  std::copy(v, v + 4, std::begin(a));
  boost::asio::ip::address_v4 v4(a);

  return v4;
}

ip_address_t
from_api(const vapi_type_address& v)
{
  boost::asio::ip::address addr;

  if (ADDRESS_IP6 == v.af) {
    std::array<uint8_t, 16> a;
    std::copy(v.un.ip6, v.un.ip6 + 16, std::begin(a));
    boost::asio::ip::address_v6 v6(a);
    addr = v6;
  } else {
    std::array<uint8_t, 4> a;
    std::copy(v.un.ip6, v.un.ip6 + 4, std::begin(a));
    boost::asio::ip::address_v4 v4(a);
    addr = v4;
  }

  return addr;
}

ip_address_t
from_api(const vapi_union_address_union& u, vapi_enum_fib_path_nh_proto proto)
{
  boost::asio::ip::address addr;

  if (FIB_API_PATH_NH_PROTO_IP6 == proto) {
    std::array<uint8_t, 16> a;
    std::copy(u.ip6, u.ip6 + 16, std::begin(a));
    boost::asio::ip::address_v6 v6(a);
    addr = v6;
  } else if (FIB_API_PATH_NH_PROTO_IP4 == proto) {
    std::array<uint8_t, 4> a;
    std::copy(u.ip6, u.ip6 + 4, std::begin(a));
    boost::asio::ip::address_v4 v4(a);
    addr = v4;
  }

  return addr;
}

ip_address_t
from_api(const vapi_union_address_union& u, vapi_enum_address_family af)
{
  boost::asio::ip::address addr;

  if (ADDRESS_IP6 == af) {
    std::array<uint8_t, 16> a;
    std::copy(u.ip6, u.ip6 + 16, std::begin(a));
    boost::asio::ip::address_v6 v6(a);
    addr = v6;
  } else {
    std::array<uint8_t, 4> a;
    std::copy(u.ip6, u.ip6 + 4, std::begin(a));
    boost::asio::ip::address_v4 v4(a);
    addr = v4;
  }

  return addr;
}

void
to_api(const mac_address_t& a, vapi_type_mac_address& v)
{
  std::copy(std::begin(a.bytes), std::end(a.bytes), v);
}

mac_address_t
from_api(const vapi_type_mac_address& v)
{
  return mac_address_t(v);
}

route::prefix_t
from_api(const vapi_type_prefix& v)
{
  return route::prefix_t(from_api(v.address), v.len);
}

vapi_type_prefix
to_api(const route::prefix_t& p)
{
  vapi_type_prefix v;
  to_api(p.address(), v.address);
  v.len = p.mask_width();
  return v;
}

route::mprefix_t
from_api(const vapi_type_mprefix& v)
{
  return route::mprefix_t(from_api(v.src_address, v.af),
                          from_api(v.grp_address, v.af),
                          v.grp_address_length);
}

vapi_type_mprefix
to_api(const route::mprefix_t& p)
{
  vapi_enum_address_family af;
  vapi_type_mprefix v;
  to_api(p.grp_address(), v.grp_address, af);
  to_api(p.src_address(), v.src_address, af);
  v.grp_address_length = p.mask_width();
  v.af = af;
  return v;
}

vapi_enum_fib_path_nh_proto
to_api(const nh_proto_t& p)
{
  if (p == nh_proto_t::IPV4) {
    return FIB_API_PATH_NH_PROTO_IP4;
  } else if (p == nh_proto_t::IPV6) {
    return FIB_API_PATH_NH_PROTO_IP6;
  } else if (p == nh_proto_t::ETHERNET) {
    return FIB_API_PATH_NH_PROTO_ETHERNET;
  } else if (p == nh_proto_t::MPLS) {
    return FIB_API_PATH_NH_PROTO_MPLS;
  }

  return FIB_API_PATH_NH_PROTO_IP4;
}

vapi_enum_address_family
to_api(const l3_proto_t p)
{
  if (p == l3_proto_t::IPV6) {
    return ADDRESS_IP6;
  }
  return ADDRESS_IP4;
}

const nh_proto_t&
from_api(vapi_enum_fib_path_nh_proto p)
{
  switch (p) {
    case FIB_API_PATH_NH_PROTO_IP4:
      return nh_proto_t::IPV4;
    case FIB_API_PATH_NH_PROTO_IP6:
      return nh_proto_t::IPV6;
    case FIB_API_PATH_NH_PROTO_ETHERNET:
      return nh_proto_t::ETHERNET;
    case FIB_API_PATH_NH_PROTO_MPLS:
      return nh_proto_t::MPLS;
    case FIB_API_PATH_NH_PROTO_BIER:
      break;
  }

  return nh_proto_t::IPV4;
}

}; // VOM

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */
