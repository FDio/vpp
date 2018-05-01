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

invalid_decode::invalid_decode(const std::string reason):
    reason(reason)
{
}

static vapi_type_ip4_address
to_api(const boost::asio::ip::address_v4& a)
{
  vapi_type_ip4_address v;

  std::copy_n(a.to_bytes().data(), 4, v.address);

  return v;
}

static vapi_type_ip6_address
to_api(const boost::asio::ip::address_v6& a)
{
  vapi_type_ip6_address v;

  std::copy_n(a.to_bytes().data(), 16, v.address);

  return v;
}

vapi_type_address
to_api(const ip_address_t& a)
{
  if (a.is_v4()) {
    vapi_type_address v = {
      .af = ADDRESS_IP4,
      .un =
        {
          .ip4 = to_api(a.to_v4()),
        },
    };
    return (v);
  } else {
    vapi_type_address v = {
      .af = ADDRESS_IP6,
      .un =
        {
          .ip6 = to_api(a.to_v6()),
        },
    };
    return (v);
  }
}

ip_address_t
from_api(const vapi_type_address& v)
{
  boost::asio::ip::address addr;

  if (ADDRESS_IP6 == v.af) {
    std::array<uint8_t, 16> a;
    std::copy(v.un.ip6.address, v.un.ip6.address + 16, std::begin(a));
    boost::asio::ip::address_v6 v6(a);
    addr = v6;
  } else {
    std::array<uint8_t, 4> a;
    std::copy(v.un.ip6.address, v.un.ip6.address + 4, std::begin(a));
    boost::asio::ip::address_v4 v4(a);
    addr = v4;
  }

  return addr;
}

vapi_type_mac_address
to_api(const mac_address_t& a)
{
  vapi_type_mac_address v;

  std::copy(std::begin(a.bytes), std::end(a.bytes), v.bytes);

  return (v);
}

mac_address_t
from_api(const vapi_type_mac_address& v)
{
  return mac_address_t(v.bytes);
}

route::prefix_t
from_api(const vapi_type_prefix& v)
{
  return route::prefix_t(from_api(v.address), v.address_length);
}

vapi_type_prefix
to_api(const route::prefix_t& p)
{
  vapi_type_prefix v = {
    .address = to_api(p.address()), .address_length = p.mask_width(),
  };

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

}; // VOM

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */
