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

#include <boost/asio/ip/address.hpp>
#include <vom/neighbour.hpp>
#include <vom/prefix.hpp>
#include <vom/types.hpp>

#include <vapi/ip.api.vapi.hpp>
#include <vapi/ip_neighbor.api.vapi.hpp>

namespace VOM {

struct invalid_decode
{
  invalid_decode(const std::string reason);
  const std::string reason;
};

typedef boost::asio::ip::address ip_address_t;

vapi_enum_ip_neighbor_flags to_api(const neighbour::flags_t& f);
const neighbour::flags_t from_api(vapi_enum_ip_neighbor_flags f);

void to_api(const ip_address_t& a, vapi_type_address& v);
void to_api(const boost::asio::ip::address_v4& a, vapi_type_ip4_address& v);
void to_api(const boost::asio::ip::address_v6& a, vapi_type_ip6_address& v);
void to_api(const boost::asio::ip::address& a,
            vapi_union_address_union& u,
            vapi_enum_address_family& af);
void to_api(const boost::asio::ip::address& a, vapi_union_address_union& u);
vapi_enum_address_family to_api(const l3_proto_t p);

boost::asio::ip::address_v4 from_api(const vapi_type_ip4_address& v);
boost::asio::ip::address_v6 from_api(const vapi_type_ip6_address& v);
ip_address_t from_api(const vapi_type_address& v);
ip_address_t from_api(const vapi_union_address_union& u,
                      vapi_enum_address_family af);
ip_address_t from_api(const vapi_union_address_union& u,
                      vapi_enum_fib_path_nh_proto proto);

void to_api(const mac_address_t& a, vapi_type_mac_address& m);

mac_address_t from_api(const vapi_type_mac_address& v);

route::prefix_t from_api(const vapi_type_prefix&);
route::mprefix_t from_api(const vapi_type_mprefix&);

vapi_type_prefix to_api(const route::prefix_t&);
vapi_type_mprefix to_api(const route::mprefix_t&);

vapi_enum_fib_path_nh_proto to_api(const nh_proto_t&);
const nh_proto_t& from_api(vapi_enum_fib_path_nh_proto);

}; // VOM

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */
