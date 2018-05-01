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
#include <vom/prefix.hpp>
#include <vom/types.hpp>

#include <vapi/ip.api.vapi.hpp>

namespace VOM {

struct invalid_decode
{
    invalid_decode(const std::string reason);
    const std::string reason;
};

typedef boost::asio::ip::address ip_address_t;

vapi_type_address to_api(const ip_address_t& a);

ip_address_t from_api(const vapi_type_address& v);

vapi_type_mac_address to_api(const mac_address_t& a);

mac_address_t from_api(const vapi_type_mac_address& v);

route::prefix_t from_api(const vapi_type_prefix&);

vapi_type_prefix to_api(const route::prefix_t&);

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
