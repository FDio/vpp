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
#include <vom/route.hpp>
#include <vom/route_api_types.hpp>

namespace VOM {

const route::itf_flags_t&
from_api(vapi_enum_mfib_itf_flags val)
{
  if (route::itf_flags_t::ACCEPT == val)
    return route::itf_flags_t::ACCEPT;
  else
    return route::itf_flags_t::FORWARD;
}

vapi_enum_mfib_itf_flags
to_api(const route::itf_flags_t& in)
{
  vapi_enum_mfib_itf_flags out = MFIB_API_ITF_FLAG_NONE;

  if (route::itf_flags_t::ACCEPT & in)
    out = static_cast<vapi_enum_mfib_itf_flags>(out | MFIB_API_ITF_FLAG_ACCEPT);
  if (route::itf_flags_t::FORWARD & in)
    out =
      static_cast<vapi_enum_mfib_itf_flags>(out | MFIB_API_ITF_FLAG_FORWARD);

  return (out);
}

void
to_api(const route::path& p, vapi_type_fib_path& payload)
{
  payload.flags = FIB_API_PATH_FLAG_NONE;
  payload.proto = to_api(p.nh_proto());
  payload.sw_if_index = ~0;

  if (route::path::flags_t::DVR & p.flags()) {
    payload.type = FIB_API_PATH_TYPE_DVR;
  } else if (route::path::special_t::STANDARD == p.type()) {
    to_api(p.nh(), payload.nh.address);

    if (p.rd()) {
      payload.table_id = p.rd()->table_id();
    }
    if (p.itf()) {
      payload.sw_if_index = p.itf()->handle().value();
    }
  } else if (route::path::special_t::DROP == p.type()) {
    payload.type = FIB_API_PATH_TYPE_DROP;
  } else if (route::path::special_t::UNREACH == p.type()) {
    payload.type = FIB_API_PATH_TYPE_ICMP_UNREACH;
  } else if (route::path::special_t::PROHIBIT == p.type()) {
    payload.type = FIB_API_PATH_TYPE_ICMP_PROHIBIT;
  } else if (route::path::special_t::LOCAL == p.type()) {
    payload.type = FIB_API_PATH_TYPE_LOCAL;
  }

  payload.weight = p.weight();
  payload.preference = p.preference();
  payload.n_labels = 0;
}

route::path
from_api(const vapi_type_fib_path& p)
{
  switch (p.type) {
    case FIB_API_PATH_TYPE_DVR: {
      std::shared_ptr<interface> itf = interface::find(p.sw_if_index);
      if (!itf)
        throw invalid_decode("fib-path deocde no interface:" +
                             std::to_string(p.sw_if_index));

      return (route::path(*itf, from_api(p.proto), route::path::flags_t::DVR,
                          p.weight, p.preference));
    }
    case FIB_API_PATH_TYPE_NORMAL: {
      boost::asio::ip::address address = from_api(p.nh.address, p.proto);
      std::shared_ptr<interface> itf = interface::find(p.sw_if_index);
      if (itf) {
        return (route::path(address, *itf, p.weight, p.preference));
      } else {
        std::shared_ptr<route_domain> rd = route_domain::find(p.table_id);

        if (!rd)
          throw invalid_decode("fib-path deocde no route-domain:" +
                               std::to_string(p.table_id));

        return (route::path(*rd, address, p.weight, p.preference));
      }
    }
    case FIB_API_PATH_TYPE_LOCAL:
      return (route::path(route::path::special_t::LOCAL));
    case FIB_API_PATH_TYPE_DROP:
      return (route::path(route::path::special_t::DROP));
    case FIB_API_PATH_TYPE_ICMP_UNREACH:
      return (route::path(route::path::special_t::PROHIBIT));
    case FIB_API_PATH_TYPE_ICMP_PROHIBIT:
      return (route::path(route::path::special_t::UNREACH));

    case FIB_API_PATH_TYPE_UDP_ENCAP:
    case FIB_API_PATH_TYPE_BIER_IMP:
    case FIB_API_PATH_TYPE_SOURCE_LOOKUP:
    case FIB_API_PATH_TYPE_INTERFACE_RX:
    case FIB_API_PATH_TYPE_CLASSIFY:
      // not done yet
      break;
  }
  return (route::path(route::path::special_t::DROP));
};

vapi_enum_ip_dscp
to_api(const ip_dscp_t& d)
{
  return static_cast<vapi_enum_ip_dscp>((int)d);
}
const ip_dscp_t&
from_api(vapi_enum_ip_dscp d)
{
  switch (d) {
    case IP_API_DSCP_CS0:
      return ip_dscp_t::DSCP_CS0;
    case IP_API_DSCP_CS1:
      return ip_dscp_t::DSCP_CS1;
    case IP_API_DSCP_CS2:
      return ip_dscp_t::DSCP_CS2;
    case IP_API_DSCP_CS3:
      return ip_dscp_t::DSCP_CS3;
    case IP_API_DSCP_CS4:
      return ip_dscp_t::DSCP_CS4;
    case IP_API_DSCP_CS5:
      return ip_dscp_t::DSCP_CS5;
    case IP_API_DSCP_CS6:
      return ip_dscp_t::DSCP_CS6;
    case IP_API_DSCP_CS7:
      return ip_dscp_t::DSCP_CS7;
    case IP_API_DSCP_EF:
      return ip_dscp_t::DSCP_EF;
    case IP_API_DSCP_AF11:
      return ip_dscp_t::DSCP_AF11;
    case IP_API_DSCP_AF12:
      return ip_dscp_t::DSCP_AF12;
    case IP_API_DSCP_AF13:
      return ip_dscp_t::DSCP_AF13;
    case IP_API_DSCP_AF21:
      return ip_dscp_t::DSCP_AF21;
    case IP_API_DSCP_AF22:
      return ip_dscp_t::DSCP_AF22;
    case IP_API_DSCP_AF23:
      return ip_dscp_t::DSCP_AF23;
    case IP_API_DSCP_AF31:
      return ip_dscp_t::DSCP_AF31;
    case IP_API_DSCP_AF32:
      return ip_dscp_t::DSCP_AF32;
    case IP_API_DSCP_AF33:
      return ip_dscp_t::DSCP_AF33;
    case IP_API_DSCP_AF41:
      return ip_dscp_t::DSCP_AF41;
    case IP_API_DSCP_AF42:
      return ip_dscp_t::DSCP_AF42;
    case IP_API_DSCP_AF43:
      return ip_dscp_t::DSCP_AF43;
  }

  return ip_dscp_t::DSCP_CS0;
}

}; // namespace VOM

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */
