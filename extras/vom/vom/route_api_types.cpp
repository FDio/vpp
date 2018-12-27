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

#include <vom/route.hpp>
#include <vom/route_api_types.hpp>

namespace VOM {

void
to_vpp(const route::path& p, vapi_payload_ip_add_del_route& payload)
{
  payload.is_drop = 0;
  payload.is_unreach = 0;
  payload.is_prohibit = 0;
  payload.is_local = 0;
  payload.is_classify = 0;
  payload.is_multipath = 0;
  payload.is_resolve_host = 0;
  payload.is_resolve_attached = 0;

  if (route::path::flags_t::DVR & p.flags()) {
    payload.is_dvr = 1;
  }

  if (route::path::special_t::STANDARD == p.type()) {
    uint8_t path_v6;
    to_bytes(p.nh(), &path_v6, payload.next_hop_address);

    if (p.rd()) {
      payload.next_hop_table_id = p.rd()->table_id();
    }
    if (p.itf()) {
      payload.next_hop_sw_if_index = p.itf()->handle().value();
    }
  } else if (route::path::special_t::DROP == p.type()) {
    payload.is_drop = 1;
  } else if (route::path::special_t::UNREACH == p.type()) {
    payload.is_unreach = 1;
  } else if (route::path::special_t::PROHIBIT == p.type()) {
    payload.is_prohibit = 1;
  } else if (route::path::special_t::LOCAL == p.type()) {
    payload.is_local = 1;
  }
  payload.next_hop_weight = p.weight();
  payload.next_hop_preference = p.preference();
  payload.next_hop_via_label = 0;
  payload.classify_table_index = 0;
}

void
to_vpp(const route::path& p, vapi_payload_ip_mroute_add_del& payload)
{
  if (route::path::special_t::STANDARD == p.type()) {
    uint8_t path_v6;
    to_bytes(p.nh(), &path_v6, payload.nh_address);

    if (p.itf()) {
      payload.next_hop_sw_if_index = p.itf()->handle().value();
    }

    payload.next_hop_afi = p.nh_proto();
  }
}

route::path
from_vpp(const vapi_type_fib_path& p, const nh_proto_t& nhp)
{
  if (p.is_local) {
    return route::path(route::path::special_t::LOCAL);
  } else if (p.is_drop) {
    return route::path(route::path::special_t::DROP);
  } else if (p.is_unreach) {
    return route::path(route::path::special_t::UNREACH);
  } else if (p.is_prohibit) {
    return route::path(route::path::special_t::PROHIBIT);
  } else {
    boost::asio::ip::address address =
      from_bytes(nh_proto_t::IPV6 == nhp, p.next_hop);
    std::shared_ptr<interface> itf = interface::find(p.sw_if_index);
    if (itf) {
      if (p.is_dvr) {
        return route::path(*itf, nhp, route::path::flags_t::DVR, p.weight,
                           p.preference);
      } else {
        return route::path(address, *itf, p.weight, p.preference);
      }
    } else {
      std::shared_ptr<route_domain> rd = route_domain::find(p.table_id);
      if (rd) {
        return route::path(*rd, address, p.weight, p.preference);
      }
    }
  }

  VOM_LOG(log_level_t::ERROR) << "cannot decode: ";

  return route::path(route::path::special_t::DROP);
}
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */
