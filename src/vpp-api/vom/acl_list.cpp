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

#include "vom/acl_list.hpp"
#include "vom/logger.hpp"

namespace VOM {
namespace ACL {
template <>
void
l2_list::event_handler::handle_populate(const client_db::key_t& key)
{
  /* hack to get this function instantiated */
  m_evh.order();

  /*
* dump VPP Bridge domains
*/
  std::shared_ptr<l2_list::dump_cmd> cmd(new l2_list::dump_cmd());

  HW::enqueue(cmd);
  HW::write();

  for (auto& record : *cmd) {
    auto& payload = record.get_payload();

    const handle_t hdl(payload.acl_index);
    l2_list acl(hdl, std::string(reinterpret_cast<const char*>(payload.tag)));

    for (unsigned int ii = 0; ii < payload.count; ii++) {
      const route::prefix_t pfx(payload.r[ii].is_ipv6,
                                payload.r[ii].src_ip_addr,
                                payload.r[ii].src_ip_prefix_len);
      l2_rule rule(ii, action_t::from_int(payload.r[ii].is_permit), pfx,
                   { payload.r[ii].src_mac }, { payload.r[ii].src_mac_mask });

      acl.insert(rule);
    }
    VOM_LOG(log_level_t::DEBUG) << "dump: " << acl.to_string();

    /*
* Write each of the discovered ACLs into the OM,
* but disable the HW Command q whilst we do, so that no
* commands are sent to VPP
*/
    OM::commit(key, acl);
  }
}

template <>
void
l3_list::event_handler::handle_populate(const client_db::key_t& key)
{
  /* hack to get this function instantiated */
  m_evh.order();

  /*
* dump VPP Bridge domains
*/
  std::shared_ptr<l3_list::dump_cmd> cmd(new l3_list::dump_cmd());

  HW::enqueue(cmd);
  HW::write();

  for (auto& record : *cmd) {
    auto& payload = record.get_payload();

    const handle_t hdl(payload.acl_index);
    l3_list acl(hdl, std::string(reinterpret_cast<const char*>(payload.tag)));

    for (unsigned int ii = 0; ii < payload.count; ii++) {
      const route::prefix_t src(payload.r[ii].is_ipv6,
                                payload.r[ii].src_ip_addr,
                                payload.r[ii].src_ip_prefix_len);
      const route::prefix_t dst(payload.r[ii].is_ipv6,
                                payload.r[ii].dst_ip_addr,
                                payload.r[ii].dst_ip_prefix_len);
      l3_rule rule(ii, action_t::from_int(payload.r[ii].is_permit), src, dst);

      acl.insert(rule);
    }
    VOM_LOG(log_level_t::DEBUG) << "dump: " << acl.to_string();

    /*
* Write each of the discovered ACLs into the OM,
* but disable the HW Command q whilst we do, so that no
* commands are sent to VPP
*/
    OM::commit(key, acl);
  }
}
};
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */
