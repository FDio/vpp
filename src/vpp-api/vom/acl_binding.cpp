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

#include "vom/acl_binding.hpp"
#include "vom/acl_binding_cmds.hpp"

namespace VOM {
namespace ACL {
template <>
void
l2_binding::event_handler::handle_populate(const client_db::key_t& key)
{
  /*
* dump VPP Bridge domains
*/
  std::shared_ptr<binding_cmds::l2_dump_cmd> cmd(
    new binding_cmds::l2_dump_cmd());

  HW::enqueue(cmd);
  HW::write();

  for (auto& record : *cmd) {
    auto& payload = record.get_payload();

    std::shared_ptr<interface> itf = interface::find(payload.sw_if_index);

    for (int ii = 0; ii < payload.count; ii++) {
      std::shared_ptr<l2_list> acl = l2_list::find(payload.acls[ii]);

      l2_binding binding(direction_t::INPUT, *itf, *acl);

      OM::commit(key, binding);
    }
  }
}

template <>
void
l3_binding::event_handler::handle_populate(const client_db::key_t& key)
{
  std::shared_ptr<binding_cmds::l3_dump_cmd> cmd(
    new binding_cmds::l3_dump_cmd());

  HW::enqueue(cmd);
  HW::write();

  for (auto& record : *cmd) {
    auto& payload = record.get_payload();

    std::shared_ptr<interface> itf = interface::find(payload.sw_if_index);
    uint8_t n_input = payload.n_input;

    for (int ii = 0; ii < payload.count; ii++) {
      std::shared_ptr<l3_list> acl = l3_list::find(payload.acls[ii]);

      if (n_input) {
        l3_binding binding(direction_t::INPUT, *itf, *acl);
        n_input--;
        OM::commit(key, binding);
      } else {
        l3_binding binding(direction_t::OUTPUT, *itf, *acl);
        OM::commit(key, binding);
      }
    }
  }
}

template <>
void
l3_binding::update(const binding& obj)
{
  if (!m_binding) {
    HW::enqueue(new binding_cmds::l3_bind_cmd(
      m_binding, m_direction, m_itf->handle(), m_acl->handle()));
  }
  HW::write();
}

template <>
void
l3_binding::sweep(void)
{
  if (m_binding) {
    HW::enqueue(new binding_cmds::l3_unbind_cmd(
      m_binding, m_direction, m_itf->handle(), m_acl->handle()));
  }
  HW::write();
}

template <>
void
l3_binding::replay(void)
{
  if (m_binding) {
    HW::enqueue(new binding_cmds::l3_bind_cmd(
      m_binding, m_direction, m_itf->handle(), m_acl->handle()));
  }
}

template <>
void
l2_binding::update(const binding& obj)
{
  if (!m_binding) {
    HW::enqueue(new binding_cmds::l2_bind_cmd(
      m_binding, m_direction, m_itf->handle(), m_acl->handle()));
  }
  HW::write();
}

template <>
void
l2_binding::sweep(void)
{
  if (m_binding) {
    HW::enqueue(new binding_cmds::l2_unbind_cmd(
      m_binding, m_direction, m_itf->handle(), m_acl->handle()));
  }
  HW::write();
}

template <>
void
l2_binding::replay(void)
{
  if (m_binding) {
    HW::enqueue(new binding_cmds::l2_bind_cmd(
      m_binding, m_direction, m_itf->handle(), m_acl->handle()));
  }
}
};

std::ostream&
operator<<(std::ostream& os,
           const std::pair<direction_t, interface::key_type>& key)
{
  os << "[" << key.first.to_string() << " " << key.second << "]";

  return (os);
}
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */
