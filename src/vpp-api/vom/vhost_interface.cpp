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

#include "vom/vhost_interface.hpp"
#include "vom/vhost_interface_cmds.hpp"

#include <vapi/vpe.api.vapi.hpp>

namespace VOM {
vhost_interface::event_handler vhost_interface::m_evh;

/**
 * Construct a new object matching the desried state
 */
vhost_interface::vhost_interface(const std::string& name,
                                 admin_state_t state,
                                 const std::string& tag)
  : interface(name, type_t::VHOST, state)
  , m_tag(tag)
{
}

vhost_interface::~vhost_interface()
{
  sweep();
  release();
}

vhost_interface::vhost_interface(const vhost_interface& o)
  : interface(o)
  , m_tag(o.m_tag)
{
}

std::queue<cmd*>&
vhost_interface::mk_create_cmd(std::queue<cmd*>& q)
{
  q.push(new vhost_interface_cmds::create_cmd(m_hdl, name(), m_tag));

  return (q);
}

std::queue<cmd*>&
vhost_interface::mk_delete_cmd(std::queue<cmd*>& q)
{
  q.push(new vhost_interface_cmds::delete_cmd(m_hdl));

  return (q);
}

std::shared_ptr<vhost_interface>
vhost_interface::singular() const
{
  return std::dynamic_pointer_cast<vhost_interface>(singular_i());
}

std::shared_ptr<interface>
vhost_interface::singular_i() const
{
  return m_db.find_or_add(name(), *this);
}

void
vhost_interface::event_handler::handle_populate(const client_db::key_t& key)
{
  /*
   * dump VPP current states
   */
  std::shared_ptr<vhost_interface_cmds::dump_cmd> cmd =
    std::make_shared<vhost_interface_cmds::dump_cmd>();

  HW::enqueue(cmd);
  HW::write();

  for (auto& record : *cmd) {
    auto& payload = record.get_payload();

    std::string name = reinterpret_cast<const char*>(payload.sock_filename);
    std::string tag = reinterpret_cast<const char*>(payload.interface_name);

    vhost_interface itf(name, interface::admin_state_t::UP, tag);

    VOM_LOG(log_level_t::DEBUG) << "vhost-dump: " << itf.to_string();

    /*
     * Write each of the discovered interfaces into the OM,
     * but disable the HW Command q whilst we do, so that no
     * commands are sent to VPP
     */
    OM::commit(key, itf);
  }
}

vhost_interface::event_handler::event_handler()
{
  OM::register_listener(this);
  inspect::register_handler({ "vhost" }, "vhost_interfaces", this);
}

void
vhost_interface::event_handler::handle_replay()
{
  // It will be replayed by interface handler
}

dependency_t
vhost_interface::event_handler::order() const
{
  return (dependency_t::INTERFACE);
}

void
vhost_interface::event_handler::show(std::ostream& os)
{
  // dumped by the interface handler
}

}; // namespace VOM

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */
