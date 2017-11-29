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

#include "vom/tap_interface.hpp"
#include "vom/tap_interface_cmds.hpp"

#include <vapi/vpe.api.vapi.hpp>

namespace VOM {
tap_interface::event_handler tap_interface::m_evh;

/**
 * Construct a new object matching the desried state
 */
tap_interface::tap_interface(const std::string& name,
                             admin_state_t state,
                             route::prefix_t prefix)
  : interface(name, type_t::TAP, state)
  , m_prefix(prefix)
  , m_l2_address(l2_address_t::ZERO)
{
}

tap_interface::tap_interface(const std::string& name,
                             admin_state_t state,
                             route::prefix_t prefix,
                             const l2_address_t& l2_address)
  : interface(name, type_t::TAP, state)
  , m_prefix(prefix)
  , m_l2_address(l2_address)
{
}

tap_interface::~tap_interface()
{
  sweep();
  release();
}

tap_interface::tap_interface(const tap_interface& o)
  : interface(o)
  , m_prefix(o.m_prefix)
  , m_l2_address(o.m_l2_address)
{
}

std::queue<cmd*>&
tap_interface::mk_create_cmd(std::queue<cmd*>& q)
{
  q.push(
    new tap_interface_cmds::create_cmd(m_hdl, name(), m_prefix, m_l2_address));

  return (q);
}

std::queue<cmd*>&
tap_interface::mk_delete_cmd(std::queue<cmd*>& q)
{
  q.push(new tap_interface_cmds::delete_cmd(m_hdl));

  return (q);
}

std::shared_ptr<tap_interface>
tap_interface::singular() const
{
  return std::dynamic_pointer_cast<tap_interface>(singular_i());
}

std::shared_ptr<interface>
tap_interface::singular_i() const
{
  return m_db.find_or_add(name(), *this);
}

void
tap_interface::event_handler::handle_populate(const client_db::key_t& key)
{
  /*
   * dump VPP current states
   */
  std::shared_ptr<tap_interface_cmds::dump_cmd> cmd =
    std::make_shared<tap_interface_cmds::dump_cmd>();

  HW::enqueue(cmd);
  HW::write();

  for (auto& record : *cmd) {
    auto& payload = record.get_payload();

    std::string name = reinterpret_cast<const char*>(payload.dev_name);

    tap_interface itf(name, interface::admin_state_t::UP,
                      route::prefix_t::ZERO);

    VOM_LOG(log_level_t::DEBUG) << "tap-dump: " << itf.to_string();

    /*
     * Write each of the discovered interfaces into the OM,
     * but disable the HW Command q whilst we do, so that no
     * commands are sent to VPP
     */
    OM::commit(key, itf);
  }
}

tap_interface::event_handler::event_handler()
{
  OM::register_listener(this);
  inspect::register_handler({ "tap" }, "tap_interfaces", this);
}

void
tap_interface::event_handler::handle_replay()
{
  m_db.replay();
}

dependency_t
tap_interface::event_handler::order() const
{
  return (dependency_t::INTERFACE);
}

void
tap_interface::event_handler::show(std::ostream& os)
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
