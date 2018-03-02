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

#include "vom/bond_interface.hpp"
#include "vom/bond_interface_cmds.hpp"

#include <vapi/vpe.api.vapi.hpp>

namespace VOM {
bond_interface::event_handler bond_interface::m_evh;

/**
 * Construct a new object matching the desried state
 */
bond_interface::bond_interface(const std::string& name,
                               admin_state_t state,
                               mode_t mode,
                               lb_t lb)
  : interface(name, type_t::BOND, state)
  , m_mode(mode)
  , m_lb(lb)
  , m_l2_address(l2_address_t::ZERO)
{
}

bond_interface::bond_interface(const std::string& name,
                               admin_state_t state,
                               mode_t mode,
                               lb_t lb,
                               const l2_address_t& l2_address)
  : interface(name, type_t::BOND, state)
  , m_mode(mode)
  , m_lb(lb)
  , m_l2_address(l2_address)
{
}

bond_interface::~bond_interface()
{
  sweep();
  release();
}

bond_interface::bond_interface(const bond_interface& o)
  : interface(o)
  , m_mode(o.m_mode)
  , m_lb(o.m_lb)
  , m_l2_address(o.m_l2_address)
{
}

std::queue<cmd*>&
bond_interface::mk_create_cmd(std::queue<cmd*>& q)
{
  q.push(new bond_interface_cmds::create_cmd(m_hdl, name(), m_mode, m_lb,
                                             m_l2_address));

  return (q);
}

std::queue<cmd*>&
bond_interface::mk_delete_cmd(std::queue<cmd*>& q)
{
  q.push(new bond_interface_cmds::delete_cmd(m_hdl));

  return (q);
}

std::shared_ptr<bond_interface>
bond_interface::singular() const
{
  return std::dynamic_pointer_cast<bond_interface>(singular_i());
}

std::shared_ptr<interface>
bond_interface::singular_i() const
{
  return m_db.find_or_add(name(), *this);
}

void
bond_interface::event_handler::handle_populate(const client_db::key_t& key)
{
  /*
   * dump VPP current states
   */
  std::shared_ptr<bond_interface_cmds::dump_cmd> cmd =
    std::make_shared<bond_interface_cmds::dump_cmd>();

  HW::enqueue(cmd);
  HW::write();

  for (auto& record : *cmd) {
    auto& payload = record.get_payload();

    std::string name = reinterpret_cast<const char*>(payload.interface_name);
    bond_interface::mode_t mode =
      bond_interface::mode_t::from_numeric_val(payload.mode);
    bond_interface::lb_t lb =
      bond_interface::lb_t::from_numeric_val(payload.lb);

    bond_interface itf(name, interface::admin_state_t::UP, mode, lb);

    VOM_LOG(log_level_t::DEBUG) << "bond-dump: " << itf.to_string();

    /*
     * Write each of the discovered interfaces into the OM,
     * but disable the HW Command q whilst we do, so that no
     * commands are sent to VPP
     */
    OM::commit(key, itf);
  }
}

bond_interface::event_handler::event_handler()
{
  OM::register_listener(this);
  inspect::register_handler({ "bond-intf" }, "bond interfaces", this);
}

void
bond_interface::event_handler::handle_replay()
{
  // It will be replayed by interface handler
}

dependency_t
bond_interface::event_handler::order() const
{
  return (dependency_t::INTERFACE);
}

void
bond_interface::event_handler::show(std::ostream& os)
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
