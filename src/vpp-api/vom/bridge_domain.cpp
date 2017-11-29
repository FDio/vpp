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

#include "vom/bridge_domain.hpp"
#include "vom/bridge_domain_cmds.hpp"
#include "vom/interface.hpp"
#include "vom/l2_binding.hpp"

namespace VOM {

const bridge_domain::learning_mode_t bridge_domain::learning_mode_t::ON(1,
                                                                        "on");
const bridge_domain::learning_mode_t bridge_domain::learning_mode_t::OFF(0,
                                                                         "off");

bridge_domain::learning_mode_t::learning_mode_t(int v, const std::string& s)
  : enum_base<bridge_domain::learning_mode_t>(v, s)
{
}

/**
 * A DB of al the interfaces, key on the name
 */
singular_db<uint32_t, bridge_domain> bridge_domain::m_db;

bridge_domain::event_handler bridge_domain::m_evh;

/**
 * Construct a new object matching the desried state
 */
bridge_domain::bridge_domain(uint32_t id, const learning_mode_t& lmode)
  : m_id(id)
  , m_learning_mode(lmode)
{
}

bridge_domain::bridge_domain(const bridge_domain& o)
  : m_id(o.m_id)
  , m_learning_mode(o.m_learning_mode)
{
}

const bridge_domain::key_t&
bridge_domain::key() const
{
  return (m_id.data());
}

uint32_t
bridge_domain::id() const
{
  return (m_id.data());
}

bool
bridge_domain::operator==(const bridge_domain& b) const
{
  return (id() == b.id());
}

void
bridge_domain::sweep()
{
  if (rc_t::OK == m_id.rc()) {
    HW::enqueue(new bridge_domain_cmds::delete_cmd(m_id));
  }
  HW::write();
}

void
bridge_domain::replay()
{
  if (rc_t::OK == m_id.rc()) {
    HW::enqueue(new bridge_domain_cmds::create_cmd(m_id, m_learning_mode));
  }
}

bridge_domain::~bridge_domain()
{
  sweep();

  // not in the DB anymore.
  m_db.release(m_id.data(), this);
}

std::string
bridge_domain::to_string() const
{
  std::ostringstream s;
  s << "bridge-domain:[" << m_id.to_string() << "]";

  return (s.str());
}

std::shared_ptr<bridge_domain>
bridge_domain::find(const key_t& key)
{
  return (m_db.find(key));
}

void
bridge_domain::update(const bridge_domain& desired)
{
  /*
   * the desired state is always that the interface should be created
   */
  if (rc_t::OK != m_id.rc()) {
    HW::enqueue(new bridge_domain_cmds::create_cmd(m_id, m_learning_mode));
  }
}

std::shared_ptr<bridge_domain>
bridge_domain::find_or_add(const bridge_domain& temp)
{
  return (m_db.find_or_add(temp.m_id.data(), temp));
}

std::shared_ptr<bridge_domain>
bridge_domain::singular() const
{
  return find_or_add(*this);
}

void
bridge_domain::dump(std::ostream& os)
{
  m_db.dump(os);
}

void
bridge_domain::event_handler::handle_populate(const client_db::key_t& key)
{
  /*
   * dump VPP Bridge domains
   */
  std::shared_ptr<bridge_domain_cmds::dump_cmd> cmd =
    std::make_shared<bridge_domain_cmds::dump_cmd>();

  HW::enqueue(cmd);
  HW::write();

  for (auto& record : *cmd) {
    auto& payload = record.get_payload();

    bridge_domain bd(payload.bd_id);

    VOM_LOG(log_level_t::DEBUG) << "dump: " << bd.to_string();

    /*
     * Write each of the discovered bridge-domains into the OM,
     * but disable the HW Command q whilst we do, so that no
     * commands are sent to VPP
     */
    OM::commit(key, bd);

    /**
     * For each interface in the BD construct an l2_binding
     */
    for (unsigned int ii = 0; ii < payload.n_sw_ifs; ii++) {
      std::shared_ptr<interface> itf =
        interface::find(payload.sw_if_details[ii].sw_if_index);
      l2_binding l2(*itf, bd);
      OM::commit(key, l2);
    }
  }
}

bridge_domain::event_handler::event_handler()
{
  OM::register_listener(this);
  inspect::register_handler({ "bd", "bridge" }, "Bridge Domains", this);
}

void
bridge_domain::event_handler::handle_replay()
{
  m_db.replay();
}

dependency_t
bridge_domain::event_handler::order() const
{
  return (dependency_t::TABLE);
}

void
bridge_domain::event_handler::show(std::ostream& os)
{
  m_db.dump(os);
}
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */
