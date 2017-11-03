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
/**
 * A DB of al the interfaces, key on the name
 */
singular_db<uint32_t, bridge_domain> bridge_domain::m_db;

bridge_domain::event_handler bridge_domain::m_evh;

/**
 * Construct a new object matching the desried state
 */
bridge_domain::bridge_domain(uint32_t id)
  : m_id(id)
{
}

bridge_domain::bridge_domain(const bridge_domain& o)
  : m_id(o.m_id)
{
}

uint32_t
bridge_domain::id() const
{
  return (m_id.data());
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
    HW::enqueue(new bridge_domain_cmds::create_cmd(m_id));
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
bridge_domain::find(uint32_t id)
{
  /*
 * Loop throught the entire map looking for matching interface.
 * not the most efficient algorithm, but it will do for now. The
 * number of L3 configs is low and this is only called during bootup
 */
  std::shared_ptr<bridge_domain> bd;

  auto it = m_db.cbegin();

  while (it != m_db.cend()) {
    /*
 * The key in the DB is a pair of the interface's name and prefix.
 * If the keys match, save the L3-config
 */
    auto key = it->first;

    if (id == key) {
      bd = it->second.lock();
      break;
    }

    ++it;
  }

  return (bd);
}

void
bridge_domain::update(const bridge_domain& desired)
{
  /*
 * the desired state is always that the interface should be created
 */
  if (rc_t::OK != m_id.rc()) {
    HW::enqueue(new bridge_domain_cmds::create_cmd(m_id));
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
  std::shared_ptr<bridge_domain_cmds::dump_cmd> cmd(
    new bridge_domain_cmds::dump_cmd());

  HW::enqueue(cmd);
  HW::write();

  for (auto& record : *cmd) {
    auto& payload = record.get_payload();

    bridge_domain bd(payload.bd_id);

    VOM_LOG(log_level_t::DEBUG) << "dump: " << bd.to_string();

    /*
 * Write each of the discovered interfaces into the OM,
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
