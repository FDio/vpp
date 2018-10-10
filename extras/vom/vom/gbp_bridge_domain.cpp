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

#include "vom/gbp_bridge_domain.hpp"
#include "vom/gbp_bridge_domain_cmds.hpp"
#include "vom/interface.hpp"
#include "vom/l2_binding.hpp"
#include "vom/singular_db_funcs.hpp"

namespace VOM {

/**
 * A DB of al the interfaces, key on the name
 */
singular_db<uint32_t, gbp_bridge_domain> gbp_bridge_domain::m_db;

gbp_bridge_domain::event_handler gbp_bridge_domain::m_evh;

/**
 * Construct a new object matching the desried state
 */
gbp_bridge_domain::gbp_bridge_domain(const bridge_domain& bd)
  : m_id(bd.id())
  , m_bd(bd.singular())
{
}

gbp_bridge_domain::gbp_bridge_domain(const bridge_domain& bd,
                                     const interface& bvi,
                                     const interface& uu_fwd)
  : m_id(bd.id())
  , m_bd(bd.singular())
  , m_bvi(bvi.singular())
  , m_uu_fwd(uu_fwd.singular())
{
}

gbp_bridge_domain::gbp_bridge_domain(const gbp_bridge_domain& bd)
  : m_id(bd.id())
  , m_bd(bd.m_bd)
{
}

const gbp_bridge_domain::key_t
gbp_bridge_domain::key() const
{
  return (m_bd->key());
}

uint32_t
gbp_bridge_domain::id() const
{
  return (m_bd->id());
}

bool
gbp_bridge_domain::operator==(const gbp_bridge_domain& b) const
{
  bool equal = true;

  if (m_bvi && b.m_bvi)
    equal &= (m_bvi->key() == b.m_bvi->key());
  else if (!m_bvi && !b.m_bvi)
    ;
  else
    equal = false;

  if (m_uu_fwd && b.m_uu_fwd)
    equal &= (m_uu_fwd->key() == b.m_uu_fwd->key());
  else if (!m_uu_fwd && !b.m_uu_fwd)
    ;
  else
    equal = false;

  return ((m_bd->key() == b.m_bd->key()) && equal);
}

void
gbp_bridge_domain::sweep()
{
  if (rc_t::OK == m_id.rc()) {
    HW::enqueue(new gbp_bridge_domain_cmds::delete_cmd(m_id));
  }
  HW::write();
}

void
gbp_bridge_domain::replay()
{
  if (rc_t::OK == m_id.rc()) {
    if (m_bvi && m_uu_fwd)
      HW::enqueue(new gbp_bridge_domain_cmds::create_cmd(m_id, m_bvi->handle(),
                                                         m_uu_fwd->handle()));
    else
      HW::enqueue(new gbp_bridge_domain_cmds::create_cmd(
        m_id, handle_t::INVALID, handle_t::INVALID));
  }
}

gbp_bridge_domain::~gbp_bridge_domain()
{
  sweep();

  // not in the DB anymore.
  m_db.release(m_id.data(), this);
}

std::string
gbp_bridge_domain::to_string() const
{
  std::ostringstream s;
  s << "gbp-bridge-domain:[" << m_bd->to_string() << "]";

  return (s.str());
}

std::shared_ptr<gbp_bridge_domain>
gbp_bridge_domain::find(const key_t& key)
{
  return (m_db.find(key));
}

void
gbp_bridge_domain::update(const gbp_bridge_domain& desired)
{
  /*
   * the desired state is always that the interface should be created
   */
  if (rc_t::OK != m_id.rc()) {
    if (m_bvi && m_uu_fwd)
      HW::enqueue(new gbp_bridge_domain_cmds::create_cmd(m_id, m_bvi->handle(),
                                                         m_uu_fwd->handle()));
    else
      HW::enqueue(new gbp_bridge_domain_cmds::create_cmd(
        m_id, handle_t::INVALID, handle_t::INVALID));
  }
}

std::shared_ptr<gbp_bridge_domain>
gbp_bridge_domain::find_or_add(const gbp_bridge_domain& temp)
{
  return (m_db.find_or_add(temp.m_id.data(), temp));
}

std::shared_ptr<gbp_bridge_domain>
gbp_bridge_domain::singular() const
{
  return find_or_add(*this);
}

void
gbp_bridge_domain::dump(std::ostream& os)
{
  db_dump(m_db, os);
}

void
gbp_bridge_domain::event_handler::handle_populate(const client_db::key_t& key)
{
  /*
   * dump VPP Bridge domains
   */
  std::shared_ptr<gbp_bridge_domain_cmds::dump_cmd> cmd =
    std::make_shared<gbp_bridge_domain_cmds::dump_cmd>();

  HW::enqueue(cmd);
  HW::write();

  for (auto& record : *cmd) {
    auto& payload = record.get_payload();

    std::shared_ptr<interface> uu_fwd =
      interface::find(payload.bd.uu_fwd_sw_if_index);
    std::shared_ptr<interface> bvi =
      interface::find(payload.bd.bvi_sw_if_index);

    if (uu_fwd && bvi) {
      gbp_bridge_domain bd(payload.bd.bd_id, *bvi, *uu_fwd);
      OM::commit(key, bd);
      VOM_LOG(log_level_t::DEBUG) << "dump: " << bd.to_string();
    } else {
      gbp_bridge_domain bd(payload.bd.bd_id);
      OM::commit(key, bd);
      VOM_LOG(log_level_t::DEBUG) << "dump: " << bd.to_string();
    }
  }
}

gbp_bridge_domain::event_handler::event_handler()
{
  OM::register_listener(this);
  inspect::register_handler({ "gbd", "gbridge" }, "GBP Bridge Domains", this);
}

void
gbp_bridge_domain::event_handler::handle_replay()
{
  m_db.replay();
}

dependency_t
gbp_bridge_domain::event_handler::order() const
{
  return (dependency_t::TABLE);
}

void
gbp_bridge_domain::event_handler::show(std::ostream& os)
{
  db_dump(m_db, os);
}
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */
