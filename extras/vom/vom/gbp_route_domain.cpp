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

#include "vom/gbp_route_domain.hpp"
#include "vom/gbp_route_domain_cmds.hpp"
#include "vom/interface.hpp"
#include "vom/l2_binding.hpp"
#include "vom/singular_db_funcs.hpp"

namespace VOM {

/**
 * A DB of al the interfaces, key on the name
 */
singular_db<uint32_t, gbp_route_domain> gbp_route_domain::m_db;

gbp_route_domain::event_handler gbp_route_domain::m_evh;

/**
 * Construct a new object matching the desried state
 */
gbp_route_domain::gbp_route_domain(const gbp_route_domain& rd)
  : m_id(rd.id())
  , m_rd(rd.m_rd)
{
}

gbp_route_domain::gbp_route_domain(const route_domain& rd,
                                   const interface& ip4_uu_fwd,
                                   const interface& ip6_uu_fwd)
  : m_id(rd.table_id())
  , m_rd(rd.singular())
  , m_ip4_uu_fwd(ip4_uu_fwd.singular())
  , m_ip6_uu_fwd(ip6_uu_fwd.singular())
{
}

gbp_route_domain::gbp_route_domain(const route_domain& rd)
  : m_id(rd.table_id())
  , m_rd(rd.singular())
{
}

const gbp_route_domain::key_t
gbp_route_domain::key() const
{
  return (m_rd->key());
}

uint32_t
gbp_route_domain::id() const
{
  return (m_rd->table_id());
}

bool
gbp_route_domain::operator==(const gbp_route_domain& b) const
{
  bool equal = true;

  if (m_ip4_uu_fwd && b.m_ip4_uu_fwd)
    equal &= (m_ip4_uu_fwd->key() == b.m_ip4_uu_fwd->key());
  else if (!m_ip4_uu_fwd && !b.m_ip4_uu_fwd)
    ;
  else
    equal = false;

  if (m_ip6_uu_fwd && b.m_ip6_uu_fwd)
    equal &= (m_ip6_uu_fwd->key() == b.m_ip6_uu_fwd->key());
  else if (!m_ip6_uu_fwd && !b.m_ip6_uu_fwd)
    ;
  else
    equal = false;

  return ((m_rd->key() == b.m_rd->key()) && equal);
}

void
gbp_route_domain::sweep()
{
  if (rc_t::OK == m_id.rc()) {
    HW::enqueue(new gbp_route_domain_cmds::delete_cmd(m_id));
  }
  HW::write();
}

void
gbp_route_domain::replay()
{
  if (rc_t::OK == m_id.rc()) {
    if (m_ip4_uu_fwd && m_ip6_uu_fwd)
      HW::enqueue(new gbp_route_domain_cmds::create_cmd(
        m_id, m_ip4_uu_fwd->handle(), m_ip6_uu_fwd->handle()));
    else
      HW::enqueue(new gbp_route_domain_cmds::create_cmd(m_id, handle_t::INVALID,
                                                        handle_t::INVALID));
  }
}

gbp_route_domain::~gbp_route_domain()
{
  sweep();

  // not in the DB anymore.
  m_db.release(m_id.data(), this);
}

std::string
gbp_route_domain::to_string() const
{
  std::ostringstream s;
  s << "gbp-route-domain:[" << m_rd->to_string() << "]";

  return (s.str());
}

std::shared_ptr<gbp_route_domain>
gbp_route_domain::find(const key_t& key)
{
  return (m_db.find(key));
}

void
gbp_route_domain::update(const gbp_route_domain& desired)
{
  /*
   * the desired state is always that the interface should be created
   */
  if (rc_t::OK != m_id.rc()) {
    if (m_ip4_uu_fwd && m_ip6_uu_fwd)
      HW::enqueue(new gbp_route_domain_cmds::create_cmd(
        m_id, m_ip4_uu_fwd->handle(), m_ip6_uu_fwd->handle()));
    else
      HW::enqueue(new gbp_route_domain_cmds::create_cmd(m_id, handle_t::INVALID,
                                                        handle_t::INVALID));
  }
}

std::shared_ptr<gbp_route_domain>
gbp_route_domain::find_or_add(const gbp_route_domain& temp)
{
  return (m_db.find_or_add(temp.m_id.data(), temp));
}

std::shared_ptr<gbp_route_domain>
gbp_route_domain::singular() const
{
  return find_or_add(*this);
}

void
gbp_route_domain::dump(std::ostream& os)
{
  db_dump(m_db, os);
}

void
gbp_route_domain::event_handler::handle_populate(const client_db::key_t& key)
{
  /*
   * dump VPP Route domains
   */
  std::shared_ptr<gbp_route_domain_cmds::dump_cmd> cmd =
    std::make_shared<gbp_route_domain_cmds::dump_cmd>();

  HW::enqueue(cmd);
  HW::write();

  for (auto& record : *cmd) {
    auto& payload = record.get_payload();

    std::shared_ptr<interface> ip6_uu_fwd =
      interface::find(payload.rd.ip6_uu_sw_if_index);
    std::shared_ptr<interface> ip4_uu_fwd =
      interface::find(payload.rd.ip4_uu_sw_if_index);

    if (ip6_uu_fwd && ip4_uu_fwd) {
      gbp_route_domain rd(payload.rd.rd_id, *ip4_uu_fwd, *ip6_uu_fwd);
      OM::commit(key, rd);
      VOM_LOG(log_level_t::DEBUG) << "dump: " << rd.to_string();
    } else {
      gbp_route_domain rd(payload.rd.rd_id);
      OM::commit(key, rd);
      VOM_LOG(log_level_t::DEBUG) << "dump: " << rd.to_string();
    }
  }
}

gbp_route_domain::event_handler::event_handler()
{
  OM::register_listener(this);
  inspect::register_handler({ "grd", "groute" }, "GBP Route Domains", this);
}

void
gbp_route_domain::event_handler::handle_replay()
{
  m_db.replay();
}

dependency_t
gbp_route_domain::event_handler::order() const
{
  return (dependency_t::TABLE);
}

void
gbp_route_domain::event_handler::show(std::ostream& os)
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
