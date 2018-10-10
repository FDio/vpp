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

#include "vom/gbp_endpoint_group.hpp"
#include "vom/gbp_endpoint_group_cmds.hpp"
#include "vom/singular_db_funcs.hpp"

namespace VOM {

singular_db<gbp_endpoint_group::key_t, gbp_endpoint_group>
  gbp_endpoint_group::m_db;

gbp_endpoint_group::event_handler gbp_endpoint_group::m_evh;

gbp_endpoint_group::gbp_endpoint_group(epg_id_t epg_id,
                                       const interface& itf,
                                       const gbp_route_domain& rd,
                                       const gbp_bridge_domain& bd)
  : m_hw(false)
  , m_epg_id(epg_id)
  , m_itf(itf.singular())
  , m_rd(rd.singular())
  , m_bd(bd.singular())
{
}

gbp_endpoint_group::gbp_endpoint_group(const gbp_endpoint_group& epg)
  : m_hw(epg.m_hw)
  , m_epg_id(epg.m_epg_id)
  , m_itf(epg.m_itf)
  , m_rd(epg.m_rd)
  , m_bd(epg.m_bd)
{
}

gbp_endpoint_group::~gbp_endpoint_group()
{
  sweep();
  m_db.release(key(), this);
}

const gbp_endpoint_group::key_t
gbp_endpoint_group::key() const
{
  return (m_epg_id);
}

epg_id_t
gbp_endpoint_group::id() const
{
  return (m_epg_id);
}

bool
gbp_endpoint_group::operator==(const gbp_endpoint_group& gg) const
{
  return (key() == gg.key() && (m_itf == gg.m_itf) && (m_rd == gg.m_rd) &&
          (m_bd == gg.m_bd));
}

void
gbp_endpoint_group::sweep()
{
  if (m_hw) {
    HW::enqueue(new gbp_endpoint_group_cmds::delete_cmd(m_hw, m_epg_id));
  }
  HW::write();
}

void
gbp_endpoint_group::replay()
{
  if (m_hw) {
    HW::enqueue(new gbp_endpoint_group_cmds::create_cmd(
      m_hw, m_epg_id, m_bd->id(), m_rd->id(), m_itf->handle()));
  }
}

std::string
gbp_endpoint_group::to_string() const
{
  std::ostringstream s;
  s << "gbp-endpoint-group:["
    << "epg:" << m_epg_id << ", " << m_itf->to_string() << ", "
    << m_bd->to_string() << ", " << m_rd->to_string() << "]";

  return (s.str());
}

void
gbp_endpoint_group::update(const gbp_endpoint_group& r)
{
  if (rc_t::OK != m_hw.rc()) {
    HW::enqueue(new gbp_endpoint_group_cmds::create_cmd(
      m_hw, m_epg_id, m_bd->id(), m_rd->id(), m_itf->handle()));
  }
}

std::shared_ptr<gbp_endpoint_group>
gbp_endpoint_group::find_or_add(const gbp_endpoint_group& temp)
{
  return (m_db.find_or_add(temp.key(), temp));
}

std::shared_ptr<gbp_endpoint_group>
gbp_endpoint_group::find(const key_t& k)
{
  return (m_db.find(k));
}

std::shared_ptr<gbp_endpoint_group>
gbp_endpoint_group::singular() const
{
  return find_or_add(*this);
}

void
gbp_endpoint_group::dump(std::ostream& os)
{
  db_dump(m_db, os);
}

gbp_endpoint_group::event_handler::event_handler()
{
  OM::register_listener(this);
  inspect::register_handler({ "gbp-endpoint-group" }, "GBP Endpoint_Groups",
                            this);
}

void
gbp_endpoint_group::event_handler::handle_replay()
{
  m_db.replay();
}

void
gbp_endpoint_group::event_handler::handle_populate(const client_db::key_t& key)
{
  std::shared_ptr<gbp_endpoint_group_cmds::dump_cmd> cmd =
    std::make_shared<gbp_endpoint_group_cmds::dump_cmd>();

  HW::enqueue(cmd);
  HW::write();

  for (auto& record : *cmd) {
    auto& payload = record.get_payload();

    std::shared_ptr<interface> itf =
      interface::find(payload.epg.uplink_sw_if_index);
    std::shared_ptr<gbp_route_domain> rd =
      gbp_route_domain::find(payload.epg.rd_id);
    std::shared_ptr<gbp_bridge_domain> bd =
      gbp_bridge_domain::find(payload.epg.bd_id);

    VOM_LOG(log_level_t::DEBUG) << "data: [" << payload.epg.uplink_sw_if_index
                                << ", " << payload.epg.rd_id << ", "
                                << payload.epg.bd_id << "]";

    if (itf && bd && rd) {
      gbp_endpoint_group gbpe(payload.epg.epg_id, *itf, *rd, *bd);
      OM::commit(key, gbpe);

      VOM_LOG(log_level_t::DEBUG) << "read: " << gbpe.to_string();
    }
  }
}

dependency_t
gbp_endpoint_group::event_handler::order() const
{
  return (dependency_t::ACL);
}

void
gbp_endpoint_group::event_handler::show(std::ostream& os)
{
  db_dump(m_db, os);
}
} // namespace VOM

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */
