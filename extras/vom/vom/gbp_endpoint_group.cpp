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

gbp_endpoint_group::retention_t::retention_t()
  : remote_ep_timeout(0xffffffff)
{
}
gbp_endpoint_group::retention_t::retention_t(uint32_t remote_ep_timeout_)
  : remote_ep_timeout(remote_ep_timeout_)
{
}

bool
gbp_endpoint_group::retention_t::operator==(const retention_t& o) const
{
  return (remote_ep_timeout == o.remote_ep_timeout);
}

std::string
gbp_endpoint_group::retention_t::to_string() const
{
  return std::to_string(remote_ep_timeout);
}

gbp_endpoint_group::gbp_endpoint_group(vnid_t vnid,
                                       sclass_t sclass,
                                       const interface& itf,
                                       const gbp_route_domain& rd,
                                       const gbp_bridge_domain& bd)
  : m_hw(false)
  , m_vnid(vnid)
  , m_sclass(sclass)
  , m_itf(itf.singular())
  , m_rd(rd.singular())
  , m_bd(bd.singular())
  , m_retention()
{
}

gbp_endpoint_group::gbp_endpoint_group(vnid_t vnid,
                                       sclass_t sclass,
                                       const gbp_route_domain& rd,
                                       const gbp_bridge_domain& bd)
  : m_hw(false)
  , m_vnid(vnid)
  , m_sclass(sclass)
  , m_itf()
  , m_rd(rd.singular())
  , m_bd(bd.singular())
  , m_retention()
{
}

gbp_endpoint_group::gbp_endpoint_group(sclass_t sclass,
                                       const gbp_route_domain& rd,
                                       const gbp_bridge_domain& bd)
  : m_hw(false)
  , m_vnid(~0)
  , m_sclass(sclass)
  , m_itf()
  , m_rd(rd.singular())
  , m_bd(bd.singular())
  , m_retention()
{
}

gbp_endpoint_group::gbp_endpoint_group(const gbp_endpoint_group& epg)
  : m_hw(epg.m_hw)
  , m_vnid(epg.m_vnid)
  , m_sclass(epg.m_sclass)
  , m_itf(epg.m_itf)
  , m_rd(epg.m_rd)
  , m_bd(epg.m_bd)
  , m_retention(epg.m_retention)
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
  return (m_sclass);
}

vnid_t
gbp_endpoint_group::vnid() const
{
  return (m_vnid);
}

void
gbp_endpoint_group::set(const retention_t& retention)
{
  m_retention = retention;
}

sclass_t
gbp_endpoint_group::sclass() const
{
  return (m_sclass);
}

bool
gbp_endpoint_group::operator==(const gbp_endpoint_group& gg) const
{
  return (key() == gg.key() && (m_vnid == gg.m_vnid) &&
          (m_retention == gg.m_retention) && (m_itf == gg.m_itf) &&
          (m_rd == gg.m_rd) && (m_bd == gg.m_bd));
}

void
gbp_endpoint_group::sweep()
{
  if (m_hw) {
    HW::enqueue(new gbp_endpoint_group_cmds::delete_cmd(m_hw, m_vnid));
  }
  HW::write();
}

void
gbp_endpoint_group::replay()
{
  if (m_hw) {
    HW::enqueue(new gbp_endpoint_group_cmds::create_cmd(
      m_hw, m_vnid, m_sclass, m_bd->id(), m_rd->id(), m_retention,
      (m_itf ? m_itf->handle() : handle_t::INVALID)));
  }
}

std::string
gbp_endpoint_group::to_string() const
{
  std::ostringstream s;
  s << "gbp-endpoint-group:["
    << "vnid:" << m_vnid << ", sclass:" << m_sclass << ", "
    << "retention:[" << m_retention.to_string() << "], "
    << (m_itf ? m_itf->to_string() : "NULL") << ", " << m_bd->to_string()
    << ", " << m_rd->to_string() << "]";

  return (s.str());
}

void
gbp_endpoint_group::update(const gbp_endpoint_group& r)
{
  if (rc_t::OK != m_hw.rc()) {
    HW::enqueue(new gbp_endpoint_group_cmds::create_cmd(
      m_hw, m_vnid, m_sclass, m_bd->id(), m_rd->id(), m_retention,
      (m_itf ? m_itf->handle() : handle_t::INVALID)));
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

const std::shared_ptr<gbp_route_domain>
gbp_endpoint_group::get_route_domain() const
{
  return m_rd;
}

const std::shared_ptr<gbp_bridge_domain>
gbp_endpoint_group::get_bridge_domain() const
{
  return m_bd;
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
      gbp_endpoint_group gbpe(payload.epg.vnid, payload.epg.sclass, *itf, *rd,
                              *bd);
      OM::commit(key, gbpe);

      VOM_LOG(log_level_t::DEBUG) << "read: " << gbpe.to_string();
    } else if (bd && rd) {
      gbp_endpoint_group gbpe(payload.epg.sclass, *rd, *bd);
      OM::commit(key, gbpe);

      VOM_LOG(log_level_t::DEBUG) << "read: " << gbpe.to_string();
    } else {
      VOM_LOG(log_level_t::ERROR) << "no itf:" << payload.epg.uplink_sw_if_index
                                  << " or BD:" << payload.epg.bd_id
                                  << " or RD:" << payload.epg.rd_id;
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
