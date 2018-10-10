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

#include "vom/gbp_vxlan.hpp"
#include "vom/gbp_vxlan_cmds.hpp"
#include "vom/interface.hpp"
#include "vom/singular_db_funcs.hpp"

namespace VOM {

/**
 * A DB of al the interfaces, key on the name
 */
singular_db<gbp_vxlan::key_t, gbp_vxlan> gbp_vxlan::m_db;

gbp_vxlan::event_handler gbp_vxlan::m_evh;

gbp_vxlan::gbp_vxlan(uint32_t vni, const gbp_route_domain& grd)
  : interface(mk_name(vni),
              interface::type_t::UNKNOWN,
              interface::admin_state_t::UP)
  , m_vni(vni)
  , m_gbd()
  , m_grd(grd.singular())
{
}
gbp_vxlan::gbp_vxlan(uint32_t vni, const gbp_bridge_domain& gbd)
  : interface(mk_name(vni),
              interface::type_t::UNKNOWN,
              interface::admin_state_t::UP)
  , m_vni(vni)
  , m_gbd(gbd.singular())
  , m_grd()
{
}

gbp_vxlan::gbp_vxlan(const gbp_vxlan& vt)
  : interface(vt)
  , m_vni(vt.m_vni)
  , m_gbd(vt.m_gbd)
  , m_grd(vt.m_grd)
{
}

const gbp_vxlan::key_t
gbp_vxlan::key() const
{
  return (m_vni);
}

bool
gbp_vxlan::operator==(const gbp_vxlan& vt) const
{
  return (m_vni == vt.m_vni);
}

void
gbp_vxlan::sweep()
{
  if (rc_t::OK == m_hdl) {
    HW::enqueue(new gbp_vxlan_cmds::delete_cmd(m_hdl, m_vni));
  }
  HW::write();
}

void
gbp_vxlan::replay()
{
  if (rc_t::OK == m_hdl) {
    if (m_grd)
      HW::enqueue(new gbp_vxlan_cmds::create_cmd(m_hdl, name(), m_vni, false,
                                                 m_grd->id()));
    else if (m_gbd)
      HW::enqueue(new gbp_vxlan_cmds::create_cmd(m_hdl, name(), m_vni, true,
                                                 m_gbd->id()));
  }
}

gbp_vxlan::~gbp_vxlan()
{
  sweep();
  m_db.release(key(), this);
}

std::string
gbp_vxlan::to_string() const
{
  std::ostringstream s;
  s << "gbp-vxlan:[" << m_vni << "]";

  return (s.str());
}

std::shared_ptr<gbp_vxlan>
gbp_vxlan::find(const key_t key)
{
  return (m_db.find(key));
}

void
gbp_vxlan::update(const gbp_vxlan& desired)
{
  /*
   * the desired state is always that the interface should be created
   */
  if (rc_t::OK != m_hdl) {
    if (m_grd)
      HW::enqueue(new gbp_vxlan_cmds::create_cmd(m_hdl, name(), m_vni, false,
                                                 m_grd->id()));
    else if (m_gbd)
      HW::enqueue(new gbp_vxlan_cmds::create_cmd(m_hdl, name(), m_vni, true,
                                                 m_gbd->id()));
  }
}

std::shared_ptr<gbp_vxlan>
gbp_vxlan::find_or_add(const gbp_vxlan& temp)
{
  return (m_db.find_or_add(temp.key(), temp));
}

std::shared_ptr<gbp_vxlan>
gbp_vxlan::singular() const
{
  return find_or_add(*this);
}

void
gbp_vxlan::dump(std::ostream& os)
{
  db_dump(m_db, os);
}

void
gbp_vxlan::event_handler::handle_populate(const client_db::key_t& key)
{
  /*
   * dump VPP Bridge domains
   */
  std::shared_ptr<gbp_vxlan_cmds::dump_cmd> cmd =
    std::make_shared<gbp_vxlan_cmds::dump_cmd>();

  HW::enqueue(cmd);
  HW::write();

  for (auto& record : *cmd) {
    auto& payload = record.get_payload();

    if (GBP_VXLAN_TUNNEL_MODE_L3 == payload.tunnel.mode) {
      auto rd = gbp_route_domain::find(payload.tunnel.bd_rd_id);

      if (rd) {
        gbp_vxlan vt(payload.tunnel.vni, *rd);
        OM::commit(key, vt);
        VOM_LOG(log_level_t::DEBUG) << "dump: " << vt.to_string();
      }
    } else {
      auto bd = gbp_bridge_domain::find(payload.tunnel.bd_rd_id);

      if (bd) {
        gbp_vxlan vt(payload.tunnel.vni, *bd);
        OM::commit(key, vt);
        VOM_LOG(log_level_t::DEBUG) << "dump: " << vt.to_string();
      }
    }
  }
}

gbp_vxlan::event_handler::event_handler()
{
  OM::register_listener(this);
  inspect::register_handler({ "gvt", "gbp-vxlan-tunnel" }, "GBP VXLAN Tunnels",
                            this);
}

void
gbp_vxlan::event_handler::handle_replay()
{
  m_db.replay();
}

dependency_t
gbp_vxlan::event_handler::order() const
{
  return (dependency_t::BINDING);
}

void
gbp_vxlan::event_handler::show(std::ostream& os)
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
