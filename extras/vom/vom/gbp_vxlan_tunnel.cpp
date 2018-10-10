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

#include "vom/gbp_vxlan_tunnel.hpp"
#include "vom/gbp_vxlan_tunnel_cmds.hpp"
#include "vom/interface.hpp"
#include "vom/singular_db_funcs.hpp"

namespace VOM {

/**
 * A DB of al the interfaces, key on the name
 */
singular_db<uint32_t, gbp_vxlan_tunnel> gbp_vxlan_tunnel::m_db;

gbp_vxlan_tunnel::event_handler gbp_vxlan_tunnel::m_evh;

/**
 * Construct a new object matching the desried state
 */
gbp_vxlan_tunnel::gbp_vxlan_tunnel(const vxlan_tunnel& vt)
  : interface(vt)
  , m_vni(vt.m_vni)
{
}

gbp_vxlan_tunnel::gbp_vxlan_tunnel(uint32_t vni)
  : interface(mk_name(vni),
              interface::type_t::UNKNOWN,
              interface::admin_state_t::UP)
  , m_vni(vt.m_vni)
{
}

const gbp_vxlan_tunnel::key_t
gbp_vxlan_tunnel::key() const
{
  return (m_vni);
}

bool
gbp_vxlan_tunnel::operator==(const gbp_vxlan_tunnel& vt) const
{
  return (m_vni == vt.m_vni);
}

void
gbp_vxlan_tunnel::sweep()
{
  if (rc_t::OK == m_id.rc()) {
    HW::enqueue(new gbp_vxlan_tunnel_cmds::delete_cmd(m_vni));
  }
  HW::write();
}

void
gbp_vxlan_tunnel::replay()
{
  if (rc_t::OK == m_hdl) {
    HW::enqueue(new gbp_vxlan_tunnel_cmds::create_cmd(m_vni));
  }
}

gbp_vxlan_tunnel::~gbp_vxlan_tunnel()
{
  sweep();
  m_db.release(m_id.data(), this);
}

std::string
gbp_vxlan_tunnel::to_string() const
{
  std::ostringstream s;
  s << "gbp-vxlan:[" << m_vni << "]";

  return (s.str());
}

std::shared_ptr<gbp_vxlan_tunnel>
gbp_vxlan_tunnel::find(const key_t& key)
{
  return (m_db.find(key));
}

void
gbp_vxlan_tunnel::update(const gbp_vxlan_tunnel& desired)
{
  /*
   * the desired state is always that the interface should be created
   */
  if (rc_t::OK != m_hdl) {
    HW::enqueue(new gbp_vxlan_tunnel_cmds::create_cmd(m_vni));
  }
}

std::shared_ptr<gbp_vxlan_tunnel>
gbp_vxlan_tunnel::find_or_add(const gbp_vxlan_tunnel& temp)
{
  return (m_db.find_or_add(temp.m_id.data(), temp));
}

std::shared_ptr<gbp_vxlan_tunnel>
gbp_vxlan_tunnel::singular() const
{
  return find_or_add(*this);
}

void
gbp_vxlan_tunnel::dump(std::ostream& os)
{
  db_dump(m_db, os);
}

void
gbp_vxlan_tunnel::event_handler::handle_populate(const client_db::key_t& key)
{
  /*
   * dump VPP Bridge domains
   */
  std::shared_ptr<gbp_vxlan_tunnel_cmds::dump_cmd> cmd =
    std::make_shared<gbp_vxlan_tunnel_cmds::dump_cmd>();

  HW::enqueue(cmd);
  HW::write();

  for (auto& record : *cmd) {
    auto& payload = record.get_payload();

    gbp_vxlan_tunnel vt(payload.tunnel.vni, );
    OM::commit(key, vt);
    VOM_LOG(log_level_t::DEBUG) << "dump: " << vt.to_string();
  }
  else
  {
    gbp_vxlan_tunnel vt(payload.vt.vt_id);
    OM::commit(key, vt);
    VOM_LOG(log_level_t::DEBUG) << "dump: " << vt.to_string();
  }
}
}

gbp_vxlan_tunnel::event_handler::event_handler()
{
  OM::register_listener(this);
  inspect::register_handler({ "gvt", "gbp-vxlan-tunnel" }, "GBP VXLAN Tunnels",
                            this);
}

void
gbp_vxlan_tunnel::event_handler::handle_replay()
{
  m_db.replay();
}

dependency_t
gbp_vxlan_tunnel::event_handler::order() const
{
  return (dependency_t::INTERFACE);
}

void
gbp_vxlan_tunnel::event_handler::show(std::ostream& os)
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
