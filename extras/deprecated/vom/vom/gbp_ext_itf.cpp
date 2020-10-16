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

#include "vom/gbp_ext_itf.hpp"
#include "vom/gbp_ext_itf_cmds.hpp"
#include "vom/singular_db_funcs.hpp"

namespace VOM {

singular_db<gbp_ext_itf::key_t, gbp_ext_itf> gbp_ext_itf::m_db;

gbp_ext_itf::event_handler gbp_ext_itf::m_evh;

gbp_ext_itf::gbp_ext_itf(const interface& itf,
                         const gbp_bridge_domain& gbd,
                         const gbp_route_domain& grd)
  : m_hw(false)
  , m_itf(itf.singular())
  , m_bd(gbd.singular())
  , m_rd(grd.singular())
{
}

gbp_ext_itf::gbp_ext_itf(const gbp_ext_itf& gbpe)
  : m_hw(gbpe.m_hw)
  , m_itf(gbpe.m_itf)
  , m_bd(gbpe.m_bd)
  , m_rd(gbpe.m_rd)
{
}

gbp_ext_itf::~gbp_ext_itf()
{
  sweep();
  m_db.release(key(), this);
}

const gbp_ext_itf::key_t
gbp_ext_itf::key() const
{
  return (m_itf->key());
}

const handle_t&
gbp_ext_itf::handle() const
{
  return m_itf->handle();
}

bool
gbp_ext_itf::operator==(const gbp_ext_itf& gei) const
{
  return ((key() == gei.key()) && (m_itf == gei.m_itf) && (m_rd == gei.m_rd) &&
          (m_bd == gei.m_bd));
}

void
gbp_ext_itf::sweep()
{
  if (m_hw) {
    HW::enqueue(new gbp_ext_itf_cmds::delete_cmd(m_hw, m_itf->handle()));
  }
  HW::write();
}

void
gbp_ext_itf::replay()
{
  if (m_hw) {
    HW::enqueue(new gbp_ext_itf_cmds::create_cmd(m_hw, m_itf->handle(),
                                                 m_bd->id(), m_rd->id()));
  }
}

std::string
gbp_ext_itf::to_string() const
{
  std::ostringstream s;
  s << "gbp-ext_itf:[" << m_itf->to_string() << ", " << m_bd->to_string()
    << ", " << m_rd->to_string() << "]";

  return (s.str());
}

void
gbp_ext_itf::update(const gbp_ext_itf& r)
{
  if (rc_t::OK != m_hw.rc()) {
    HW::enqueue(new gbp_ext_itf_cmds::create_cmd(m_hw, m_itf->handle(),
                                                 m_bd->id(), m_rd->id()));
  }
}

std::shared_ptr<gbp_ext_itf>
gbp_ext_itf::find_or_add(const gbp_ext_itf& temp)
{
  return (m_db.find_or_add(temp.key(), temp));
}

std::shared_ptr<gbp_ext_itf>
gbp_ext_itf::find(const key_t& k)
{
  return (m_db.find(k));
}

std::shared_ptr<gbp_ext_itf>
gbp_ext_itf::singular() const
{
  return find_or_add(*this);
}

void
gbp_ext_itf::dump(std::ostream& os)
{
  db_dump(m_db, os);
}

gbp_ext_itf::event_handler::event_handler()
{
  OM::register_listener(this);
  inspect::register_handler({ "gbp-ext-itf" }, "GBP External-Itfs", this);
}

void
gbp_ext_itf::event_handler::handle_replay()
{
  m_db.replay();
}

void
gbp_ext_itf::event_handler::handle_populate(const client_db::key_t& key)
{
  std::shared_ptr<gbp_ext_itf_cmds::dump_cmd> cmd =
    std::make_shared<gbp_ext_itf_cmds::dump_cmd>();

  HW::enqueue(cmd);
  HW::write();

  for (auto& record : *cmd) {
    auto& payload = record.get_payload();

    std::shared_ptr<interface> itf =
      interface::find(payload.ext_itf.sw_if_index);
    std::shared_ptr<gbp_bridge_domain> gbd =
      gbp_bridge_domain::find(payload.ext_itf.bd_id);
    std::shared_ptr<gbp_route_domain> grd =
      gbp_route_domain::find(payload.ext_itf.rd_id);

    VOM_LOG(log_level_t::DEBUG) << "data: [" << payload.ext_itf.sw_if_index
                                << ", " << payload.ext_itf.bd_id << ", "
                                << payload.ext_itf.rd_id << "]";

    if (itf && gbd && grd) {
      gbp_ext_itf ext_itf(*itf, *gbd, *grd);
      OM::commit(key, ext_itf);

      VOM_LOG(log_level_t::DEBUG) << "read: " << ext_itf.to_string();
    } else {
      VOM_LOG(log_level_t::ERROR) << "no itf:" << payload.ext_itf.sw_if_index
                                  << " or BD:" << payload.ext_itf.bd_id
                                  << " or RD:" << payload.ext_itf.rd_id;
    }
  }
}

dependency_t
gbp_ext_itf::event_handler::order() const
{
  return (dependency_t::BINDING);
}

void
gbp_ext_itf::event_handler::show(std::ostream& os)
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
