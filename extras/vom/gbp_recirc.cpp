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

#include "vom/gbp_recirc.hpp"
#include "vom/gbp_recirc_cmds.hpp"
#include "vom/singular_db_funcs.hpp"

namespace VOM {

gbp_recirc::type_t::type_t(int v, const std::string s)
  : enum_base<gbp_recirc::type_t>(v, s)
{
}

const gbp_recirc::type_t gbp_recirc::type_t::INTERNAL(0, "internal");
const gbp_recirc::type_t gbp_recirc::type_t::EXTERNAL(1, "external");

singular_db<gbp_recirc::key_t, gbp_recirc> gbp_recirc::m_db;

gbp_recirc::event_handler gbp_recirc::m_evh;

gbp_recirc::gbp_recirc(const interface& itf,
                       const type_t& type,
                       const gbp_endpoint_group& epg)
  : m_hw(false)
  , m_itf(itf.singular())
  , m_type(type)
  , m_epg(epg.singular())
{
}

gbp_recirc::gbp_recirc(const gbp_recirc& gbpe)
  : m_hw(gbpe.m_hw)
  , m_itf(gbpe.m_itf)
  , m_type(gbpe.m_type)
  , m_epg(gbpe.m_epg)
{
}

gbp_recirc::~gbp_recirc()
{
  sweep();
  m_db.release(key(), this);
}

const gbp_recirc::key_t
gbp_recirc::key() const
{
  return (m_itf->key());
}

const handle_t&
gbp_recirc::handle() const
{
  return m_itf->handle();
}

bool
gbp_recirc::operator==(const gbp_recirc& gbpe) const
{
  return ((key() == gbpe.key()) && (m_type == gbpe.m_type) &&
          (m_itf == gbpe.m_itf) && (m_epg == gbpe.m_epg));
}

void
gbp_recirc::sweep()
{
  if (m_hw) {
    HW::enqueue(new gbp_recirc_cmds::delete_cmd(m_hw, m_itf->handle()));
  }
  HW::write();
}

void
gbp_recirc::replay()
{
  if (m_hw) {
    HW::enqueue(new gbp_recirc_cmds::create_cmd(
      m_hw, m_itf->handle(), (m_type == type_t::EXTERNAL), m_epg->id()));
  }
}

std::string
gbp_recirc::to_string() const
{
  std::ostringstream s;
  s << "gbp-recirc:[" << m_itf->to_string() << ", type:" << m_type.to_string()
    << ", " << m_epg->to_string() << "]";

  return (s.str());
}

void
gbp_recirc::update(const gbp_recirc& r)
{
  if (rc_t::OK != m_hw.rc()) {
    HW::enqueue(new gbp_recirc_cmds::create_cmd(
      m_hw, m_itf->handle(), (m_type == type_t::EXTERNAL), m_epg->id()));
  }
}

std::shared_ptr<gbp_recirc>
gbp_recirc::find_or_add(const gbp_recirc& temp)
{
  return (m_db.find_or_add(temp.key(), temp));
}

std::shared_ptr<gbp_recirc>
gbp_recirc::find(const key_t& k)
{
  return (m_db.find(k));
}

std::shared_ptr<gbp_recirc>
gbp_recirc::singular() const
{
  return find_or_add(*this);
}

void
gbp_recirc::dump(std::ostream& os)
{
  db_dump(m_db, os);
}

gbp_recirc::event_handler::event_handler()
{
  OM::register_listener(this);
  inspect::register_handler({ "gbp-recirc" }, "GBP Recircs", this);
}

void
gbp_recirc::event_handler::handle_replay()
{
  m_db.replay();
}

void
gbp_recirc::event_handler::handle_populate(const client_db::key_t& key)
{
  std::shared_ptr<gbp_recirc_cmds::dump_cmd> cmd =
    std::make_shared<gbp_recirc_cmds::dump_cmd>();

  HW::enqueue(cmd);
  HW::write();

  for (auto& record : *cmd) {
    auto& payload = record.get_payload();

    std::shared_ptr<interface> itf =
      interface::find(payload.recirc.sw_if_index);
    std::shared_ptr<gbp_endpoint_group> epg =
      gbp_endpoint_group::find(payload.recirc.epg_id);

    VOM_LOG(log_level_t::DEBUG) << "data: [" << payload.recirc.sw_if_index
                                << ", " << payload.recirc.epg_id << "]";

    if (itf && epg) {
      gbp_recirc recirc(
        *itf, (payload.recirc.is_ext ? type_t::EXTERNAL : type_t::INTERNAL),
        *epg);
      OM::commit(key, recirc);

      VOM_LOG(log_level_t::DEBUG) << "read: " << recirc.to_string();
    }
  }
}

dependency_t
gbp_recirc::event_handler::order() const
{
  return (dependency_t::BINDING);
}

void
gbp_recirc::event_handler::show(std::ostream& os)
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
