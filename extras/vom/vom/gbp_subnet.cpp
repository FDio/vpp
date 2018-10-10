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

#include "vom/gbp_subnet.hpp"
#include "vom/api_types.hpp"
#include "vom/gbp_subnet_cmds.hpp"
#include "vom/singular_db_funcs.hpp"

namespace VOM {

gbp_subnet::type_t::type_t(int v, const std::string s)
  : enum_base<gbp_subnet::type_t>(v, s)
{
}

const gbp_subnet::type_t gbp_subnet::type_t::STITCHED_INTERNAL(
  0,
  "stitched-internal");
const gbp_subnet::type_t gbp_subnet::type_t::STITCHED_EXTERNAL(
  1,
  "stitched-external");
const gbp_subnet::type_t gbp_subnet::type_t::TRANSPORT(1, "transport");

singular_db<gbp_subnet::key_t, gbp_subnet> gbp_subnet::m_db;

gbp_subnet::event_handler gbp_subnet::m_evh;

gbp_subnet::gbp_subnet(const gbp_route_domain& rd,
                       const route::prefix_t& prefix,
                       const type_t& type)
  : m_hw(false)
  , m_rd(rd.singular())
  , m_prefix(prefix)
  , m_type(type)
  , m_recirc(nullptr)
  , m_epg(nullptr)
{
}

gbp_subnet::gbp_subnet(const gbp_route_domain& rd,
                       const route::prefix_t& prefix,
                       const gbp_recirc& recirc,
                       const gbp_endpoint_group& epg)
  : m_hw(false)
  , m_rd(rd.singular())
  , m_prefix(prefix)
  , m_type(type_t::STITCHED_EXTERNAL)
  , m_recirc(recirc.singular())
  , m_epg(epg.singular())
{
}

gbp_subnet::gbp_subnet(const gbp_subnet& o)
  : m_hw(o.m_hw)
  , m_rd(o.m_rd)
  , m_prefix(o.m_prefix)
  , m_type(o.m_type)
  , m_recirc(o.m_recirc)
  , m_epg(o.m_epg)
{
}

gbp_subnet::~gbp_subnet()
{
  sweep();
  m_db.release(key(), this);
}

const gbp_subnet::key_t
gbp_subnet::key() const
{
  return (std::make_pair(m_rd->key(), m_prefix));
}

bool
gbp_subnet::operator==(const gbp_subnet& gs) const
{
  return ((key() == gs.key()) && (m_type == gs.m_type) &&
          (m_recirc == gs.m_recirc) && (m_epg == gs.m_epg));
}

void
gbp_subnet::sweep()
{
  if (m_hw) {
    HW::enqueue(new gbp_subnet_cmds::delete_cmd(m_hw, m_rd->id(), m_prefix));
  }
  HW::write();
}

void
gbp_subnet::replay()
{
  if (m_hw) {
    HW::enqueue(new gbp_subnet_cmds::create_cmd(
      m_hw, m_rd->id(), m_prefix, m_type,
      (m_recirc ? m_recirc->handle() : handle_t::INVALID),
      (m_epg ? m_epg->id() : ~0)));
  }
}

std::string
gbp_subnet::to_string() const
{
  std::ostringstream s;
  s << "gbp-subnet:[" << m_type.to_string() << ", " << m_rd->to_string() << ":"
    << m_prefix.to_string();
  if (m_recirc)
    s << ", " << m_recirc->to_string();
  if (m_epg)
    s << ", " << m_epg->to_string();

  s << "]";

  return (s.str());
}

void
gbp_subnet::update(const gbp_subnet& r)
{
  if (rc_t::OK != m_hw.rc()) {
    HW::enqueue(new gbp_subnet_cmds::create_cmd(
      m_hw, m_rd->id(), m_prefix, m_type,
      (m_recirc ? m_recirc->handle() : handle_t::INVALID),
      (m_epg ? m_epg->id() : ~0)));
  } else {
    if (m_type != r.m_type) {
      m_epg = r.m_epg;
      m_recirc = r.m_recirc;
      m_type = r.m_type;

      HW::enqueue(new gbp_subnet_cmds::create_cmd(
        m_hw, m_rd->id(), m_prefix, m_type,
        (m_recirc ? m_recirc->handle() : handle_t::INVALID),
        (m_epg ? m_epg->id() : ~0)));
    }
  }
}

std::shared_ptr<gbp_subnet>
gbp_subnet::find_or_add(const gbp_subnet& temp)
{
  return (m_db.find_or_add(temp.key(), temp));
}

std::shared_ptr<gbp_subnet>
gbp_subnet::find(const key_t& k)
{
  return (m_db.find(k));
}

std::shared_ptr<gbp_subnet>
gbp_subnet::singular() const
{
  return find_or_add(*this);
}

void
gbp_subnet::dump(std::ostream& os)
{
  db_dump(m_db, os);
}

gbp_subnet::event_handler::event_handler()
{
  OM::register_listener(this);
  inspect::register_handler({ "gbp-subnet" }, "GBP Subnets", this);
}

void
gbp_subnet::event_handler::handle_replay()
{
  m_db.replay();
}

void
gbp_subnet::event_handler::handle_populate(const client_db::key_t& key)
{
  std::shared_ptr<gbp_subnet_cmds::dump_cmd> cmd =
    std::make_shared<gbp_subnet_cmds::dump_cmd>();

  HW::enqueue(cmd);
  HW::write();

  for (auto& record : *cmd) {
    auto& payload = record.get_payload();

    route::prefix_t pfx = from_api(payload.subnet.prefix);
    std::shared_ptr<gbp_route_domain> rd =
      gbp_route_domain::find(payload.subnet.rd_id);

    if (rd) {
      switch (payload.subnet.type) {
        case GBP_API_SUBNET_TRANSPORT: {
          gbp_subnet gs(*rd, pfx, type_t::TRANSPORT);
          OM::commit(key, gs);
          VOM_LOG(log_level_t::DEBUG) << "read: " << gs.to_string();
          break;
        }
        case GBP_API_SUBNET_STITCHED_INTERNAL: {
          gbp_subnet gs(*rd, pfx, type_t::STITCHED_INTERNAL);
          OM::commit(key, gs);
          VOM_LOG(log_level_t::DEBUG) << "read: " << gs.to_string();
          break;
        }
        case GBP_API_SUBNET_STITCHED_EXTERNAL: {
          std::shared_ptr<interface> itf =
            interface::find(payload.subnet.sw_if_index);
          std::shared_ptr<gbp_endpoint_group> epg =
            gbp_endpoint_group::find(payload.subnet.epg_id);

          if (itf && epg) {
            std::shared_ptr<gbp_recirc> recirc = gbp_recirc::find(itf->key());

            if (recirc) {
              gbp_subnet gs(*rd, pfx, *recirc, *epg);
              OM::commit(key, gs);
              VOM_LOG(log_level_t::DEBUG) << "read: " << gs.to_string();
            }
          }
        }
      }
    }
  }
}

dependency_t
gbp_subnet::event_handler::order() const
{
  return (dependency_t::ENTRY);
}

void
gbp_subnet::event_handler::show(std::ostream& os)
{
  db_dump(m_db, os);
}

std::ostream&
operator<<(std::ostream& os, const gbp_subnet::key_t& key)
{
  os << "[" << key.first << ", " << key.second << "]";

  return os;
}

} // namespace VOM

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */
