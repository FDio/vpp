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

#include "vom/gbp_endpoint.hpp"
#include "vom/gbp_endpoint_cmds.hpp"

namespace VOM {

singular_db<gbp_endpoint::key_t, gbp_endpoint> gbp_endpoint::m_db;

gbp_endpoint::event_handler gbp_endpoint::m_evh;

gbp_endpoint::gbp_endpoint(const interface& itf,
                           const boost::asio::ip::address& ip_addr,
                           epg_id_t epg_id)
  : m_hw(false)
  , m_itf(itf.singular())
  , m_ip_addr(ip_addr)
  , m_epg_id(epg_id)
{
}

gbp_endpoint::gbp_endpoint(const gbp_endpoint& gbpe)
  : m_hw(gbpe.m_hw)
  , m_itf(gbpe.m_itf)
  , m_ip_addr(gbpe.m_ip_addr)
  , m_epg_id(gbpe.m_epg_id)
{
}

gbp_endpoint::~gbp_endpoint()
{
  sweep();

  // not in the DB anymore.
  m_db.release(key(), this);
}

const gbp_endpoint::key_t
gbp_endpoint::key() const
{
  return (std::make_pair(m_itf->key(), m_ip_addr));
}

bool
gbp_endpoint::operator==(const gbp_endpoint& gbpe) const
{
  return ((key() == gbpe.key()) && (m_epg_id == gbpe.m_epg_id));
}

void
gbp_endpoint::sweep()
{
  if (m_hw) {
    HW::enqueue(
      new gbp_endpoint_cmds::delete_cmd(m_hw, m_itf->handle(), m_ip_addr));
  }
  HW::write();
}

void
gbp_endpoint::replay()
{
  if (m_hw) {
    HW::enqueue(new gbp_endpoint_cmds::create_cmd(m_hw, m_itf->handle(),
                                                  m_ip_addr, m_epg_id));
  }
}

std::string
gbp_endpoint::to_string() const
{
  std::ostringstream s;
  s << "gbp-endpoint:[" << m_itf->to_string() << ", " << m_ip_addr.to_string()
    << ", epg-id:" << m_epg_id << "]";

  return (s.str());
}

void
gbp_endpoint::update(const gbp_endpoint& r)
{
  /*
 * create the table if it is not yet created
 */
  if (rc_t::OK != m_hw.rc()) {
    HW::enqueue(new gbp_endpoint_cmds::create_cmd(m_hw, m_itf->handle(),
                                                  m_ip_addr, m_epg_id));
  }
}

std::shared_ptr<gbp_endpoint>
gbp_endpoint::find_or_add(const gbp_endpoint& temp)
{
  return (m_db.find_or_add(temp.key(), temp));
}

std::shared_ptr<gbp_endpoint>
gbp_endpoint::find(const key_t& k)
{
  return (m_db.find(k));
}

std::shared_ptr<gbp_endpoint>
gbp_endpoint::singular() const
{
  return find_or_add(*this);
}

void
gbp_endpoint::dump(std::ostream& os)
{
  m_db.dump(os);
}

gbp_endpoint::event_handler::event_handler()
{
  OM::register_listener(this);
  inspect::register_handler({ "gbp-endpoint" }, "GBP Endpoints", this);
}

void
gbp_endpoint::event_handler::handle_replay()
{
  m_db.replay();
}

void
gbp_endpoint::event_handler::handle_populate(const client_db::key_t& key)
{
  std::shared_ptr<gbp_endpoint_cmds::dump_cmd> cmd =
    std::make_shared<gbp_endpoint_cmds::dump_cmd>();

  HW::enqueue(cmd);
  HW::write();

  for (auto& record : *cmd) {
    auto& payload = record.get_payload();

    boost::asio::ip::address address =
      from_bytes(payload.endpoint.is_ip6, payload.endpoint.address);
    std::shared_ptr<interface> itf =
      interface::find(payload.endpoint.sw_if_index);

    VOM_LOG(log_level_t::DEBUG) << "data: " << payload.endpoint.sw_if_index;

    if (itf) {
      gbp_endpoint gbpe(*itf, address, payload.endpoint.epg_id);
      OM::commit(key, gbpe);

      VOM_LOG(log_level_t::DEBUG) << "read: " << gbpe.to_string();
    }
  }
}

dependency_t
gbp_endpoint::event_handler::order() const
{
  return (dependency_t::ENTRY);
}

void
gbp_endpoint::event_handler::show(std::ostream& os)
{
  m_db.dump(os);
}
} // namespace VOM

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */
