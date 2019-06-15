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
#include "vom/api_types.hpp"
#include "vom/gbp_endpoint_cmds.hpp"
#include "vom/singular_db_funcs.hpp"

namespace VOM {

singular_db<gbp_endpoint::key_t, gbp_endpoint> gbp_endpoint::m_db;

gbp_endpoint::event_handler gbp_endpoint::m_evh;

const gbp_endpoint::flags_t gbp_endpoint::flags_t::NONE(0, "none");
const gbp_endpoint::flags_t gbp_endpoint::flags_t::BOUNCE(1, "bounce");
const gbp_endpoint::flags_t gbp_endpoint::flags_t::LEARNT(2, "learnt");
const gbp_endpoint::flags_t gbp_endpoint::flags_t::REMOTE(4, "remote");
const gbp_endpoint::flags_t gbp_endpoint::flags_t::EXTERNAL(8, "external");

gbp_endpoint::flags_t::flags_t(int v, const std::string& s)
  : enum_base<gbp_endpoint::flags_t>(v, s)
{
}

gbp_endpoint::gbp_endpoint(
  const interface& itf,
  const std::vector<boost::asio::ip::address>& ip_addrs,
  const mac_address_t& mac,
  const gbp_endpoint_group& epg,
  const flags_t& flags)
  : m_hdl(handle_t::INVALID)
  , m_itf(itf.singular())
  , m_ips(ip_addrs)
  , m_mac(mac)
  , m_epg(epg.singular())
  , m_flags(flags)
{
}

gbp_endpoint::gbp_endpoint(const gbp_endpoint& gbpe)
  : m_hdl(gbpe.m_hdl)
  , m_itf(gbpe.m_itf)
  , m_ips(gbpe.m_ips)
  , m_mac(gbpe.m_mac)
  , m_epg(gbpe.m_epg)
  , m_flags(gbpe.m_flags)
{
}

gbp_endpoint::~gbp_endpoint()
{
  sweep();
  m_db.release(key(), this);
}

const gbp_endpoint::key_t
gbp_endpoint::key() const
{
  return (std::make_pair(m_itf->key(), m_mac));
}

bool
gbp_endpoint::operator==(const gbp_endpoint& gbpe) const
{
  return ((key() == gbpe.key()) && (m_epg == gbpe.m_epg) &&
          (m_flags == gbpe.m_flags));
}

void
gbp_endpoint::sweep()
{
  if (m_hdl) {
    HW::enqueue(new gbp_endpoint_cmds::delete_cmd(m_hdl));
  }
  HW::write();
}

void
gbp_endpoint::replay()
{
  if (m_hdl) {
    HW::enqueue(new gbp_endpoint_cmds::create_cmd(
      m_hdl, m_itf->handle(), m_ips, m_mac, m_epg->sclass(), m_flags));
  }
}

std::string
gbp_endpoint::to_string() const
{
  std::ostringstream s;
  s << "gbp-endpoint:[" << m_itf->to_string() << ", ips:[";

  for (auto ip : m_ips)
    s << ip.to_string();

  s << "], " << m_mac.to_string() << ", epg:" << m_epg->to_string() << "]";

  return (s.str());
}

void
gbp_endpoint::update(const gbp_endpoint& r)
{
  if (rc_t::OK != m_hdl.rc()) {
    HW::enqueue(new gbp_endpoint_cmds::create_cmd(
      m_hdl, m_itf->handle(), m_ips, m_mac, m_epg->sclass(), m_flags));
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
  db_dump(m_db, os);
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

    std::vector<boost::asio::ip::address> addresses;

    for (uint8_t n = 0; n < payload.endpoint.n_ips; n++)
      addresses.push_back(from_api(payload.endpoint.ips[n]));
    std::shared_ptr<interface> itf =
      interface::find(payload.endpoint.sw_if_index);
    std::shared_ptr<gbp_endpoint_group> epg =
      gbp_endpoint_group::find(payload.endpoint.sclass);
    mac_address_t mac = from_api(payload.endpoint.mac);

    VOM_LOG(log_level_t::DEBUG) << "data: " << payload.endpoint.sw_if_index;

    if (itf && epg) {
      gbp_endpoint gbpe(*itf, addresses, mac, *epg);
      OM::commit(key, gbpe);

      VOM_LOG(log_level_t::DEBUG) << "read: " << gbpe.to_string();
    } else {
      VOM_LOG(log_level_t::ERROR)
        << "no interface:" << payload.endpoint.sw_if_index
        << "or sclass:" << payload.endpoint.sclass;
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
  db_dump(m_db, os);
}

std::ostream&
operator<<(std::ostream& os, const gbp_endpoint::key_t& key)
{
  os << key.first << "," << key.second;

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
