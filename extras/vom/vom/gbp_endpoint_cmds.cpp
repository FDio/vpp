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

#include "vom/gbp_endpoint_cmds.hpp"
#include "vom/api_types.hpp"

DEFINE_VAPI_MSG_IDS_GBP_API_JSON;

namespace VOM {
namespace gbp_endpoint_cmds {

static vapi_enum_gbp_endpoint_flags
to_api(const gbp_endpoint::flags_t& in)
{
  vapi_enum_gbp_endpoint_flags out = GBP_API_ENDPOINT_FLAG_NONE;

  if (in & gbp_endpoint::flags_t::REMOTE)
    out = (vapi_enum_gbp_endpoint_flags)(out | GBP_API_ENDPOINT_FLAG_REMOTE);
  if (in & gbp_endpoint::flags_t::BOUNCE)
    out = (vapi_enum_gbp_endpoint_flags)(out | GBP_API_ENDPOINT_FLAG_BOUNCE);
  if (in & gbp_endpoint::flags_t::LEARNT)
    out = (vapi_enum_gbp_endpoint_flags)(out | GBP_API_ENDPOINT_FLAG_LEARNT);
  if (in & gbp_endpoint::flags_t::EXTERNAL)
    out = (vapi_enum_gbp_endpoint_flags)(out | GBP_API_ENDPOINT_FLAG_EXTERNAL);

  return (out);
}

create_cmd::create_cmd(HW::item<handle_t>& item,
                       const handle_t& itf,
                       const std::vector<boost::asio::ip::address>& ip_addrs,
                       const mac_address_t& mac,
                       sclass_t sclass,
                       const gbp_endpoint::flags_t& flags)
  : rpc_cmd(item)
  , m_itf(itf)
  , m_ip_addrs(ip_addrs)
  , m_mac(mac)
  , m_sclass(sclass)
  , m_flags(flags)
{
}

bool
create_cmd::operator==(const create_cmd& other) const
{
  return ((m_itf == other.m_itf) && (m_ip_addrs == other.m_ip_addrs) &&
          (m_mac == other.m_mac) && (m_sclass == other.m_sclass) &&
          (m_flags == other.m_flags));
}

rc_t
create_cmd::issue(connection& con)
{
  msg_t req(con.ctx(), m_ip_addrs.size() * sizeof(vapi_type_address),
            std::ref(*this));
  uint8_t n;

  auto& payload = req.get_request().get_payload();
  payload.endpoint.sw_if_index = m_itf.value();
  payload.endpoint.sclass = m_sclass;
  payload.endpoint.n_ips = m_ip_addrs.size();
  payload.endpoint.flags = to_api(m_flags);

  for (n = 0; n < payload.endpoint.n_ips; n++) {
    VOM::to_api(m_ip_addrs[n], payload.endpoint.ips[n]);
  }
  to_api(m_mac, payload.endpoint.mac);

  VAPI_CALL(req.execute());

  return (wait());
}

vapi_error_e
create_cmd::operator()(vapi::Gbp_endpoint_add& reply)
{
  int handle = reply.get_response().get_payload().handle;
  int retval = reply.get_response().get_payload().retval;

  VOM_LOG(log_level_t::DEBUG) << this->to_string() << " " << retval;

  rc_t rc = rc_t::from_vpp_retval(retval);
  handle_t hdl = handle_t::INVALID;

  if (rc_t::OK == rc) {
    hdl = handle;
  }

  this->fulfill(HW::item<handle_t>(hdl, rc));

  return (VAPI_OK);
}

std::string
create_cmd::to_string() const
{
  std::ostringstream s;
  s << "gbp-endpoint-create: " << m_hw_item.to_string() << " itf:" << m_itf
    << " ips:[";
  for (auto ip : m_ip_addrs)
    s << ip.to_string();

  s << "] mac:" << m_mac << " slcass:" << m_sclass
    << " flags:" << m_flags.to_string();

  return (s.str());
}

delete_cmd::delete_cmd(HW::item<handle_t>& item)
  : rpc_cmd(item)
{
}

bool
delete_cmd::operator==(const delete_cmd& other) const
{
  return (m_hw_item == other.m_hw_item);
}

rc_t
delete_cmd::issue(connection& con)
{
  msg_t req(con.ctx(), std::ref(*this));

  auto& payload = req.get_request().get_payload();
  payload.handle = m_hw_item.data().value();

  VAPI_CALL(req.execute());

  return (wait());
}

std::string
delete_cmd::to_string() const
{
  std::ostringstream s;
  s << "gbp-endpoint-delete: " << m_hw_item.to_string();

  return (s.str());
}

dump_cmd::dump_cmd()
{
}

bool
dump_cmd::operator==(const dump_cmd& other) const
{
  return (true);
}

rc_t
dump_cmd::issue(connection& con)
{
  m_dump.reset(new msg_t(con.ctx(), std::ref(*this)));

  VAPI_CALL(m_dump->execute());

  wait();

  return rc_t::OK;
}

std::string
dump_cmd::to_string() const
{
  return ("gbp-endpoint-dump");
}

}; // namespace gbp_endpoint_cmds
}; // namespace VOM

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */
