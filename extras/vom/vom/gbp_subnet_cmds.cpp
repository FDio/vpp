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

#include "vom/gbp_subnet_cmds.hpp"
#include "vom/api_types.hpp"

namespace VOM {
namespace gbp_subnet_cmds {

create_cmd::create_cmd(HW::item<bool>& item,
                       route::table_id_t rd,
                       const route::prefix_t& prefix,
                       const gbp_subnet::type_t& type,
                       const handle_t& itf,
                       epg_id_t epg_id)
  : rpc_cmd(item)
  , m_rd(rd)
  , m_prefix(prefix)
  , m_type(type)
  , m_itf(itf)
  , m_epg_id(epg_id)
{
}

bool
create_cmd::operator==(const create_cmd& other) const
{
  return ((m_itf == other.m_itf) && (m_rd == other.m_rd) &&
          (m_prefix == other.m_prefix) && (m_type == other.m_type) &&
          (m_itf == other.m_itf) && (m_epg_id == other.m_epg_id));
}

static vapi_enum_gbp_subnet_type
gbp_subnet_type_to_api(const gbp_subnet::type_t& type)
{
  if (gbp_subnet::type_t::STITCHED_INTERNAL == type)
    return (GBP_API_SUBNET_STITCHED_INTERNAL);
  if (gbp_subnet::type_t::STITCHED_EXTERNAL == type)
    return (GBP_API_SUBNET_STITCHED_EXTERNAL);
  if (gbp_subnet::type_t::TRANSPORT == type)
    return (GBP_API_SUBNET_TRANSPORT);

  return (GBP_API_SUBNET_STITCHED_INTERNAL);
}

rc_t
create_cmd::issue(connection& con)
{
  msg_t req(con.ctx(), std::ref(*this));

  auto& payload = req.get_request().get_payload();
  payload.is_add = 1;
  payload.subnet.type = gbp_subnet_type_to_api(m_type);
  payload.subnet.rd_id = m_rd;
  payload.subnet.sw_if_index = m_itf.value();
  payload.subnet.epg_id = m_epg_id;
  payload.subnet.prefix = to_api(m_prefix);

  VAPI_CALL(req.execute());

  return (wait());
}

std::string
create_cmd::to_string() const
{
  std::ostringstream s;
  s << "gbp-subnet-create: " << m_hw_item.to_string() << "type:" << m_type
    << ", " << m_rd << ":" << m_prefix.to_string() << " itf:" << m_itf
    << " epg-id:" << m_epg_id;

  return (s.str());
}

delete_cmd::delete_cmd(HW::item<bool>& item,
                       route::table_id_t rd,
                       const route::prefix_t& prefix)
  : rpc_cmd(item)
  , m_rd(rd)
  , m_prefix(prefix)
{
}

bool
delete_cmd::operator==(const delete_cmd& other) const
{
  return ((m_rd == other.m_rd) && (m_prefix == other.m_prefix));
}

rc_t
delete_cmd::issue(connection& con)
{
  msg_t req(con.ctx(), std::ref(*this));

  auto& payload = req.get_request().get_payload();
  payload.is_add = 0;
  payload.subnet.rd_id = m_rd;
  payload.subnet.prefix = to_api(m_prefix);

  VAPI_CALL(req.execute());

  return (wait());
}

std::string
delete_cmd::to_string() const
{
  std::ostringstream s;
  s << "gbp-subnet-delete: " << m_hw_item.to_string() << ", " << m_rd << ":"
    << m_prefix.to_string();

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
  return ("gbp-subnet-dump");
}

}; // namespace gbp_subnet_cmds
}; // namespace VOM

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */
