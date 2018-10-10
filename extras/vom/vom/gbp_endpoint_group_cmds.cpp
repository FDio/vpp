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

#include "vom/gbp_endpoint_group_cmds.hpp"

namespace VOM {
namespace gbp_endpoint_group_cmds {

create_cmd::create_cmd(HW::item<bool>& item,
                       epg_id_t epg_id,
                       uint32_t bd_id,
                       route::table_id_t rd_id,
                       const handle_t& itf)
  : rpc_cmd(item)
  , m_epg_id(epg_id)
  , m_bd_id(bd_id)
  , m_rd_id(rd_id)
  , m_itf(itf)
{
}

bool
create_cmd::operator==(const create_cmd& other) const
{
  return ((m_itf == other.m_itf) && (m_bd_id == other.m_bd_id) &&
          (m_rd_id == other.m_rd_id) && (m_epg_id == other.m_epg_id));
}

rc_t
create_cmd::issue(connection& con)
{
  msg_t req(con.ctx(), std::ref(*this));

  auto& payload = req.get_request().get_payload();
  payload.epg.uplink_sw_if_index = m_itf.value();
  payload.epg.epg_id = m_epg_id;
  payload.epg.bd_id = m_bd_id;
  payload.epg.rd_id = m_rd_id;

  VAPI_CALL(req.execute());

  return (wait());
}

std::string
create_cmd::to_string() const
{
  std::ostringstream s;
  s << "gbp-endpoint-group-create: " << m_hw_item.to_string()
    << " epg-id:" << m_epg_id << " bd-id:" << m_bd_id << " rd-id:" << m_rd_id
    << " itf:" << m_itf;

  return (s.str());
}

delete_cmd::delete_cmd(HW::item<bool>& item, epg_id_t epg_id)
  : rpc_cmd(item)
  , m_epg_id(epg_id)
{
}

bool
delete_cmd::operator==(const delete_cmd& other) const
{
  return (m_epg_id == other.m_epg_id);
}

rc_t
delete_cmd::issue(connection& con)
{
  msg_t req(con.ctx(), std::ref(*this));

  auto& payload = req.get_request().get_payload();
  payload.epg_id = m_epg_id;

  VAPI_CALL(req.execute());

  return (wait());
}

std::string
delete_cmd::to_string() const
{
  std::ostringstream s;
  s << "gbp-endpoint-group-delete: " << m_hw_item.to_string()
    << " epg:" << m_epg_id;

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
  return ("gbp-endpoint-group-dump");
}

}; // namespace gbp_endpoint_group_cmds
}; // namespace VOM

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */
