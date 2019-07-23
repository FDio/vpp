/*
 * Copyright (c) 2019 Cisco and/or its affiliates.
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

#include "vom/qos_map_cmds.hpp"
#include "vom/qos_types_api.hpp"

namespace VOM {
namespace QoS {
namespace map_cmds {

static void
to_api(const map::outputs_t& o, vapi_type_qos_egress_map_row rows[4])
{
  for (uint32_t ii = 0; ii < 4; ii++) {
    std::copy(o[ii].begin(), o[ii].end(), std::begin(rows[ii].outputs));
  }
}

create_cmd::create_cmd(HW::item<bool>& item,
                       uint32_t id,
                       const map::outputs_t& o)
  : rpc_cmd(item)
  , m_id(id)
  , m_outputs(o)
{
}

bool
create_cmd::operator==(const create_cmd& other) const
{
  return (m_id == other.m_id && m_outputs == other.m_outputs);
}

rc_t
create_cmd::issue(connection& con)
{
  msg_t req(con.ctx(), std::ref(*this));

  auto& payload = req.get_request().get_payload();

  payload.map.id = m_id;
  to_api(m_outputs, payload.map.rows);

  VAPI_CALL(req.execute());

  return (wait());
}

std::string
create_cmd::to_string() const
{
  std::ostringstream s;
  s << "qos-map-create: " << m_hw_item.to_string() << " map:" << m_id;

  return (s.str());
}

delete_cmd::delete_cmd(HW::item<bool>& item, uint32_t id)
  : rpc_cmd(item)
  , m_id(id)
{
}

bool
delete_cmd::operator==(const delete_cmd& other) const
{
  return (m_hw_item == other.m_hw_item && m_id == other.m_id);
}

rc_t
delete_cmd::issue(connection& con)
{
  msg_t req(con.ctx(), std::ref(*this));

  auto& payload = req.get_request().get_payload();
  payload.map.id = m_id;

  VAPI_CALL(req.execute());

  return (wait());
}

std::string
delete_cmd::to_string() const
{
  std::ostringstream s;
  s << "qos-map-delete: " << m_hw_item.to_string() << " map:" << m_id;

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
  return ("qos-map-dump");
}

}; // namespace map_cmds
}; // namespace QoS
}; // namespace VOM

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */
