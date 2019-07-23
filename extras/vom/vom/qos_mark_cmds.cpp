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

#include "vom/qos_mark_cmds.hpp"
#include "vom/qos_types_api.hpp"

namespace VOM {
namespace QoS {
namespace mark_cmds {

create_cmd::create_cmd(HW::item<bool>& item,
                       const handle_t& itf,
                       uint32_t map_id,
                       const source_t& s)
  : rpc_cmd(item)
  , m_itf(itf)
  , m_map_id(map_id)
  , m_src(s)
{
}

bool
create_cmd::operator==(const create_cmd& other) const
{
  return ((m_itf == other.m_itf) && (m_src == other.m_src) &&
          (m_map_id == other.m_map_id));
}

rc_t
create_cmd::issue(connection& con)
{
  msg_t req(con.ctx(), std::ref(*this));

  auto& payload = req.get_request().get_payload();
  payload.mark.sw_if_index = m_itf.value();
  payload.mark.map_id = m_map_id;
  payload.mark.output_source = to_api(m_src);

  VAPI_CALL(req.execute());

  return (wait());
}

std::string
create_cmd::to_string() const
{
  std::ostringstream s;
  s << "qos-mark-create: " << m_hw_item.to_string() << " itf:" << m_itf
    << " src:" << m_src.to_string() << " map-id:" << m_map_id;

  return (s.str());
}

delete_cmd::delete_cmd(HW::item<bool>& item,
                       const handle_t& itf,
                       const source_t& s)
  : rpc_cmd(item)
  , m_itf(itf)
  , m_src(s)
{
}

bool
delete_cmd::operator==(const delete_cmd& other) const
{
  return (m_hw_item == other.m_hw_item && m_itf == other.m_itf &&
          m_src == other.m_src);
}

rc_t
delete_cmd::issue(connection& con)
{
  msg_t req(con.ctx(), std::ref(*this));

  auto& payload = req.get_request().get_payload();
  payload.mark.sw_if_index = m_itf.value();
  payload.mark.output_source = to_api(m_src);

  VAPI_CALL(req.execute());

  return (wait());
}

std::string
delete_cmd::to_string() const
{
  std::ostringstream s;
  s << "qos-mark-delete: " << m_hw_item.to_string();

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
  return ("qos-mark-dump");
}

}; // namespace mark_cmds
}; // namespace QoS
}; // namespace VOM

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */
