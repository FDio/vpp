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

#include "vom/gbp_recirc_cmds.hpp"

namespace VOM {
namespace gbp_recirc_cmds {

create_cmd::create_cmd(HW::item<bool>& item,
                       const handle_t& itf,
                       bool is_ext,
                       epg_id_t epg_id)
  : rpc_cmd(item)
  , m_itf(itf)
  , m_is_ext(is_ext)
  , m_epg_id(epg_id)
{
}

bool
create_cmd::operator==(const create_cmd& other) const
{
  return ((m_itf == other.m_itf) && (m_is_ext == other.m_is_ext) &&
          (m_epg_id == other.m_epg_id));
}

rc_t
create_cmd::issue(connection& con)
{
  msg_t req(con.ctx(), std::ref(*this));

  auto& payload = req.get_request().get_payload();
  payload.is_add = 1;
  payload.recirc.sw_if_index = m_itf.value();
  payload.recirc.epg_id = m_epg_id;
  payload.recirc.is_ext = m_is_ext;

  VAPI_CALL(req.execute());

  return (wait());
}

std::string
create_cmd::to_string() const
{
  std::ostringstream s;
  s << "gbp-recirc-create: " << m_hw_item.to_string() << " itf:" << m_itf
    << " ext:" << m_is_ext << " epg-id:" << m_epg_id;

  return (s.str());
}

delete_cmd::delete_cmd(HW::item<bool>& item, const handle_t& itf)
  : rpc_cmd(item)
  , m_itf(itf)
{
}

bool
delete_cmd::operator==(const delete_cmd& other) const
{
  return (m_itf == other.m_itf);
}

rc_t
delete_cmd::issue(connection& con)
{
  msg_t req(con.ctx(), std::ref(*this));

  auto& payload = req.get_request().get_payload();
  payload.is_add = 0;
  payload.recirc.sw_if_index = m_itf.value();
  payload.recirc.epg_id = ~0;

  VAPI_CALL(req.execute());

  return (wait());
}

std::string
delete_cmd::to_string() const
{
  std::ostringstream s;
  s << "gbp-recirc-delete: " << m_hw_item.to_string() << " itf:" << m_itf;

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
  return ("gbp-recirc-dump");
}

}; // namespace gbp_recirc_cmds
}; // namespace VOM

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */
