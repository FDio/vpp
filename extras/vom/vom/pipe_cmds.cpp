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

#include "vom/pipe_cmds.hpp"

DEFINE_VAPI_MSG_IDS_PIPE_API_JSON;

namespace VOM {
namespace pipe_cmds {

create_cmd::create_cmd(HW::item<handle_t>& item,
                       const std::string& name,
                       uint32_t instance,
                       HW::item<pipe::handle_pair_t>& ends)
  : interface::create_cmd<vapi::Pipe_create>(item, name)
  , m_hdl_pair(ends)
  , m_instance(instance)
{
}

bool
create_cmd::operator==(const create_cmd& other) const
{
  return (m_name == other.m_name);
}

vapi_error_e
create_cmd::operator()(vapi::Pipe_create& reply)
{
  auto& payload = reply.get_response().get_payload();

  VOM_LOG(log_level_t::DEBUG) << to_string() << " " << payload.retval;

  const rc_t& rc = rc_t::from_vpp_retval(payload.retval);

  m_hdl_pair = { pipe::handle_pair_t(payload.pipe_sw_if_index[0],
                                     payload.pipe_sw_if_index[1]),
                 rc };

  fulfill(HW::item<handle_t>(payload.sw_if_index, rc));

  return (VAPI_OK);
}
rc_t
create_cmd::issue(connection& con)
{
  msg_t req(con.ctx(), std::ref(*this));

  auto& payload = req.get_request().get_payload();

  payload.is_specified = 1;
  payload.user_instance = m_instance;

  VAPI_CALL(req.execute());

  if (rc_t::OK == wait()) {
    insert_interface();
  }

  return rc_t::OK;
}

std::string
create_cmd::to_string() const
{
  std::ostringstream s;

  s << "pipe-create: " << m_name << " instance:" << m_instance;

  return (s.str());
}

delete_cmd::delete_cmd(HW::item<handle_t>& item,
                       HW::item<pipe::handle_pair_t>& end_pair)
  : interface::delete_cmd<vapi::Pipe_delete>(item)
  , m_hdl_pair(end_pair)
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

  VAPI_CALL(req.execute());

  wait();
  m_hw_item.set(rc_t::NOOP);
  m_hdl_pair.set(rc_t::NOOP);

  remove_interface();

  return (rc_t::OK);
}

std::string
delete_cmd::to_string() const
{
  return ("pipe-delete");
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
  return ("pipe-dump");
}

} // namespace pipe_cmds
} // namespace VOM

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */
