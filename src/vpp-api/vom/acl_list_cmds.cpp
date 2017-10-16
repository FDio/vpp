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

#include "vom/acl_list.hpp"

namespace VOM {
namespace ACL {
template <>
rc_t
l3_list::update_cmd::issue(connection& con)
{
  msg_t req(con.ctx(), m_rules.size(), std::ref(*this));
  uint32_t ii = 0;

  auto& payload = req.get_request().get_payload();
  payload.acl_index = m_hw_item.data().value();
  payload.count = m_rules.size();
  memset(payload.tag, 0, sizeof(payload.tag));
  memcpy(payload.tag, m_key.c_str(),
         std::min(m_key.length(), sizeof(payload.tag)));

  auto it = m_rules.cbegin();

  while (it != m_rules.cend()) {
    it->to_vpp(payload.r[ii]);
    ++it;
    ++ii;
  }

  VAPI_CALL(req.execute());

  m_hw_item = wait();
  complete();

  return rc_t::OK;
}

template <>
rc_t
l3_list::delete_cmd::issue(connection& con)
{
  msg_t req(con.ctx(), std::ref(*this));

  auto& payload = req.get_request().get_payload();
  payload.acl_index = m_hw_item.data().value();

  VAPI_CALL(req.execute());

  wait();
  m_hw_item.set(rc_t::NOOP);

  return rc_t::OK;
}

template <>
rc_t
l3_list::dump_cmd::issue(connection& con)
{
  m_dump.reset(new msg_t(con.ctx(), std::ref(*this)));

  auto& payload = m_dump->get_request().get_payload();
  payload.acl_index = ~0;

  VAPI_CALL(m_dump->execute());

  wait();

  return rc_t::OK;
}

template <>
rc_t
l2_list::update_cmd::issue(connection& con)
{
  msg_t req(con.ctx(), m_rules.size(), std::ref(*this));
  uint32_t ii = 0;

  auto& payload = req.get_request().get_payload();
  // payload.acl_index = m_hw_item.data().value();
  payload.count = m_rules.size();
  memset(payload.tag, 0, sizeof(payload.tag));
  memcpy(payload.tag, m_key.c_str(),
         std::min(m_key.length(), sizeof(payload.tag)));

  auto it = m_rules.cbegin();

  while (it != m_rules.cend()) {
    it->to_vpp(payload.r[ii]);
    ++it;
    ++ii;
  }

  VAPI_CALL(req.execute());

  m_hw_item = wait();

  return rc_t::OK;
}

template <>
rc_t
l2_list::delete_cmd::issue(connection& con)
{
  msg_t req(con.ctx(), std::ref(*this));

  auto& payload = req.get_request().get_payload();
  payload.acl_index = m_hw_item.data().value();

  VAPI_CALL(req.execute());

  wait();
  m_hw_item.set(rc_t::NOOP);

  return rc_t::OK;
}

template <>
rc_t
l2_list::dump_cmd::issue(connection& con)
{
  m_dump.reset(new msg_t(con.ctx(), std::ref(*this)));

  auto& payload = m_dump->get_request().get_payload();
  payload.acl_index = ~0;

  VAPI_CALL(m_dump->execute());

  wait();

  return rc_t::OK;
}
}
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */
