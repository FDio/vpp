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

#include "vom/bond_member_interface.hpp"

namespace VOM {
/**
 * Construct a new object matching the desried state
 */
bond_member_interface::bond_member_interface(const std::string& name,
                                             admin_state_t state,
                                             mode_t mode,
                                             rate_t rate)
  : interface(name, type_t::ETHERNET, state)
  , m_mode(mode)
  , m_rate(rate)
{
}

bond_member_interface::~bond_member_interface()
{
  // not in the DB anymore.
  m_db.release(name(), this);
}

bond_member_interface::bond_member_interface(const bond_member_interface& o)
  : interface(o)
  , m_mode(o.m_mode)
  , m_rate(o.m_rate)
{
}

std::shared_ptr<bond_member_interface>
bond_member_interface::find(const handle_t& hdl)
{
  return std::dynamic_pointer_cast<bond_member_interface>(interface::find(hdl));
}

std::shared_ptr<bond_member_interface>
bond_member_interface::singular() const
{
  return std::dynamic_pointer_cast<bond_member_interface>(singular_i());
}

std::shared_ptr<interface>
bond_member_interface::singular_i() const
{
  return m_db.find_or_add(name(), *this);
}

void
bond_member_interface::to_vpp(vapi_payload_bond_enslave& bond_enslave) const
{
  bond_enslave.sw_if_index = handle().value();
  if (m_mode == mode_t::PASSIVE)
    bond_enslave.is_passive = 1;
  if (m_rate == rate_t::SLOW)
    bond_enslave.is_long_timeout = 1;
}

std::string
bond_member_interface::to_string() const
{
  std::ostringstream s;

  s << interface::to_string() << " mode:" << m_mode.to_string()
    << " rate:" << m_rate.to_string();

  return (s.str());
}

bool
bond_member_interface::operator<(const bond_member_interface& itf) const
{
  return (handle() < itf.handle());
}

void
bond_member_interface::set(mode_t mode)
{
  m_mode = mode;
}

void
bond_member_interface::set(rate_t rate)
{
  m_rate = rate;
}

void
bond_member_interface::set(handle_t& handle)
{
  this->interface::set(handle);
}
}; // namespace VOM

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */
