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

#include "vom/bond_member.hpp"

namespace VOM {
/**
 * Construct a new object matching the desried state
 */
bond_member::bond_member(const interface& itf, mode_t mode, rate_t rate)
  : m_itf(itf.singular())
  , m_mode(mode)
  , m_rate(rate)
{
}

bond_member::~bond_member()
{
}

bond_member::bond_member(const bond_member& o)
  : m_itf(o.m_itf)
  , m_mode(o.m_mode)
  , m_rate(o.m_rate)
{
}

void
bond_member::to_vpp(vapi_payload_bond_enslave& bond_enslave) const
{
  bond_enslave.sw_if_index = m_itf->handle().value();
  if (m_mode == mode_t::PASSIVE)
    bond_enslave.is_passive = 1;
  if (m_rate == rate_t::SLOW)
    bond_enslave.is_long_timeout = 1;
}

std::string
bond_member::to_string() const
{
  std::ostringstream s;

  s << m_itf->to_string() << " mode:" << m_mode.to_string()
    << " rate:" << m_rate.to_string();

  return (s.str());
}

bool
bond_member::operator<(const bond_member& itf) const
{
  return (m_itf->handle() < itf.m_itf->handle());
}

void
bond_member::set(mode_t mode)
{
  m_mode = mode;
}

void
bond_member::set(rate_t rate)
{
  m_rate = rate;
}

const handle_t
bond_member::hdl(void) const
{
  return m_itf->handle();
}

bool
bond_member::operator==(const bond_member& b) const
{
  return ((m_itf == b.m_itf) && (m_mode == b.m_mode) && (m_rate == b.m_rate));
}
}; // namespace VOM

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */
