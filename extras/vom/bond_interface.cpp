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

#include "vom/bond_interface.hpp"
#include "vom/bond_group_binding.hpp"
#include "vom/bond_group_binding_cmds.hpp"
#include "vom/bond_interface_cmds.hpp"

namespace VOM {
/**
 * Construct a new object matching the desried state
 */
bond_interface::bond_interface(const std::string& name,
                               admin_state_t state,
                               mode_t mode,
                               lb_t lb)
  : interface(name, type_t::BOND, state)
  , m_l2_address(l2_address_t::ZERO)
  , m_mode(mode)
  , m_lb(lb)
{
}

bond_interface::bond_interface(const std::string& name,
                               admin_state_t state,
                               const l2_address_t& l2_address,
                               mode_t mode,
                               lb_t lb)
  : interface(name, type_t::BOND, state)
  , m_l2_address(l2_address)
  , m_mode(mode)
  , m_lb(lb)
{
}

bond_interface::~bond_interface()
{
  sweep();
  release();
}

bond_interface::bond_interface(const bond_interface& o)
  : interface(o)
  , m_l2_address(o.m_l2_address)
  , m_mode(o.m_mode)
  , m_lb(o.m_lb)
{
}

std::shared_ptr<bond_interface>
bond_interface::find(const handle_t& hdl)
{
  return std::dynamic_pointer_cast<bond_interface>(interface::find(hdl));
}

void
bond_interface::set(bond_interface::mode_t mode)
{
  m_mode = mode;
}

void
bond_interface::set(bond_interface::lb_t lb)
{
  m_lb = lb;
}

std::string
bond_interface::to_string() const
{
  std::ostringstream s;

  s << this->interface::to_string() << " mode:" << m_mode.to_string()
    << " lb:" << m_lb.to_string();

  return (s.str());
}

std::queue<cmd*>&
bond_interface::mk_create_cmd(std::queue<cmd*>& q)
{
  q.push(new bond_interface_cmds::create_cmd(m_hdl, name(), m_mode, m_lb,
                                             m_l2_address));

  return (q);
}

std::queue<cmd*>&
bond_interface::mk_delete_cmd(std::queue<cmd*>& q)
{
  q.push(new bond_interface_cmds::delete_cmd(m_hdl));

  return (q);
}

std::shared_ptr<bond_interface>
bond_interface::singular() const
{
  return std::dynamic_pointer_cast<bond_interface>(singular_i());
}

std::shared_ptr<interface>
bond_interface::singular_i() const
{
  return m_db.find_or_add(name(), *this);
}

void
bond_interface::set(handle_t& handle)
{
  this->interface::set(handle);
}

const bond_interface::mode_t bond_interface::mode_t::ROUND_ROBIN(1,
                                                                 "round-robin");
const bond_interface::mode_t bond_interface::mode_t::ACTIVE_BACKUP(
  2,
  "active-backup");
const bond_interface::mode_t bond_interface::mode_t::XOR(3, "xor");
const bond_interface::mode_t bond_interface::mode_t::BROADCAST(4, "broadcast");
const bond_interface::mode_t bond_interface::mode_t::LACP(5, "lacp");
const bond_interface::mode_t bond_interface::mode_t::UNSPECIFIED(0,
                                                                 "unspecified");

const bond_interface::mode_t
bond_interface::mode_t::from_numeric_val(uint8_t numeric)
{
  if (1 == numeric) {
    return (bond_interface::mode_t::ROUND_ROBIN);
  }
  if (2 == numeric) {
    return (bond_interface::mode_t::ACTIVE_BACKUP);
  }
  if (3 == numeric) {
    return (bond_interface::mode_t::XOR);
  }
  if (4 == numeric) {
    return (bond_interface::mode_t::BROADCAST);
  }
  if (5 == numeric) {
    return (bond_interface::mode_t::LACP);
  }

  return (bond_interface::mode_t::UNSPECIFIED);
}

bond_interface::mode_t::mode_t(int v, const std::string& s)
  : enum_base<bond_interface::mode_t>(v, s)
{
}

const bond_interface::lb_t bond_interface::lb_t::L2(0, "l2");
const bond_interface::lb_t bond_interface::lb_t::L34(1, "l34");
const bond_interface::lb_t bond_interface::lb_t::L23(2, "l23");
const bond_interface::lb_t bond_interface::lb_t::UNSPECIFIED(~0, "unspecified");

const bond_interface::lb_t
bond_interface::lb_t::from_numeric_val(uint8_t numeric)
{
  if (0 == numeric) {
    return (bond_interface::lb_t::L2);
  }
  if (1 == numeric) {
    return (bond_interface::lb_t::L34);
  }
  if (2 == numeric) {
    return (bond_interface::lb_t::L23);
  }

  return (bond_interface::lb_t::UNSPECIFIED);
}

bond_interface::lb_t::lb_t(int v, const std::string& s)
  : enum_base<bond_interface::lb_t>(v, s)
{
}
}; // namespace VOM

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */
