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

#include <algorithm>
#include <iomanip>
#include <iostream>
#include <sstream>

#include "vom/types.hpp"

namespace VOM {

rc_t::rc_t(int v, const std::string s)
  : enum_base<rc_t>(v, s)
{
}
rc_t::~rc_t()
{
}

const rc_t&
rc_t::from_vpp_retval(int32_t rv)
{
  if (0 == rv) {
    return (rc_t::OK);
  }
  if (-68 == rv) {
    // interface laready exists
    return (rc_t::OK);
  }

  return (rc_t::INVALID);
}

const rc_t rc_t::UNSET(0, "un-set");
const rc_t rc_t::NOOP(1, "no-op");
const rc_t rc_t::OK(2, "ok");
const rc_t rc_t::INPROGRESS(3, "in-progess");
const rc_t rc_t::INVALID(4, "invalid");
const rc_t rc_t::TIMEOUT(5, "timeout");

const handle_t handle_t::INVALID(~0);

handle_t::handle_t(int value)
  : m_value(value)
{
}

handle_t::handle_t()
  : m_value(~0)
{
}

std::string
handle_t::to_string() const
{
  return (std::to_string(m_value));
}

bool
handle_t::operator==(const handle_t& other) const
{
  return (m_value == other.m_value);
}

bool
handle_t::operator!=(const handle_t& other) const
{
  return (!(*this == other));
}

bool
handle_t::operator<(const handle_t& other) const
{
  return (m_value < other.m_value);
}

uint32_t
handle_t::value() const
{
  return (m_value);
}

std::ostream&
operator<<(std::ostream& os, const handle_t& h)
{
  os << h.value();

  return (os);
}

mac_address_t::mac_address_t(uint8_t b[6])
{
  std::copy(b, b + 6, std::begin(bytes));
}

mac_address_t::mac_address_t(std::initializer_list<uint8_t> i)
{
  std::copy(i.begin(), i.end(), std::begin(bytes));
}

const mac_address_t mac_address_t::ONE({ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff });

const mac_address_t mac_address_t::ZERO({ 0x0 });

void
mac_address_t::to_bytes(uint8_t* array, uint8_t len) const
{
  for (int i = 0; i < 6 && i < len; i++) {
    array[i] = bytes[i];
  }
}

std::string
mac_address_t::to_string() const
{
  std::ostringstream s;
  bool first = true;

  s.fill('0');
  s << std::hex;
  s << "mac:[";
  for (auto byte : bytes) {
    if (first)
      first = false;
    else
      s << ":";
    s << std::setw(2) << static_cast<unsigned int>(byte);
  }
  s << "]";

  return (s.str());
}

bool
mac_address_t::operator==(const mac_address_t& mac) const
{
  return (bytes == mac.bytes);
}
bool
mac_address_t::operator<(const mac_address_t& m) const
{
  return (bytes < m.bytes);
}

std::ostream&
operator<<(std::ostream& os, const mac_address_t& mac)
{
  os << mac.to_string();

  return (os);
}

l2_address_t::l2_address_t(const uint8_t b[8], uint8_t n_bytes)
  : bytes(n_bytes)
{
  std::copy_n(b, n_bytes, std::begin(bytes));
}

l2_address_t::l2_address_t(std::initializer_list<uint8_t> i)
  : bytes(i)
{
}

l2_address_t::l2_address_t(const mac_address_t& mac)
  : bytes(6)
{
  std::copy(begin(mac.bytes), std::end(mac.bytes), std::begin(bytes));
}

const l2_address_t l2_address_t::ONE({ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                       0xff });

const l2_address_t l2_address_t::ZERO({ 0x0 });

void
l2_address_t::to_bytes(uint8_t* array, uint8_t len) const
{
  for (uint8_t i = 0; i < bytes.size() && i < len; i++) {
    array[i] = bytes[i];
  }
}

mac_address_t
l2_address_t::to_mac() const
{
  mac_address_t mac({});

  std::copy_n(bytes.begin(), mac.bytes.size(), mac.bytes.begin());

  return (mac);
}

std::string
l2_address_t::to_string() const
{
  std::ostringstream s;
  bool first = true;

  s.fill('0');
  s << std::hex;
  for (auto byte : bytes) {
    if (first)
      first = false;
    else
      s << ":";
    s << std::setw(2) << static_cast<unsigned int>(byte);
  }

  return (s.str());
}

bool
l2_address_t::operator==(const l2_address_t& l2) const
{
  return (bytes == l2.bytes);
}

bool
l2_address_t::operator!=(const l2_address_t& l2) const
{
  return (bytes != l2.bytes);
}

std::ostream&
operator<<(std::ostream& os, const l2_address_t& l2)
{
  os << l2.to_string();

  return (os);
}

const direction_t direction_t::INPUT(1, "input");
const direction_t direction_t::OUTPUT(0, "output");

direction_t::direction_t(int v, const std::string s)
  : enum_base(v, s)
{
}
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */
