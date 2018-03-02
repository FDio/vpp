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

#include "vom/interface.hpp"
#include "vom/bond_interface.hpp"
#include "vom/bond_member.hpp"
namespace VOM {
/*
 * constants and enums
 */
const interface::type_t interface::type_t::UNKNOWN(0, "unknown");
const interface::type_t interface::type_t::BVI(1, "BVI");
const interface::type_t interface::type_t::ETHERNET(2, "Ethernet");
const interface::type_t interface::type_t::VXLAN(3, "VXLAN");
const interface::type_t interface::type_t::AFPACKET(4, "AFPACKET");
const interface::type_t interface::type_t::LOOPBACK(5, "LOOPBACK");
const interface::type_t interface::type_t::LOCAL(6, "LOCAL");
const interface::type_t interface::type_t::TAP(7, "TAP");
const interface::type_t interface::type_t::VHOST(8, "VHOST");
const interface::type_t interface::type_t::BOND(9, "Bond");

const interface::oper_state_t interface::oper_state_t::DOWN(0, "down");
const interface::oper_state_t interface::oper_state_t::UP(1, "up");

const interface::admin_state_t interface::admin_state_t::DOWN(0, "down");
const interface::admin_state_t interface::admin_state_t::UP(1, "up");

interface::type_t
interface::type_t::from_string(const std::string& str)
{
  if ((str.find("Virtual") != std::string::npos) ||
      (str.find("vhost") != std::string::npos)) {
    return interface::type_t::VHOST;
  } else if (str.find("Bond") != std::string::npos) {
    return interface::type_t::BOND;
  } else if (str.find("Ethernet") != std::string::npos) {
    return interface::type_t::ETHERNET;
  } else if (str.find("vxlan") != std::string::npos) {
    return interface::type_t::VXLAN;
  } else if (str.find("loop") != std::string::npos) {
    return interface::type_t::LOOPBACK;
  } else if (str.find("host-") != std::string::npos) {
    return interface::type_t::AFPACKET;
  } else if (str.find("local") != std::string::npos) {
    return interface::type_t::LOCAL;
  } else if (str.find("tap") != std::string::npos) {
    return interface::type_t::TAP;
  } else if (str.find("bvi") != std::string::npos) {
    return interface::type_t::BVI;
  }

  return interface::type_t::UNKNOWN;
}

interface::type_t::type_t(int v, const std::string& s)
  : enum_base<interface::type_t>(v, s)
{
}

interface::oper_state_t::oper_state_t(int v, const std::string& s)
  : enum_base<interface::oper_state_t>(v, s)
{
}

interface::admin_state_t::admin_state_t(int v, const std::string& s)
  : enum_base<interface::admin_state_t>(v, s)
{
}

interface::admin_state_t
interface::admin_state_t::from_int(uint8_t v)
{
  if (0 == v) {
    return (interface::admin_state_t::DOWN);
  }
  return (interface::admin_state_t::UP);
}

interface::oper_state_t
interface::oper_state_t::from_int(uint8_t v)
{
  if (0 == v) {
    return (interface::oper_state_t::DOWN);
  }
  return (interface::oper_state_t::UP);
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
const bond_interface::lb_t bond_interface::lb_t::L23(1, "l23");
const bond_interface::lb_t bond_interface::lb_t::L34(2, "l34");
const bond_interface::lb_t bond_interface::lb_t::UNSPECIFIED(~0, "unspecified");

const bond_interface::lb_t
bond_interface::lb_t::from_numeric_val(uint8_t numeric)
{
  if (0 == numeric) {
    return (bond_interface::lb_t::L2);
  }
  if (1 == numeric) {
    return (bond_interface::lb_t::L23);
  }
  if (2 == numeric) {
    return (bond_interface::lb_t::L34);
  }

  return (bond_interface::lb_t::UNSPECIFIED);
}

bond_interface::lb_t::lb_t(int v, const std::string& s)
  : enum_base<bond_interface::lb_t>(v, s)
{
}

const bond_member::mode_t bond_member::mode_t::ACTIVE(0, "active");
const bond_member::mode_t bond_member::mode_t::PASSIVE(1, "passive");

const bond_member::mode_t
bond_member::mode_t::from_numeric_val(uint8_t numeric)
{
  if (0 == numeric)
    return (bond_member::mode_t::ACTIVE);

  return (bond_member::mode_t::PASSIVE);
}

bond_member::mode_t::mode_t(int v, const std::string& s)
  : enum_base<bond_member::mode_t>(v, s)
{
}

const bond_member::rate_t bond_member::rate_t::FAST(0, "fast");
const bond_member::rate_t bond_member::rate_t::SLOW(1, "slow");

const bond_member::rate_t
bond_member::rate_t::from_numeric_val(uint8_t numeric)
{
  if (0 == numeric)
    return (bond_member::rate_t::FAST);

  return (bond_member::rate_t::SLOW);
}

bond_member::rate_t::rate_t(int v, const std::string& s)
  : enum_base<bond_member::rate_t>(v, s)
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
