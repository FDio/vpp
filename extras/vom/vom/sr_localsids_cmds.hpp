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

#ifndef __VOM_SR_CMDS_H__
#define __VOM_SR_CMDS_H__

#include "vom/sr_localsids.hpp"
#include "vom/dump_cmd.hpp"
#include "vom/rpc_cmd.hpp"

#include <vapi/sr.api.vapi.hpp>

namespace VOM {
namespace sr_localsids_cmds {

class dump_cmd : public VOM::dump_cmd<vapi::Sr_localsids_dump>
{
public:
  /**
   * Constructor
   */
  dump_cmd() = default;
  ~dump_cmd() = default;

  /**
   * Issue the command to VPP/HW
   */
  rc_t issue(connection& con);
  /**
   * convert to string format for debug purposes
   */
  std::string to_string() const;
  /**
   * Comparison operator - only used for UT
   */
  bool operator==(const dump_cmd& i) const;

private:
  /**
   * HW return code
   */
  HW::item<bool> item;
};

class create_cmd
  : public VOM::rpc_cmd<HW::item<bool>, vapi::Sr_localsid_add_del>
{
public:
  /**
   * Constructor
   */
  create_cmd(HW::item<bool> & item, const localsid::sr_behavior_t& behavior,
             const boost::asio::ip::address_v6& sid,
             handle_t intf = handle_t::INVALID, route::table_id_t vrf = 0);

  create_cmd(HW::item<bool> & item, const localsid::sr_behavior_t& behavior,
             const boost::asio::ip::address_v6& sid,
             const boost::asio::ip::address& nh,
             handle_t intf = handle_t::INVALID, route::table_id_t vrf = 0);

  /**
   * Issue the command to VPP/HW
   */
  rc_t issue(connection &con);
  /**
   * convert to string format for debug purposes
   */
  std::string to_string() const;
  /**
   * Comparison operator - only used for UT
   */
  bool operator==(const create_cmd& i) const;

private:
  const localsid::sr_behavior_t m_behavior;
  const boost::asio::ip::address_v6 m_localsid;
  handle_t m_intf; /* The interface used */
  route::table_id_t m_table_id; /* The VRF used */
  const boost::asio::ip::address m_nh;
};

class delete_cmd
  : public VOM::rpc_cmd<HW::item<bool>, vapi::Sr_localsid_add_del>
{
public:
  /**
   * Constructor
   */
  delete_cmd(HW::item<bool> & item, const boost::asio::ip::address_v6& sid);

  /**
   * Issue the command to VPP/HW
   */
  rc_t issue(connection &con);
  /**
   * convert to string format for debug purposes
   */
  std::string to_string() const;
  /**
   * Comparison operator - only used for UT
   */
  bool operator==(const delete_cmd& i) const;

private:
  const boost::asio::ip::address_v6 m_localsid;
};

}; // namespace sr_localsid
}; // namespace VOM

#endif // __VOM_SR_CMDS_H__
