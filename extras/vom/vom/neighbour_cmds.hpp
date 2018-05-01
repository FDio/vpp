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

#ifndef __VOM_NEIGHBOUR_CMDS_H__
#define __VOM_NEIGHBOUR_CMDS_H__

#include "vom/dump_cmd.hpp"
#include "vom/srpc_cmd.hpp"
#include "neighbour.hpp"

#include <vapi/ip.api.vapi.hpp>

namespace VOM {
namespace neighbour_cmds {

/**
 * A command class that creates or updates the bridge domain ARP Entry
 */
class create_cmd : public srpc_cmd<vapi::Ip_neighbor_add_del>
{
public:
  /**
   * Constructor
   */
  create_cmd(HW::item<handle_t>& item,
             handle_t itf,
             const mac_address_t& mac,
             const boost::asio::ip::address& ip_addr);

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
  bool operator==(const create_cmd& i) const;

private:
  handle_t m_itf;
  mac_address_t m_mac;
  boost::asio::ip::address m_ip_addr;
};

/**
 * A cmd class that deletes a bridge domain ARP entry
 */
class delete_cmd : public srpc_cmd<vapi::Ip_neighbor_add_del>
{
public:
  /**
   * Constructor
   */
  delete_cmd(HW::item<handle_t>& item,
             handle_t itf,
             const mac_address_t& mac,
             const boost::asio::ip::address& ip_addr);

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
  bool operator==(const delete_cmd& i) const;

private:
  handle_t m_itf;
  mac_address_t m_mac;
  boost::asio::ip::address m_ip_addr;
};

/**
 * A cmd class that Dumps all the neighbours
 */
class dump_cmd : public VOM::dump_cmd<vapi::Ip_neighbor_dump>
{
public:
  /**
   * Constructor
   */
  dump_cmd(const handle_t& itf, const l3_proto_t& proto);
  dump_cmd(const dump_cmd& d);

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
   * HW reutrn code
   */
  HW::item<bool> item;

  /**
   * The interface to dump
   */
  handle_t m_itf;

  /**
   * V4 or V6
   */
  l3_proto_t m_proto;
};

}; // namespace neighbour_cmds
}; // namespace vom
#endif

