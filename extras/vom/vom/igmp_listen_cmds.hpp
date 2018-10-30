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

#ifndef __VOM_IGMP_LISTEN_CMDS_H__
#define __VOM_IGMP_LISTEN_CMDS_H__

#include "vom/dump_cmd.hpp"
#include "vom/igmp_listen.hpp"
#include "vom/rpc_cmd.hpp"

#include <vapi/igmp.api.vapi.hpp>

namespace VOM {
namespace igmp_listen_cmds {

/**
 * A functor class that binds the igmp group to the interface
 */
class listen_cmd : public rpc_cmd<HW::item<bool>, vapi::Igmp_listen>
{
public:
  /**
   * Constructor
   */
  listen_cmd(HW::item<bool>& item,
             const handle_t& itf,
             const boost::asio::ip::address& gaddr,
             const igmp_listen::src_addrs_t& saddrs);

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
  bool operator==(const listen_cmd& i) const;

private:
  /**
   * Reference to the interface to bind to
   */
  const handle_t& m_itf;

  /**
   * The igmp group to bind
   */
  const boost::asio::ip::address& m_gaddr;

  /**
   * The igmp srouce specific addresses to listen them
   */
  const igmp_listen::src_addrs_t& m_saddrs;
};

/**
 * A cmd class that Unbinds igmp group from an interface
 */
class unbind_cmd : public rpc_cmd<HW::item<bool>, vapi::Igmp_listen>
{
public:
  /**
   * Constructor
   */
  unbind_cmd(HW::item<bool>& item,
             const handle_t& itf,
             const boost::asio::ip::address& gaddr);

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
  bool operator==(const unbind_cmd& i) const;

private:
  /**
   * Reference to the interface to unbind
   */
  const handle_t& m_itf;

  /**
   * The igmp group to unbind
   */
  const boost::asio::ip::address& m_gaddr;
};

/**
 * A cmd class that Dumps all the igmp configs
 */
class dump_cmd : public VOM::dump_cmd<vapi::Igmp_dump>
{
public:
  /**
   * Constructor
   */
  dump_cmd(const handle_t& itf);
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
   * The interface to get the igmp config for
   */
  const handle_t& m_itf;
};

}; // namespace igmp_listen_cmds
}; // namespace VOM

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */

#endif
