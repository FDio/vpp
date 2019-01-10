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

#ifndef __VOM_ROUTE_CMDS_H__
#define __VOM_ROUTE_CMDS_H__

#include "vom/dump_cmd.hpp"
#include "vom/route.hpp"
#include "vom/rpc_cmd.hpp"

#include <vapi/ip.api.vapi.hpp>

namespace VOM {
namespace route {
namespace ip_route_cmds {

/**
 * A command class that creates or updates the route
 */
class update_cmd : public rpc_cmd<HW::item<bool>, vapi::Ip_add_del_route>
{
public:
  /**
   * Constructor
   */
  update_cmd(HW::item<bool>& item,
             table_id_t id,
             const prefix_t& prefix,
             const path& path);

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
  bool operator==(const update_cmd& i) const;

private:
  route::table_id_t m_id;
  prefix_t m_prefix;
  const path m_path;
};

/**
 * A cmd class that deletes a route
 */
class delete_cmd : public rpc_cmd<HW::item<bool>, vapi::Ip_add_del_route>
{
public:
  /**
   * Constructor
   */
  delete_cmd(HW::item<bool>& item,
             table_id_t id,
             const prefix_t& prefix,
             const path& path);

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
  route::table_id_t m_id;
  prefix_t m_prefix;
  const path m_path;
};

/**
 * A cmd class that Dumps ipv4 fib
 */
class dump_v4_cmd : public VOM::dump_cmd<vapi::Ip_fib_dump>
{
public:
  /**
   * Constructor
   */
  dump_v4_cmd();
  dump_v4_cmd(const dump_cmd& d);

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
  bool operator==(const dump_v4_cmd& i) const;

private:
  /**
   * HW reutrn code
   */
  HW::item<bool> item;
};

/**
 * A cmd class that Dumps ipv6 fib
 */
class dump_v6_cmd : public VOM::dump_cmd<vapi::Ip6_fib_dump>
{
public:
  /**
   * Constructor
   */
  dump_v6_cmd();
  dump_v6_cmd(const dump_cmd& d);

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
  bool operator==(const dump_v6_cmd& i) const;

private:
  /**
   * HW reutrn code
   */
  HW::item<bool> item;
};

}; // namespace ip_route_cmds
}; // namespace route
}; // namespace VOM

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */

#endif
