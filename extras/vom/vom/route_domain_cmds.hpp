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

#ifndef __VOM_ROUTE_DOMAIN_CMDS_H__
#define __VOM_ROUTE_DOMAIN_CMDS_H__

#include "vom/dump_cmd.hpp"
#include "vom/route_domain.hpp"
#include "vom/rpc_cmd.hpp"

#include <vapi/ip.api.vapi.hpp>

namespace VOM {
namespace route_domain_cmds {

/**
 * A command class that creates the IP table
 */
class create_cmd : public rpc_cmd<HW::item<bool>, vapi::Ip_table_add_del>
{
public:
  /**
   * Constructor
   */
  create_cmd(HW::item<bool>& item, l3_proto_t proto, route::table_id_t id);

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
  /**
   * table-ID to create
   */
  route::table_id_t m_id;

  /**
   * L3 protocol of the table
   */
  l3_proto_t m_proto;
};

/**
 * A cmd class that Deletes the IP Table
 */
class delete_cmd : public rpc_cmd<HW::item<bool>, vapi::Ip_table_add_del>
{
public:
  /**
   * Constructor
   */
  delete_cmd(HW::item<bool>& item, l3_proto_t proto, route::table_id_t id);

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
  /**
   * table-ID to create
   */
  route::table_id_t m_id;

  /**
   * L3 protocol of the table
   */
  l3_proto_t m_proto;
};

/**
 * A cmd class that Dumps IP fib tables
 */
class dump_cmd : public VOM::dump_cmd<vapi::Ip_table_dump>
{
public:
  /**
   * Constructor
   */
  dump_cmd();
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
};

}; // namespace route_domain_cmds
}; // namespace VOM

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */

#endif
