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

#ifndef __VOM_NAT_STATIC_CMDS_H__
#define __VOM_NAT_STATIC_CMDS_H__

#include "nat_static.hpp"
#include "vom/dump_cmd.hpp"

#include <vapi/nat.api.vapi.hpp>

namespace VOM {
namespace nat_static_cmds {

/**
 * A command class that creates NAT 44 static mapping
 */
class create_44_cmd
  : public rpc_cmd<HW::item<bool>, rc_t, vapi::Nat44_add_del_static_mapping>
{
public:
  /**
   * Constructor
   */
  create_44_cmd(HW::item<bool>& item,
                route::table_id_t id,
                const boost::asio::ip::address_v4& inside,
                const boost::asio::ip::address_v4& outside);

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
  bool operator==(const create_44_cmd& i) const;

private:
  route::table_id_t m_id;
  const boost::asio::ip::address_v4 m_inside;
  const boost::asio::ip::address_v4 m_outside;
};

/**
 * A cmd class that deletes a NAT 44 static mapping
 */
class delete_44_cmd
  : public rpc_cmd<HW::item<bool>, rc_t, vapi::Nat44_add_del_static_mapping>
{
public:
  /**
   * Constructor
   */
  delete_44_cmd(HW::item<bool>& item,
                route::table_id_t id,
                const boost::asio::ip::address_v4& inside,
                const boost::asio::ip::address_v4& outside);

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
  bool operator==(const delete_44_cmd& i) const;

private:
  route::table_id_t m_id;
  const boost::asio::ip::address_v4 m_inside;
  const boost::asio::ip::address_v4 m_outside;
};

/**
 * A cmd class that Dumps all the nat_statics
 */
class dump_44_cmd : public dump_cmd<vapi::Nat44_static_mapping_dump>
{
public:
  /**
   * Constructor
   */
  dump_44_cmd();
  dump_44_cmd(const dump_44_cmd& d);

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
  bool operator==(const dump_44_cmd& i) const;

private:
  /**
   * HW reutrn code
   */
  HW::item<bool> item;
};
}; // namespace nat_static_cmds
}; // namespace vom

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */

#endif
