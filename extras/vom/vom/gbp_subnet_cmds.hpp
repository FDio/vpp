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

#ifndef __VOM_GBP_SUBNET_CMDS_H__
#define __VOM_GBP_SUBNET_CMDS_H__

#include "vom/dump_cmd.hpp"
#include "vom/gbp_subnet.hpp"

#include <vapi/gbp.api.vapi.hpp>

namespace VOM {
namespace gbp_subnet_cmds {

/**
* A command class that creates or updates the GBP subnet
*/
class create_cmd : public rpc_cmd<HW::item<bool>, vapi::Gbp_subnet_add_del>
{
public:
  /**
   * Constructor
   */
  create_cmd(HW::item<bool>& item,
             route::table_id_t rd,
             const route::prefix_t& prefix,
             const gbp_subnet::type_t& type,
             const handle_t& itf,
             epg_id_t epg_id);

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
  const route::table_id_t m_rd;
  const route::prefix_t m_prefix;
  const gbp_subnet::type_t& m_type;
  const handle_t m_itf;
  const epg_id_t m_epg_id;
};

/**
 * A cmd class that deletes a GBP subnet
 */
class delete_cmd : public rpc_cmd<HW::item<bool>, vapi::Gbp_subnet_add_del>
{
public:
  /**
   * Constructor
   */
  delete_cmd(HW::item<bool>& item,
             route::table_id_t rd,
             const route::prefix_t& prefix);

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
  const route::table_id_t m_rd;
  const route::prefix_t m_prefix;
};

/**
 * A cmd class that Dumps all the GBP subnets
 */
class dump_cmd : public VOM::dump_cmd<vapi::Gbp_subnet_dump>
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
}; // namespace gbp_enpoint_cms
}; // namespace VOM

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */

#endif
