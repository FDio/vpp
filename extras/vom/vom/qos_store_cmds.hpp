/*
 * Copyright (c) 2019 Cisco and/or its affiliates.
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

#ifndef __VOM_QOS_STORE_CMDS_H__
#define __VOM_QOS_STORE_CMDS_H__

#include "vom/dump_cmd.hpp"
#include "vom/qos_store.hpp"

#include <vapi/qos.api.vapi.hpp>

namespace VOM {
namespace QoS {
namespace store_cmds {

/**
 * A command class that creates or updates the GBP endpoint
 */
class create_cmd
  : public rpc_cmd<HW::item<bool>, vapi::Qos_store_enable_disable>
{
public:
  /**
   * Constructor
   */
  create_cmd(HW::item<bool>& item,
             const handle_t& itf,
             const source_t& src,
             bits_t value);

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
  const source_t& m_src;
  bits_t m_value;
};

/**
 * A cmd class that deletes a GBP endpoint
 */
class delete_cmd
  : public rpc_cmd<HW::item<bool>, vapi::Qos_store_enable_disable>
{
public:
  /**
   * Constructor
   */
  delete_cmd(HW::item<bool>& item, const handle_t& itf, const source_t& src);

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
  const handle_t m_itf;
  const source_t& m_src;
};

/**
 * A cmd class that Dumps all the GBP endpoints
 */
class dump_cmd : public VOM::dump_cmd<vapi::Qos_store_dump>
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
}; // namespace store_cmds
}; // namespace Qos
}; // namespace VOM

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */

#endif
