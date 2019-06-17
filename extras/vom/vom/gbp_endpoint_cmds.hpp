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

#ifndef __VOM_GBP_ENDPOINT_CMDS_H__
#define __VOM_GBP_ENDPOINT_CMDS_H__

#include "vom/dump_cmd.hpp"
#include "vom/gbp_endpoint.hpp"

#include <vapi/gbp.api.vapi.hpp>

namespace VOM {
namespace gbp_endpoint_cmds {

/**
 * A command class that creates or updates the GBP endpoint
 */
class create_cmd : public rpc_cmd<HW::item<handle_t>, vapi::Gbp_endpoint_add>
{
public:
  /**
   * Constructor
   */
  create_cmd(HW::item<handle_t>& item,
             const handle_t& itf,
             const std::vector<boost::asio::ip::address>& ip_addrs,
             const mac_address_t& mac,
             sclass_t sclass,
             const gbp_endpoint::flags_t& flags);

  /**
   * Issue the command to VPP/HW
   */
  rc_t issue(connection& con);

  /**
   * convert to string format for debug purposes
   */
  std::string to_string() const;

  virtual vapi_error_e operator()(vapi::Gbp_endpoint_add& reply);

  /**
   * Comparison operator - only used for UT
   */
  bool operator==(const create_cmd& i) const;

private:
  const handle_t m_itf;
  const std::vector<boost::asio::ip::address> m_ip_addrs;
  const mac_address_t m_mac;
  const sclass_t m_sclass;
  const gbp_endpoint::flags_t m_flags;
};

/**
 * A cmd class that deletes a GBP endpoint
 */
class delete_cmd : public rpc_cmd<HW::item<handle_t>, vapi::Gbp_endpoint_del>
{
public:
  /**
   * Constructor
   */
  delete_cmd(HW::item<handle_t>& item);

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
  const handle_t m_hdl;
};

/**
 * A cmd class that Dumps all the GBP endpoints
 */
class dump_cmd : public VOM::dump_cmd<vapi::Gbp_endpoint_dump>
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
