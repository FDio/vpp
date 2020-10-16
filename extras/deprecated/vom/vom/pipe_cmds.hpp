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

#ifndef __VOM_PIPE_CMDS_H__
#define __VOM_PIPE_CMDS_H__

#include "vom/dump_cmd.hpp"
#include "vom/pipe.hpp"
#include "vom/rpc_cmd.hpp"

#include <vapi/pipe.api.vapi.hpp>

namespace VOM {
namespace pipe_cmds {
/**
 * A functor class that creates an interface
 */
class create_cmd : public interface::create_cmd<vapi::Pipe_create>
{
public:
  /**
   * Cstrunctor taking the reference to the parent
   * and the sub-interface's VLAN
   */
  create_cmd(HW::item<handle_t>& item,
             const std::string& name,
             uint32_t instance,
             HW::item<pipe::handle_pair_t>& ends);

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

  virtual vapi_error_e operator()(vapi::Pipe_create& reply);

private:
  HW::item<pipe::handle_pair_t>& m_hdl_pair;
  uint32_t m_instance;
};

/**
 * A cmd class that Delete an interface
 */
class delete_cmd : public interface::delete_cmd<vapi::Pipe_delete>
{
public:
  /**
   * Constructor
   */
  delete_cmd(HW::item<handle_t>& item, HW::item<pipe::handle_pair_t>& end_pair);

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
  HW::item<pipe::handle_pair_t>& m_hdl_pair;
};

/**
 * A cmd class that Dumps all the Vpp interfaces
 */
class dump_cmd : public VOM::dump_cmd<vapi::Pipe_dump>
{
public:
  /**
   * Default Constructor
   */
  dump_cmd() = default;

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
};

}; // namespace pipe_cmds
}; // namespace VOM

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */

#endif
