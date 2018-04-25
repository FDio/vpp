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

#ifndef __VOM_DUMP_CMD_H__
#define __VOM_DUMP_CMD_H__

#include <future>

#include "vom/cmd.hpp"
#include "vom/hw.hpp"

#include <vapi/vapi.hpp>

namespace VOM {
/**
 * A function type def for calculating a message's size
 */
typedef unsigned int (*get_msg_size_t)(void*);

/**
 * A base class for VPP dump commands.
 * Dump commands are one of the sub-set of command types to VPP. Here the
 * client
 * makes a read request on the resource and VPP responds with all the
 * records.
 * This command is executed synchronously. Once complete the client can
 * 'pop'
 * the records from the command object
 */
template <typename MSG>
class dump_cmd : public cmd
{
public:
  typedef MSG msg_t;
  typedef typename MSG::resp_type record_t;

  typedef typename vapi::Result_set<typename MSG::resp_type>::const_iterator
    const_iterator;

  /**
   * Default Constructor
   */
  dump_cmd()
    : cmd()
  {
  }

  /**
   * Destructor
   */
  virtual ~dump_cmd() {}

  dump_cmd(const dump_cmd& d) = default;

  /**
   * Constant iterator to the start of the records retunred during the dump
   */
  const_iterator begin()
  {
    /*
     * m_dump is NULL during client UT when the commands are not issued.
     */
    if (!m_dump)
      return const_iterator();
    return (m_dump->get_result_set().begin());
  }

  /**
   * Constant iterator to the end of the records retunred during the dump
   */
  const_iterator end()
  {
    if (!m_dump)
      return const_iterator();
    return (m_dump->get_result_set().end());
  }

  /**
   * Wait for the issue of the command to complete
   */
  rc_t wait()
  {
    std::future_status status;
    std::future<rc_t> result;

    result = m_promise.get_future();
    status = result.wait_for(std::chrono::seconds(5));

    if (status != std::future_status::ready) {
      return (rc_t::TIMEOUT);
    }

    return (result.get());
  }

  /**
   * Call operator called when the dump is complete
   */
  vapi_error_e operator()(MSG& d)
  {
    m_promise.set_value(rc_t::OK);

    return (VAPI_OK);
  }

  /**
   * Retire/cancel a long running command
   */
  virtual void retire(connection& con) {}

protected:
  /**
   * The underlying promise that implements the synchornous nature
   * of the command issue
   */
  std::promise<rc_t> m_promise;

  /**
   * Dump commands should not be issued whilst the HW is disabled
   */
  void succeeded() {}

  /**
   * The HW::cmd_q is a friend so it can call suceedded.
   */
  friend class HW::cmd_q;

  /**
   * The VAPI event registration
   */
  std::unique_ptr<MSG> m_dump;
};
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */

#endif
