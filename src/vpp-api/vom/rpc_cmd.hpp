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

#ifndef __VOM_RPC_CMD_H__
#define __VOM_RPC_CMD_H__

#include <future>

#include "vom/cmd.hpp"
#include "vom/logger.hpp"

namespace VOM {
/**
 * A base class for all RPC commands to VPP.
 *  RPC commands are one of the sub-set of command types to VPP
 * that modify/create state in VPP and thus return an error code.
 * Commands are issued in one thread context, but read in another. The
 * command has an associated std::promise that is met by the RX thread.
 * this allows the sender, which waits on the promise's future, to
 * experience a synchronous command.
 *
 * The command is templatised on the type of the HW::item to be set by
 * the command, and the data returned in the promise,
 */
template <typename HWITEM, typename DATA, typename MSG>
class rpc_cmd : public cmd
{
public:
  /**
   * convenient typedef
   */
  typedef MSG msg_t;

  /**
   * Constructor taking the HW item that will be updated by the command
   */
  rpc_cmd(HWITEM& item)
    : cmd()
    , m_hw_item(item)
    , m_promise()
  {
  }

  /**
   * Desructor
   */
  virtual ~rpc_cmd() {}

  /**
   * return the HW item the command updates
   */
  HWITEM& item() { return m_hw_item; }

  /**
   * return the const HW item the command updates
   */
  const HWITEM& item() const { return m_hw_item; }

  /**
   * Fulfill the commands promise. Called from the RX thread
   */
  void fulfill(const DATA& d)
  {
    m_promise.set_value(d);

    /*
     * we reset the promise after setting the value to reuse it
     * when we run the retire command from the same cmd object
     */
    //    m_promise = std::promise<DATA>();
  }

  /**
   * Wait on the commands promise. i.e. block on the completion
   * of the command.
   */
  DATA wait()
  {
    std::future_status status;
    std::future<DATA> result;

    result = m_promise.get_future();
    status = result.wait_for(std::chrono::seconds(5));

    if (status != std::future_status::ready) {
      return (DATA(rc_t::TIMEOUT));
    }

    return (result.get());
  }

  /**
   * Called by the HW Command Q when it is disabled to indicate the
   * command can be considered successful without issuing it to HW
   */
  virtual void succeeded() { m_hw_item.set(rc_t::OK); }

  /**
   * call operator used as a callback by VAPI when the reply is available
   */
  virtual vapi_error_e operator()(MSG& reply)
  {
    int retval = reply.get_response().get_payload().retval;
    VOM_LOG(log_level_t::DEBUG) << to_string() << " " << retval;
    fulfill(rc_t::from_vpp_retval(retval));

    return (VAPI_OK);
  }

  /**
   * Retire/cancel a long running command
   */
  virtual void retire(connection& con) {}

protected:
  /**
   * A reference to an object's HW::item that the command will update
   */
  HWITEM& m_hw_item;

  /**
   * The promise that implements the synchronous issue
   */
  std::promise<DATA> m_promise;
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
