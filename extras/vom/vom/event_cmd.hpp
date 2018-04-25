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

#ifndef __VOM_EVENT_CMD_H__
#define __VOM_EVENT_CMD_H__

#include <mutex>

#include "vom/rpc_cmd.hpp"

#include <vapi/vapi.hpp>

namespace VOM {
/**
 * An Event command base class.
 * Events are one of the sub-set of command type to VPP.
 * A client performs a one time 'registration/subsription' to VPP for the
 * event in question and then is notified asynchronously when those events
 * occur.
 * The model here then is that the lifetime of the event command represensts
 * the during of the clients subscription. When the command is 'issued' the
 * subscription begins, when it is 'retired' the subscription ends. For the
 * subscription duration the client will be notified as events are recieved.
 * The client can then 'pop' these events from this command object.
 */
template <typename WANT, typename EVENT>
class event_cmd : public rpc_cmd<HW::item<bool>, rc_t, WANT>
{
public:
  /**
   * Default constructor
   */
  event_cmd(HW::item<bool>& b)
    : rpc_cmd<HW::item<bool>, rc_t, WANT>(b)
  {
  }

  /**
   * Default destructor
   */
  virtual ~event_cmd() {}

  /**
   * Typedef for the event type
   */
  typedef typename vapi::Event_registration<EVENT>::resp_type event_t;
  typedef typename vapi::Event_registration<EVENT> reg_t;

  typedef typename vapi::Result_set<typename reg_t::resp_type>::const_iterator
    const_iterator;

  const_iterator begin() { return (m_reg->get_result_set().begin()); }

  const_iterator end() { return (m_reg->get_result_set().end()); }

  void lock() { m_mutex.lock(); }
  void unlock() { m_mutex.unlock(); }

  /**
   * flush/free all the events thus far reeived.
   * Call with the lock held!
   */
  void flush() { m_reg->get_result_set().free_all_responses(); }

  /**
   * Retire the command. This is only appropriate for Event Commands
   * As they persist until retired.
   */
  virtual void retire(connection& con) = 0;

  vapi_error_e operator()(reg_t& dl)
  {
    notify();

    return (VAPI_OK);
  }

protected:
  /**
   * Notify the command that data from VPP has arrived and been stored.
   * The command should now inform its clients/listeners.
   */
  virtual void notify() = 0;

  /**
   * The VAPI event registration
   */
  std::unique_ptr<vapi::Event_registration<EVENT>> m_reg;

  /**
   * Mutex protection for the events
   */
  std::mutex m_mutex;
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
