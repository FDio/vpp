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

#ifndef __VOM_HW_H__
#define __VOM_HW_H__

#include <deque>
#include <map>
#include <sstream>
#include <string>
#include <thread>

#include "vom/connection.hpp"
#include "vom/types.hpp"

namespace VOM {

class cmd;
class HW
{
public:
  /**
   * A HW::item is data that is either to be written to or read from
   * VPP/HW.
   * The item is a pair of the data written/read and the result of that
   * operation.
   */
  template <typename T>
  class item
  {
  public:
    /**
     * Constructor
     */
    item(const T& data)
      : item_data(data)
      , item_rc(rc_t::NOOP)
    {
    }
    /**
     * Constructor
     */
    item()
      : item_data()
      , item_rc(rc_t::UNSET)
    {
    }

    /**
     * Constructor
     */
    item(rc_t rc)
      : item_data()
      , item_rc(rc)
    {
    }

    /**
     * Constructor
     */
    item(const T& data, rc_t rc)
      : item_data(data)
      , item_rc(rc)
    {
    }

    /**
     * Comparison operator
     */
    bool operator==(const item<T>& i) const
    {
      return (item_data == i.item_data);
    }

    /**
     * Copy assignment
     */
    item& operator=(const item& other)
    {
      item_data = other.item_data;
      item_rc = other.item_rc;

      return (*this);
    }

    /**
     * Return the data read/written
     */
    T& data() { return (item_data); }

    /**
     * Const reference to the data
     */
    const T& data() const { return (item_data); }

    /**
     * Get the HW return code
     */
    rc_t rc() const { return (item_rc); }

    /**
     * Set the HW return code - should only be called from the
     * family of Command objects
     */
    void set(const rc_t& rc) { item_rc = rc; }

    /**
     * Return true if the HW item is configred in HW
     */
    operator bool() const { return (rc_t::OK == item_rc); }

    /**
     * update the item to the desired state.
     *  return true if a HW update is required
     */
    bool update(const item& desired)
    {
      bool need_hw_update = false;

      /*
       * if the deisred set is unset (i.e. defaulted, we've
       * no update to make
       */
      if (rc_t::UNSET == desired.rc()) {
        return (false);
      }
      /*
       * A HW update is needed if thestate is different
       * or the state is not yet in HW
       */
      need_hw_update = (item_data != desired.data() || rc_t::OK != rc());

      item_data = desired.data();

      return (need_hw_update);
    }

    /**
     * convert to string format for debug purposes
     */
    std::string to_string() const
    {
      std::ostringstream os;

      os << "hw-item:["
         << "rc:" << item_rc.to_string() << " data:" << item_data.to_string()
         << "]";

      return (os.str());
    }

  private:
    /**
     * The data
     */
    T item_data;

    /**
     * The result when the item was written
     */
    rc_t item_rc;
  };

  /**
   * The pipe to VPP into which we write the commands
   */
  class cmd_q
  {
  public:
    /**
     * Constructor
     */
    cmd_q();
    /**
     * Destructor
     */
    ~cmd_q();

    /**
     * Copy assignement - only used in UT
     */
    cmd_q& operator=(const cmd_q& f);

    /**
     * Enqueue a command into the Q.
     */
    virtual void enqueue(cmd* c);
    /**
     * Enqueue a command into the Q.
     */
    virtual void enqueue(std::shared_ptr<cmd> c);

    /**
     * Enqueue a set of commands
     */
    virtual void enqueue(std::queue<cmd*>& c);

    /**
     * dequeue a command from the Q.
     */
    virtual void dequeue(cmd* c);

    /**
     * dequeue a command from the Q.
     */
    virtual void dequeue(std::shared_ptr<cmd> c);

    /**
     * Write all the commands to HW
     */
    virtual rc_t write();

    /**
     * Blocking Connect to VPP - call once at bootup
     */
    void connect();

    /**
     * Disable the passing of commands to VPP. Whilst disabled all
     * writes will be discarded. Use this during the reset phase.
     */
    void disable();

    /**
     * Enable the passing of commands to VPP - undoes the disable.
     * The Q is enabled by default.
     */
    void enable();

  private:
    /**
     * A queue of enqueued commands, ready to be written
     */
    std::deque<std::shared_ptr<cmd>> m_queue;

    /**
     * A map of issued, but uncompleted, commands.
     *  i.e. those that we are waiting, async stylee,
     * for VPP to complete
     */
    std::map<cmd*, std::shared_ptr<cmd>> m_pending;

    /**
     * VPP Q poll function
     */
    void rx_run();

    /**
     * The thread object running the poll/dispatch/connect thread
     */
    std::unique_ptr<std::thread> m_rx_thread;

    /**
     * A flag indicating the client has disabled the cmd Q.
     */
    bool m_enabled;

    /**
     * A flag for the thread to poll to see if the queue is still alive
     */
    bool m_connected;

    /**
     * The connection to VPP
     */
    connection m_conn;
  };

  /**
   * Initialise the HW connection to VPP - the UT version passing
   * a mock Q.
   */
  static void init(cmd_q* f);

  /**
   * Initialise the HW
   */
  static void init();

  /**
   * Enqueue A command for execution
   */
  static void enqueue(cmd* f);

  /**
   * Enqueue A command for execution
   */
  static void enqueue(std::shared_ptr<cmd> c);

  /**
   * Enqueue A set of commands for execution
   */
  static void enqueue(std::queue<cmd*>& c);

  /**
   * dequeue A command for execution
   */
  static void dequeue(cmd* f);

  /**
   * dequeue A command for execution
   */
  static void dequeue(std::shared_ptr<cmd> c);

  /**
   * Write/Execute all commands hitherto enqueued.
   */
  static rc_t write();

  /**
   * Blocking Connect to VPP
   */
  static void connect();

  /**
   * Blocking pool of the HW connection
   */
  static bool poll();

private:
  /**
   * The command Q toward HW
   */
  static cmd_q* m_cmdQ;

  /**
   * HW::item representing the connection state as determined by polling
   */
  static HW::item<bool> m_poll_state;

  /**
   * Disable the passing of commands to VPP. Whilst disabled all writes
   * will be discarded. Use this during the reset phase.
   */
  static void disable();

  /**
   * Enable the passing of commands to VPP - undoes the disable.
   * The Q is enabled by default.
   */
  static void enable();

  /**
   * Only the OM can enable/disable HW
   */
  friend class OM;
};

/**
 * bool Specialisation for HW::item to_string
 */
template <>
std::string HW::item<bool>::to_string() const;

/**
 * uint Specialisation for HW::item to_string
 */
template <>
std::string HW::item<unsigned int>::to_string() const;
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */

#endif
