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

#ifndef __VOM_PIPE_H__
#define __VOM_PIPE_H__

#include "vom/interface.hpp"

namespace VOM {
/**
 * A Pipe interface.
 * A pipe is composed for 3 'interfaces'.
 *  1) the 'parent' interface - this is used as the 'key' for the pipe
 *  2) the two 'ends' of the pipe - these are used to RX/TX packets
 *     form/to. The ends are retreivable using the east()/west() functions.
 *     The east and west end are exactly equivalent, they are merely
 *     named differently for logical purposes.
 */
class pipe : public interface
{
public:
  typedef std::pair<handle_t, handle_t> handle_pair_t;

  /**
   * Construct a new object matching the desried state
   */
  pipe(uint32_t instance, admin_state_t state);

  /**
   * Destructor
   */
  ~pipe();

  /**
   * Copy Constructor
   */
  pipe(const pipe& o);

  /**
   * comparison operator - for UT
   */
  bool operator==(const pipe& s) const;

  /**
   * Return the matching 'singular instance' of the sub-interface
   */
  std::shared_ptr<pipe> singular() const;

  /**
   * Find a subinterface from its key
   */
  static std::shared_ptr<pipe> find(const key_t& k);

  /**
   * The interface that is the east end of the pipe
   */
  std::shared_ptr<interface> east();

  /**
   * The interface that is the west end of the pipe.
   * The east and west end are exactly equivalent, they are merely
   * named differently for logical purposes.
   */
  std::shared_ptr<interface> west();

  virtual std::string to_string(void) const;

  void set_ends(const handle_pair_t& p);

private:
  /**
   * The interface type that forms the ends of the pipe
   */
  class pipe_end : public interface
  {
  public:
    pipe_end(const pipe& p, uint8_t id);

  private:
    virtual std::queue<cmd*>& mk_create_cmd(std::queue<cmd*>& cmds);
    virtual std::queue<cmd*>& mk_delete_cmd(std::queue<cmd*>& cmds);

    std::shared_ptr<pipe> m_pipe;
  };

  /**
*Class definition for listeners to OM events
*/
  class event_handler : public OM::listener, public inspect::command_handler
  {
  public:
    event_handler();
    virtual ~event_handler() = default;

    /**
     * Handle a populate event
     */
    void handle_populate(const client_db::key_t& key);

    /**
     * Handle a replay event
     */
    void handle_replay();

    /**
     * Show the object in the Singular DB
     */
    void show(std::ostream& os);

    /**
     * Get the sortable Id of the listener
     */
    dependency_t order() const;
  };
  static event_handler m_evh;

  /**
   * Return the matching 'instance' of the pipe
   *  over-ride from the base class
   */
  std::shared_ptr<interface> singular_i() const;

  /**
   * Virtual functions to construct an interface create commands.
   */
  virtual std::queue<cmd*>& mk_create_cmd(std::queue<cmd*>& cmds);

  /**
   * Virtual functions to construct an interface delete commands.
   */
  virtual std::queue<cmd*>& mk_delete_cmd(std::queue<cmd*>& cmds);

  /**
   * the handles that are set during the create command
   */
  HW::item<handle_pair_t> m_hdl_pair;

  /**
   * The ends of the pipe
   */
  std::shared_ptr<interface> m_ends[2];

  /**
   * Instance number
   */
  uint32_t m_instance;
};

}; // namespace VOM

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */

#endif
