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

#ifndef __VOM_BOND_INTERFACE_H__
#define __VOM_BOND_INTERFACE_H__

#include "vom/interface.hpp"

namespace VOM {
/**
 * A bond-interface. e.g. a bond interface
 */
class bond_interface : public interface
{
public:
  /**
   * A bond interface mode
   */
  struct mode_t : enum_base<mode_t>
  {
    /**
     * Round-Robin bond interface mode
     */
    const static mode_t ROUND_ROBIN;
    /**
     * Active-backup bond interface mode
     */
    const static mode_t ACTIVE_BACKUP;
    /**
     * XOR bond interface mode
     */
    const static mode_t XOR;
    /**
     * Broadcast bond interface mode
     */
    const static mode_t BROADCAST;
    /**
     * LACP bond interface mode
     */
    const static mode_t LACP;
    /**
     * Unspecificed bond interface mode
     */
    const static mode_t UNSPECIFIED;

    /**
     * Convert VPP's value of the bond to a mode
     */
    static const mode_t from_numeric_val(uint8_t v);

  private:
    /**
     * Private constructor taking the value and the string name
     */
    mode_t(int v, const std::string& s);
  };

  /**
    * A bond interface load balance
    */
  struct lb_t : enum_base<lb_t>
  {
    /**
     * L2 bond interface lb
     */
    const static lb_t L2;
    /**
     * L23 bond interface lb
     */
    const static lb_t L23;
    /**
     * L34 bond interface lb
     */
    const static lb_t L34;
    /**
     * Unspecificed bond interface lb
     */
    const static lb_t UNSPECIFIED;

    /**
     * Convert VPP's value of the bond to a lb
     */
    static const lb_t from_numeric_val(uint8_t v);

  private:
    /**
     * Private constructor taking the value and the string name
     */
    lb_t(int v, const std::string& s);
  };

  bond_interface(const std::string& name,
                 admin_state_t state,
                 mode_t mode,
                 lb_t lb = lb_t::UNSPECIFIED);

  bond_interface(const std::string& name,
                 admin_state_t state,
                 const l2_address_t& l2_address,
                 mode_t mode,
                 lb_t lb = lb_t::UNSPECIFIED);

  ~bond_interface();
  bond_interface(const bond_interface& o);

  /**
   * The the singular instance of the bond interface in the DB by handle
   */
  std::shared_ptr<bond_interface> find(const handle_t& hdl);

  /**
   * Return the matching 'singular instance' of the BOND interface
   */
  std::shared_ptr<bond_interface> singular() const;

  /**
   * set the mode
   */
  void set(mode_t mode);

  /**
   * set the lb
   */
  void set(lb_t lb);
protected:
  /**
   * set the handle
   */
  void set(handle_t& handle);
  friend class interface_factory;

private:
  /**
   * Class definition for listeners to OM events
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
   * l2 address on bond interface
   */
  l2_address_t m_l2_address;

  /**
   *  mode on bond interface
   */
  mode_t m_mode;

  /**
   * lb mode on bond interface
   */
  lb_t m_lb;

  /**
   * interface is a friend so it can construct with handles
   */
  friend class interface;

  /**
   * Return the matching 'instance' of the sub-interface
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

  /*
   * It's the OM class that call singular()
   */
  friend class OM;
};
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */

#endif
