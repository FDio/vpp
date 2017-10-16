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

#ifndef __VOM_DHCP_INTERFACE_H__
#define __VOM_DHCP_INTERFACE_H__

#include "vom/dump_cmd.hpp"
#include "vom/hw.hpp"
#include "vom/inspect.hpp"
#include "vom/interface.hpp"
#include "vom/object_base.hpp"
#include "vom/om.hpp"
#include "vom/rpc_cmd.hpp"
#include "vom/singular_db.hpp"
#include "vom/sub_interface.hpp"

#include <vapi/dhcp.api.vapi.hpp>

namespace VOM {
/**
 * A representation of DHCP client configuration on an interface
 */
class dhcp_config : public object_base
{
public:
  /**
   * Construct a new object matching the desried state
   */
  dhcp_config(const interface& itf, const std::string& hostname);

  /**
   * Construct a new object matching the desried state
   */
  dhcp_config(const interface& itf,
              const std::string& hostname,
              const l2_address_t& client_id);

  /**
   * Copy Constructor
   */
  dhcp_config(const dhcp_config& o);

  /**
   * Destructor
   */
  ~dhcp_config();

  /**
   * Return the 'singular' of the DHCP config that matches this object
   */
  std::shared_ptr<dhcp_config> singular() const;

  /**
   * convert to string format for debug purposes
   */
  std::string to_string() const;

  /**
   * Dump all DHCP configs into the stream provided
   */
  static void dump(std::ostream& os);

  /**
   * A command class that binds the DHCP config to the interface
   */
  class bind_cmd
    : public rpc_cmd<HW::item<bool>, rc_t, vapi::Dhcp_client_config>
  {
  public:
    /**
     * Constructor
     */
    bind_cmd(HW::item<bool>& item,
             const handle_t& itf,
             const std::string& hostname,
             const l2_address_t& client_id);

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
    bool operator==(const bind_cmd& i) const;

  private:
    /**
     * Reference to the HW::item of the interface to bind
     */
    const handle_t& m_itf;

    /**
     * The DHCP client's hostname
     */
    const std::string m_hostname;

    /**
     * The DHCP client's ID
     */
    const l2_address_t m_client_id;
  };

  /**
   * A cmd class that Unbinds Dhcp Config from an interface
   */
  class unbind_cmd
    : public rpc_cmd<HW::item<bool>, rc_t, vapi::Dhcp_client_config>
  {
  public:
    /**
     * Constructor
     */
    unbind_cmd(HW::item<bool>& item,
               const handle_t& itf,
               const std::string& hostname);

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
    bool operator==(const unbind_cmd& i) const;

  private:
    /**
     * Reference to the HW::item of the interface to unbind
     */
    const handle_t& m_itf;

    /**
     * The DHCP client's hostname
     */
    const std::string m_hostname;
  };

  /**
   * Forward declartion of the Event Command
   */
  class events_cmd;

  /**
   * A class that listens to DHCP Events
   */
  class event_listener
  {
  public:
    /**
     * Constructor
     */
    event_listener();

    /**
     * listener's virtual function invoked when a DHCP event is
     * available to read
     */
    virtual void handle_dhcp_event(events_cmd* cmd) = 0;

    /**
     * Return the HW::item associated with this command
     */
    HW::item<bool>& status();

  protected:
    /**
     * The HW::item associated with this command
     */
    HW::item<bool> m_status;
  };

  /**
   * A functor class represents our desire to recieve interface events
   */
  class events_cmd
    : public event_cmd<vapi::Control_ping, vapi::Dhcp_compl_event>
  {
  public:
    /**
     * Constructor
     */
    events_cmd(event_listener& el);

    /**
     * Issue the command to VPP/HW - subscribe to DHCP events
     */
    rc_t issue(connection& con);

    /**
     * Retire the command - unsubscribe
     */
    void retire(connection& con);
    /**
     * convert to string format for debug purposes
     */
    std::string to_string() const;

    /**
     * Comparison operator - only used for UT
     */
    bool operator==(const events_cmd& i) const;

    /**
     * called in the VAPI RX thread when data is available.
     */
    void notify();

  private:
    void succeeded() {}
    /**
     * The listner of this command
     */
    event_listener& m_listener;
  };

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

  /**
   * event_handler to register with OM
   */
  static event_handler m_evh;

  /**
   * Enquue commonds to the VPP command Q for the update
   */
  void update(const dhcp_config& obj);

  /**
   * Find or add DHCP config to the OM
   */
  static std::shared_ptr<dhcp_config> find_or_add(const dhcp_config& temp);

  /*
   * It's the OM class that calls singular()
   */
  friend class OM;

  /**
   * It's the singular_db class that calls replay()
   */
  friend class singular_db<interface::key_type, dhcp_config>;

  /**
   * Sweep/reap the object if still stale
   */
  void sweep(void);

  /**
   * replay the object to create it in hardware
   */
  void replay(void);

  /**
   * A reference counting pointer to the interface on which DHCP config
   * resides. By holding the reference here, we can guarantee that
   * this object will outlive the interface
   */
  const std::shared_ptr<interface> m_itf;

  /**
   * The hostname in the DHCP configuration
   */
  const std::string m_hostname;

  /**
   * The option-61 client_id in the DHCP configuration
   */
  const l2_address_t m_client_id;

  /**
   * HW configuration for the binding. The bool representing the
   * do/don't bind.
 */
  HW::item<bool> m_binding;

  /**
   * A map of all Dhcp configs keyed against the interface.
   */
  static singular_db<interface::key_type, dhcp_config> m_db;
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
