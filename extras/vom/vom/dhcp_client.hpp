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

#ifndef __VOM_DHCP_CLIENT_H__
#define __VOM_DHCP_CLIENT_H__

#include "vom/hw.hpp"
#include "vom/inspect.hpp"
#include "vom/interface.hpp"
#include "vom/object_base.hpp"
#include "vom/om.hpp"
#include "vom/prefix.hpp"
#include "vom/singular_db.hpp"

namespace VOM {
namespace dhcp_client_cmds {
class events_cmd;
};
/**
 * A representation of DHCP client on an interface
 */
class dhcp_client : public object_base
{
public:
  /**
   * typedef for the DHCP client key type
   */
  typedef interface::key_t key_t;

  struct state_t : enum_base<state_t>
  {
    const static state_t DISCOVER;
    const static state_t REQUEST;
    const static state_t BOUND;

    static const state_t& from_vpp(int i);

  private:
    /**
     * Private constructor taking the value and the string name
     */
    state_t(int v, const std::string& s);
  };

  /**
   * A DHCP lease data
   */
  struct lease_t
  {
    lease_t();
    lease_t(const state_t& state,
            std::shared_ptr<interface> itf,
            const boost::asio::ip::address& router_address,
            const route::prefix_t& host_prefix,
            const std::string& hostname,
            const mac_address_t& mac);

    std::string to_string() const;

    const state_t& state;
    std::shared_ptr<interface> itf;
    boost::asio::ip::address router_address;
    route::prefix_t host_prefix;
    std::string hostname;
    mac_address_t mac;
  };

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
    virtual void handle_dhcp_event(std::shared_ptr<lease_t> e) = 0;

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
   * Construct a new object matching the desried state
   */
  dhcp_client(const interface& itf,
              const std::string& hostname,
              bool set_broadcast_flag = true,
              event_listener* ev = nullptr);

  /**
   * Construct a new object matching the desried state
   */
  dhcp_client(const interface& itf,
              const std::string& hostname,
              const l2_address_t& client_id,
              bool set_broadcast_flag = true,
              event_listener* ev = nullptr);

  /**
   * Copy Constructor
   */
  dhcp_client(const dhcp_client& o);

  /**
   * Destructor
   */
  ~dhcp_client();

  /**
   * Comparison operator - for UT
   */
  bool operator==(const dhcp_client& d) const;

  /**
   * Return the object's key
   */
  const key_t& key() const;

  /**
   * Return the 'singular' of the DHCP client that matches this object
   */
  std::shared_ptr<dhcp_client> singular() const;

  /**
   * convert to string format for debug purposes
   */
  std::string to_string() const;

  /**
   * Dump all DHCP clients into the stream provided
   */
  static void dump(std::ostream& os);

  /**
   * Find a DHCP client from its key
   */
  static std::shared_ptr<dhcp_client> find(const key_t& k);

  /**
   * return the current lease data
   */
  const std::shared_ptr<lease_t> lease() const;

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
  void update(const dhcp_client& obj);

  /**
   * Find or add DHCP client to the OM
   */
  static std::shared_ptr<dhcp_client> find_or_add(const dhcp_client& temp);

  /*
   * It's the OM class that calls singular()
   */
  friend class OM;

  /**
   * It's the singular_db class that calls replay()
   */
  friend class singular_db<key_t, dhcp_client>;

  /**
   * Sweep/reap the object if still stale
   */
  void sweep(void);

  /**
   * replay the object to create it in hardware
   */
  void replay(void);

  void lease(std::shared_ptr<lease_t> l);

  /**
   * A reference counting pointer to the interface on which DHCP client
   * resides. By holding the reference here, we can guarantee that
   * this object will outlive the interface
   */
  const std::shared_ptr<interface> m_itf;

  /**
   * The hostname in the DHCP client
   */
  const std::string m_hostname;

  /**
   * The option-61 client_id in the DHCP client
   */
  const l2_address_t m_client_id;

  /**
   * Flag to control the setting the of DHCP discover's broadcast flag
   */
  const bool m_set_broadcast_flag;

  /**
   * HW configuration for the binding. The bool representing the
   * do/don't bind.
   */
  HW::item<bool> m_binding;

  /**
   * A pointer to an event listener for client events
   */
  event_listener* m_evl;

  /**
   * Current lease state for this client
   */
  std::shared_ptr<lease_t> m_lease;

  std::shared_ptr<dhcp_client_cmds::events_cmd> m_event_cmd;

  void handle_dhcp_event(std::shared_ptr<lease_t> e);

  /**
   * A map of all Dhcp clients keyed against the interface.
   */
  static singular_db<key_t, dhcp_client> m_db;

  static std::weak_ptr<dhcp_client_cmds::events_cmd> m_s_event_cmd;
  static std::shared_ptr<dhcp_client_cmds::events_cmd> get_event_cmd();

  class dhcp_client_listener : public event_listener
  {
  public:
    /**
     * listener's virtual function invoked when a DHCP event is
     * available to read
     */
    void handle_dhcp_event(std::shared_ptr<lease_t> e);
  };
  static dhcp_client_listener m_listener;
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
