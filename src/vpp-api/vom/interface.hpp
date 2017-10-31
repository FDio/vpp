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

#ifndef __VOM_INTERFACE_H__
#define __VOM_INTERFACE_H__

#include "vom/dump_cmd.hpp"
#include "vom/enum_base.hpp"
#include "vom/event_cmd.hpp"
#include "vom/hw.hpp"
#include "vom/inspect.hpp"
#include "vom/object_base.hpp"
#include "vom/om.hpp"
#include "vom/prefix.hpp"
#include "vom/route_domain.hpp"
#include "vom/rpc_cmd.hpp"
#include "vom/singular_db.hpp"

#include <vapi/af_packet.api.vapi.hpp>
#include <vapi/interface.api.vapi.hpp>
#include <vapi/stats.api.vapi.hpp>
#include <vapi/tap.api.vapi.hpp>
#include <vapi/vapi.hpp>
#include <vapi/vpe.api.vapi.hpp>

namespace VOM {
/**
 * A representation of an interface in VPP
 */
class interface : public object_base
{
public:
  /**
   * The key for interface's key
   */
  typedef std::string key_type;

  /**
   * The iterator type
   */
  typedef singular_db<const std::string, interface>::const_iterator
    const_iterator_t;

  /**
   * An interface type
   */
  struct type_t : enum_base<type_t>
  {
    /**
     * Unkown type
     */
    const static type_t UNKNOWN;
    /**
     * A brideged Virtual interface (aka SVI or IRB)
     */
    const static type_t BVI;
    /**
     * VXLAN interface
     */
    const static type_t VXLAN;
    /**
     * Ethernet interface type
     */
    const static type_t ETHERNET;
    /**
     * AF-Packet interface type
     */
    const static type_t AFPACKET;
    /**
     * loopback interface type
     */
    const static type_t LOOPBACK;
    /**
     * Local interface type (specific to VPP)
     */
    const static type_t LOCAL;
    /**
     * TAP interface type
     */
    const static type_t TAP;

    /**
     * Convert VPP's name of the interface to a type
     */
    static type_t from_string(const std::string& str);

  private:
    /**
     * Private constructor taking the value and the string name
     */
    type_t(int v, const std::string& s);
  };

  /**
   * The admin state of the interface
   */
  struct admin_state_t : enum_base<admin_state_t>
  {
    /**
     * Admin DOWN state
     */
    const static admin_state_t DOWN;
    /**
     * Admin UP state
     */
    const static admin_state_t UP;

    /**
     * Convert VPP's numerical value to enum type
     */
    static admin_state_t from_int(uint8_t val);

  private:
    /**
     * Private constructor taking the value and the string name
     */
    admin_state_t(int v, const std::string& s);
  };

  /**
   * The oper state of the interface
   */
  struct oper_state_t : enum_base<oper_state_t>
  {
    /**
     * Operational DOWN state
     */
    const static oper_state_t DOWN;
    /**
     * Operational UP state
     */
    const static oper_state_t UP;

    /**
     * Convert VPP's numerical value to enum type
     */
    static oper_state_t from_int(uint8_t val);

  private:
    /**
     * Private constructor taking the value and the string name
     */
    oper_state_t(int v, const std::string& s);
  };

  /**
   * Construct a new object matching the desried state
   */
  interface(const std::string& name, type_t type, admin_state_t state);
  /**
   * Construct a new object matching the desried state mapped
   * to a specific route_domain
   */
  interface(const std::string& name,
            type_t type,
            admin_state_t state,
            const route_domain& rd);
  /**
   * Destructor
   */
  virtual ~interface();

  /**
   * Copy Constructor
   */
  interface(const interface& o);

  static const_iterator_t cbegin();
  static const_iterator_t cend();

  /**
   * Return the matching'singular' of the interface
   */
  std::shared_ptr<interface> singular() const;

  /**
   * convert to string format for debug purposes
   */
  virtual std::string to_string(void) const;

  /**
   * Return VPP's handle to this object
   */
  const handle_t& handle() const;

  /**
   * Return the interface type
   */
  const type_t& type() const;

  /**
   * Return the interface type
   */
  const std::string& name() const;

  /**
   * Return the interface type
   */
  const key_type& key() const;

  /**
   * Return the L2 Address
   */
  const l2_address_t& l2_address() const;

  /**
   * Set the L2 Address
   */
  void set(const l2_address_t& addr);

  /**
   * Set the operational state of the interface, as reported by VPP
   */
  void set(const oper_state_t& state);

  /**
   * A base class for interface Create commands
   */
  template <typename MSG>
  class create_cmd : public rpc_cmd<HW::item<handle_t>, HW::item<handle_t>, MSG>
  {
  public:
    create_cmd(HW::item<handle_t>& item, const std::string& name)
      : rpc_cmd<HW::item<handle_t>, HW::item<handle_t>, MSG>(item)
      , m_name(name)
    {
    }

    /**
     * Destructor
     */
    virtual ~create_cmd() = default;

    /**
     * Comparison operator - only used for UT
     */
    virtual bool operator==(const create_cmd& o) const
    {
      return (m_name == o.m_name);
    }

    /**
     * Indicate the succeeded, when the HW Q is disabled.
     */
    void succeeded()
    {
      rpc_cmd<HW::item<handle_t>, HW::item<handle_t>, MSG>::succeeded();
      interface::add(m_name, this->item());
    }

    virtual vapi_error_e operator()(MSG& reply)
    {
      int sw_if_index = reply.get_response().get_payload().sw_if_index;
      int retval = reply.get_response().get_payload().retval;

      VOM_LOG(log_level_t::DEBUG) << this->to_string() << " " << retval;

      rc_t rc = rc_t::from_vpp_retval(retval);
      handle_t handle = handle_t::INVALID;

      if (rc_t::OK == rc) {
        handle = sw_if_index;
      }

      HW::item<handle_t> res(handle, rc);

      this->fulfill(res);

      return (VAPI_OK);
    }

  protected:
    /**
     * The name of the interface to be created
     */
    const std::string& m_name;
  };

  /**
   * A command class to create Loopback interfaces in VPP
   */
  class loopback_create_cmd : public create_cmd<vapi::Create_loopback>
  {
  public:
    /**
     * Constructor taking the HW::item to update
     * and the name of the interface to create
     */
    loopback_create_cmd(HW::item<handle_t>& item, const std::string& name);
    ~loopback_create_cmd() = default;

    /**
     * Issue the command to VPP/HW
     */
    rc_t issue(connection& con);
    /**
     * convert to string format for debug purposes
     */
    std::string to_string() const;
  };

  /**
   * A command class to create af_packet interfaces in VPP
   */
  class af_packet_create_cmd : public create_cmd<vapi::Af_packet_create>
  {
  public:
    /**
     * Constructor taking the HW::item to update
     * and the name of the interface to create
     */
    af_packet_create_cmd(HW::item<handle_t>& item, const std::string& name);
    ~af_packet_create_cmd() = default;
    /**
     * Issue the command to VPP/HW
     */
    rc_t issue(connection& con);
    /**
     * convert to string format for debug purposes
     */
    std::string to_string() const;
  };

  /**
   * A command class to create TAP interfaces in VPP
   */
  class tap_create_cmd : public create_cmd<vapi::Tap_connect>
  {
  public:
    /**
     * Constructor taking the HW::item to update
     * and the name of the interface to create
     */
    tap_create_cmd(HW::item<handle_t>& item, const std::string& name);
    ~tap_create_cmd() = default;

    /**
     * Issue the command to VPP/HW
     */
    rc_t issue(connection& con);

    /**
     * convert to string format for debug purposes
     */
    std::string to_string() const;
  };

  /**
   * Base class for intterface Delete commands
   */
  template <typename MSG>
  class delete_cmd : public rpc_cmd<HW::item<handle_t>, HW::item<handle_t>, MSG>
  {
  public:
    delete_cmd(HW::item<handle_t>& item, const std::string& name)
      : rpc_cmd<HW::item<handle_t>, HW::item<handle_t>, MSG>(item)
      , m_name(name)
    {
    }

    delete_cmd(HW::item<handle_t>& item)
      : rpc_cmd<HW::item<handle_t>, HW::item<handle_t>, MSG>(item)
      , m_name()
    {
    }

    /**
     * Destructor
     */
    virtual ~delete_cmd() = default;

    /**
     * Comparison operator - only used for UT
     */
    virtual bool operator==(const delete_cmd& o) const
    {
      return (this->m_hw_item == o.m_hw_item);
    }

    /**
     * Indicate the succeeded, when the HW Q is disabled.
     */
    void succeeded() {}

  protected:
    /**
     * The name of the interface to be created
     */
    const std::string m_name;
  };

  /**
   * A command class to delete loopback interfaces in VPP
   */
  class loopback_delete_cmd : public delete_cmd<vapi::Delete_loopback>
  {
  public:
    /**
     * Constructor taking the HW::item to update
     */
    loopback_delete_cmd(HW::item<handle_t>& item);

    /**
     * Issue the command to VPP/HW
     */
    rc_t issue(connection& con);
    /**
     * convert to string format for debug purposes
     */
    std::string to_string() const;
  };

  /**
   * A command class to delete af-packet interfaces in VPP
   */
  class af_packet_delete_cmd : public delete_cmd<vapi::Af_packet_delete>
  {
  public:
    /**
     * Constructor taking the HW::item to update
     * and the name of the interface to delete
     */
    af_packet_delete_cmd(HW::item<handle_t>& item, const std::string& name);

    /**
     * Issue the command to VPP/HW
     */
    rc_t issue(connection& con);
    /**
     * convert to string format for debug purposes
     */
    std::string to_string() const;
  };

  /**
   * A command class to delete TAP interfaces in VPP
   */
  class tap_delete_cmd : public delete_cmd<vapi::Tap_delete>
  {
  public:
    /**
     * Constructor taking the HW::item to update
     */
    tap_delete_cmd(HW::item<handle_t>& item);

    /**
     * Issue the command to VPP/HW
     */
    rc_t issue(connection& con);
    /**
     * convert to string format for debug purposes
     */
    std::string to_string() const;
  };

  /**
   * A command class to delete TAP interfaces in VPP
   */
  class set_tag
    : public rpc_cmd<HW::item<handle_t>, rc_t, vapi::Sw_interface_tag_add_del>
  {
  public:
    /**
     * Constructor taking the HW::item to update
     */
    set_tag(HW::item<handle_t>& item, const std::string& name);

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
    bool operator==(const set_tag& i) const;

  private:
    /**
     * The tag to add
     */
    const std::string m_name;
  };

  /**
   * A cmd class that changes the admin state
   */
  class state_change_cmd : public rpc_cmd<HW::item<admin_state_t>,
                                          rc_t,
                                          vapi::Sw_interface_set_flags>
  {
  public:
    /**
     * Constructor taking the HW::item to update
     * and the name handle of the interface whose state is to change
     */
    state_change_cmd(HW::item<admin_state_t>& s, const HW::item<handle_t>& h);

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
    bool operator==(const state_change_cmd& i) const;

  private:
    /**
     * the handle of the interface to update
     */
    const HW::item<handle_t>& m_hdl;
  };

  /**
   * A command class that binds an interface to an L3 table
   */
  class set_table_cmd : public rpc_cmd<HW::item<route::table_id_t>,
                                       rc_t,
                                       vapi::Sw_interface_set_table>
  {
  public:
    /**
     * Constructor taking the HW::item to update
     * and the name handle of the interface whose table is to change
     */
    set_table_cmd(HW::item<route::table_id_t>& item,
                  const l3_proto_t& proto,
                  const HW::item<handle_t>& h);

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
    bool operator==(const set_table_cmd& i) const;

  private:
    /**
     * the handle of the interface to update
     */
    const HW::item<handle_t>& m_hdl;

    /**
     * The L3 protocol of the table
     */
    l3_proto_t m_proto;
  };

  /**
   * A command class that binds an interface to an L3 table
   */
  class set_mac_cmd : public rpc_cmd<HW::item<l2_address_t>,
                                     rc_t,
                                     vapi::Sw_interface_set_mac_address>
  {
  public:
    /**
     * Constructor taking the HW::item to update
     * and the handle of the interface
     */
    set_mac_cmd(HW::item<l2_address_t>& item, const HW::item<handle_t>& h);

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
    bool operator==(const set_mac_cmd& i) const;

  private:
    /**
     * the handle of the interface to update
     */
    const HW::item<handle_t>& m_hdl;
  };

  /**
   * Forward declaration of the Event command
   */
  class events_cmd;

  /**
   * A class that listens to interface Events
   */
  class event_listener
  {
  public:
    /**
     * Default Constructor
     */
    event_listener();

    /**
     * Virtual function called on the listener when the command has data
     * ready to process
     */
    virtual void handle_interface_event(events_cmd* cmd) = 0;

    /**
     * Return the HW::item representing the status
     */
    HW::item<bool>& status();

  protected:
    /**
     * The status of the subscription
     */
    HW::item<bool> m_status;
  };

  /**
   * A command class represents our desire to recieve interface events
   */
  class events_cmd
    : public event_cmd<vapi::Want_interface_events, vapi::Sw_interface_event>
  {
  public:
    /**
     * Constructor taking the listner to notify
     */
    events_cmd(event_listener& el);

    /**
     * Issue the command to VPP/HW
     */
    rc_t issue(connection& con);

    /**
     * Retires the command - unsubscribe from the events.
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
     * Called when it's time to poke the listeners
     */
    void notify();

  private:
    /**
     * The listeners to notify when data/events arrive
     */
    event_listener& m_listener;
  };

  /**
   * Forward declaration of the stat command
   */
  class stats_cmd;

  /**
   * A class that listens to interface Stats
   */
  class stat_listener
  {
  public:
    /**
     * Default Constructor
     */
    stat_listener();

    /**
     * Virtual function called on the listener when the command has data
     * ready to process
     */
    virtual void handle_interface_stat(stats_cmd* cmd) = 0;

    /**
     * Return the HW::item representing the status
     */
    HW::item<bool>& status();

  protected:
    /**
     * The status of the subscription
     */
    HW::item<bool> m_status;
  };

  /**
   * A command class represents our desire to recieve interface stats
   */
  class stats_cmd : public event_cmd<vapi::Want_per_interface_combined_stats,
                                     vapi::Vnet_per_interface_combined_counters>
  {
  public:
    /**
     * Constructor taking the listner to notify
     */
    stats_cmd(stat_listener& el, const std::vector<handle_t>& interfaces);

    /**
     * Issue the command to VPP/HW
     */
    rc_t issue(connection& con);

    /**
     * Retires the command - unsubscribe from the stats.
     */
    void retire(connection& con);

    /**
     * convert to string format for debug purposes
     */
    std::string to_string() const;

    /**
     * Comparison operator - only used for UT
     */
    bool operator==(const stats_cmd& i) const;

    /**
     * Called when it's time to poke the listeners
     */
    void notify();

  private:
    /**
     * The listeners to notify when data/stats arrive
     */
    stat_listener& m_listener;

    std::vector<handle_t> m_swifindex;
  };

  /**
   * A cmd class that Dumps all the Vpp interfaces
   */
  class dump_cmd : public VOM::dump_cmd<vapi::Sw_interface_dump>
  {
  public:
    /**
     * Default Constructor
     */
    dump_cmd();

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

  /**
   * The the singular instance of the interface in the object_base-Model
   */
  static std::shared_ptr<interface> find(const interface& temp);

  /**
   * The the singular instance of the interface in the object_base-Model
   * by handle
   */
  static std::shared_ptr<interface> find(const handle_t& h);

  /**
   * The the singular instance of the interface in the object_base-Model
   * by name
   */
  static std::shared_ptr<interface> find(const std::string& s);

  /**
   * Dump all interfaces into the stream provided
   */
  static void dump(std::ostream& os);

  /**
   * Factory method to construct a new interface from the VPP record
   */
  static std::unique_ptr<interface> new_interface(
    const vapi_payload_sw_interface_details& vd);

protected:
  /**
   * Construct an interface object with a handle and a HW address
   */
  interface(const handle_t& handle,
            const l2_address_t& l2_address,
            const std::string& name,
            type_t type,
            admin_state_t state);

  /**
   * The SW interface handle VPP has asigned to the interface
   */
  HW::item<handle_t> m_hdl;

  /**
   * Return the matching 'singular' of the interface
   */
  virtual std::shared_ptr<interface> singular_i() const;

  /**
   * release/remove an interface form the singular store
   */
  void release();

  /**
   * Virtual functions to construct an interface create commands.
   * Overridden in derived classes like the sub_interface
   */
  virtual std::queue<cmd*>& mk_create_cmd(std::queue<cmd*>& cmds);

  /**
   * Virtual functions to construct an interface delete commands.
   * Overridden in derived classes like the sub_interface
   */
  virtual std::queue<cmd*>& mk_delete_cmd(std::queue<cmd*>& cmds);

  /**
   * Sweep/reap the object if still stale
   */
  virtual void sweep(void);

  /**
   * A map of all interfaces key against the interface's name
   */
  static singular_db<const std::string, interface> m_db;

  /**
   * Add an interface to the DB keyed on handle
   */
  static void add(const std::string& name, const HW::item<handle_t>& item);

  /**
   * remove an interface from the DB keyed on handle
   */
  static void remove(const HW::item<handle_t>& item);

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
   * Commit the acculmulated changes into VPP. i.e. to a 'HW" write.
   */
  void update(const interface& obj);

  /*
   * It's the OM class that calls singular()
   */
  friend class OM;

  /**
   * It's the singular_db class that calls replay()
   */
  friend class singular_db<const std::string, interface>;

  /**
   * The interfaces name
   */
  const std::string m_name;

  /**
   * The interface type. clearly this cannot be changed
   * once the interface has been created.
   */
  const type_t m_type;

  /**
   * shared pointer to the routeDoamin the interface is in.
   * NULL is not mapped  - i.e. in eht default table
   */
  const std::shared_ptr<route_domain> m_rd;

  /**
   * The state of the interface
   */
  HW::item<admin_state_t> m_state;

  /**
   * HW state of the VPP table mapping
   */
  HW::item<route::table_id_t> m_table_id;

  /**
   * HW state of the L2 address
   */
  HW::item<l2_address_t> m_l2_address;

  /**
   * Operational state of the interface
   */
  oper_state_t m_oper;

  /**
   * A map of all interfaces keyed against VPP's handle
   */
  static std::map<handle_t, std::weak_ptr<interface>> m_hdl_db;

  /**
   * replay the object to create it in hardware
   */
  virtual void replay(void);

  /**
   * Create commands are firends so they can add interfaces to the
   * handle store.
   */
  template <typename MSG>
  friend class create_cmd;

  /**
   * Create commands are firends so they can remove interfaces from the
   * handle store.
   */
  template <typename MSG>
  friend class delete_cmd;
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
