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

#ifndef __VOM_L3_BINDING_H__
#define __VOM_L3_BINDING_H__

#include "vom/dump_cmd.hpp"
#include "vom/hw.hpp"
#include "vom/inspect.hpp"
#include "vom/interface.hpp"
#include "vom/object_base.hpp"
#include "vom/om.hpp"
#include "vom/rpc_cmd.hpp"
#include "vom/singular_db.hpp"

#include <vapi/ip.api.vapi.hpp>

namespace VOM {
/**
 * A representation of L3 configuration on an interface
 */
class l3_binding : public object_base
{
public:
  /**
   * Construct a new object matching the desried state
   */
  l3_binding(const interface& itf, const route::prefix_t& pfx);

  /**
   * Copy Constructor
   */
  l3_binding(const l3_binding& o);

  /**
   * Destructor
   */
  ~l3_binding();

  /**
   * Return the 'singular instance' of the L3-Config that matches this
   * object
   */
  std::shared_ptr<l3_binding> singular() const;

  /**
   * convert to string format for debug purposes
   */
  std::string to_string() const;

  /**
   * Return the prefix associated with this L3config
   */
  const route::prefix_t& prefix() const;

  /**
   * Dump all l3_bindings into the stream provided
   */
  static void dump(std::ostream& os);

  /**
   * The key type for l3_bindings
   */
  typedef std::pair<interface::key_type, route::prefix_t> key_type_t;

  /**
   * Find an singular instance in the DB for the interface passed
   */
  static std::deque<std::shared_ptr<l3_binding>> find(const interface& i);

  /**
   * A functor class that binds the L3 config to the interface
   */
  class bind_cmd
    : public rpc_cmd<HW::item<bool>, rc_t, vapi::Sw_interface_add_del_address>
  {
  public:
    /**
     * Constructor
     */
    bind_cmd(HW::item<bool>& item,
             const handle_t& itf,
             const route::prefix_t& pfx);

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
     * Reference to the interface to bind to
     */
    const handle_t& m_itf;

    /**
     * The prefix to bind
     */
    const route::prefix_t& m_pfx;
  };

  /**
   * A cmd class that Unbinds L3 Config from an interface
   */
  class unbind_cmd
    : public rpc_cmd<HW::item<bool>, rc_t, vapi::Sw_interface_add_del_address>
  {
  public:
    /**
     * Constructor
     */
    unbind_cmd(HW::item<bool>& item,
               const handle_t& itf,
               const route::prefix_t& pfx);

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
     * Reference to the interface to unbind fomr
     */
    const handle_t& m_itf;

    /**
     * The prefix to unbind
     */
    const route::prefix_t& m_pfx;
  };

  /**
   * A cmd class that Dumps all the IPv4 L3 configs
   */
  class dump_v4_cmd : public dump_cmd<vapi::Ip_address_dump>
  {
  public:
    /**
     * Constructor
     */
    dump_v4_cmd(const handle_t& itf);
    dump_v4_cmd(const dump_v4_cmd& d);

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
    bool operator==(const dump_v4_cmd& i) const;

  private:
    /**
     * HW reutrn code
     */
    HW::item<bool> item;

    /**
     * The interface to get the addresses for
     */
    const handle_t& m_itf;
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
  void update(const l3_binding& obj);

  /**
   * Find or add the singular instance in the DB
   */
  static std::shared_ptr<l3_binding> find_or_add(const l3_binding& temp);

  /*
   * It's the VPPHW class that updates the objects in HW
   */
  friend class OM;

  /**
     e* It's the singular_db class that calls replay()
  */
  friend class singular_db<key_type_t, l3_binding>;

  /**
   * Sweep/reap the object if still stale
   */
  void sweep(void);

  /**
   * replay the object to create it in hardware
   */
  void replay(void);

  /**
   * A reference counting pointer the interface that this L3 layer
   * represents. By holding the reference here, we can guarantee that
   * this object will outlive the interface
   */
  const std::shared_ptr<interface> m_itf;

  /**
   * The prefix for this L3 configuration
   */
  const route::prefix_t& m_pfx;

  /**
   * HW configuration for the binding. The bool representing the
   * do/don't bind.
   */
  HW::item<bool> m_binding;

  /**
   * A map of all L3 configs keyed against a combination of the interface
   * and subnet's keys.
   */
  static singular_db<key_type_t, l3_binding> m_db;
};

/**
 * Ostream output for the key
 */
std::ostream& operator<<(std::ostream& os, const l3_binding::key_type_t& key);
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */

#endif
