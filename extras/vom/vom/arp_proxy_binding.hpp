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

#ifndef __VOM_ARP_PROXY_BINDING_H__
#define __VOM_ARP_PROXY_BINDING_H__

#include "vom/arp_proxy_config.hpp"
#include "vom/hw.hpp"
#include "vom/inspect.hpp"
#include "vom/interface.hpp"
#include "vom/object_base.hpp"
#include "vom/om.hpp"
#include "vom/singular_db.hpp"

namespace VOM {
/**
 * A representation of LLDP client configuration on an interface
 */
class arp_proxy_binding : public object_base
{
public:
  /**
   * Construct a new object matching the desried state
   */
  arp_proxy_binding(const interface& itf, const arp_proxy_config& proxy_cfg);

  /**
   * Copy Constructor
   */
  arp_proxy_binding(const arp_proxy_binding& o);

  /**
   * Destructor
   */
  ~arp_proxy_binding();

  /**
   * Return the 'singular' of the LLDP binding that matches this object
   */
  std::shared_ptr<arp_proxy_binding> singular() const;

  /**
   * convert to string format for debug purposes
   */
  std::string to_string() const;

  /**
   * Dump all LLDP bindings into the stream provided
   */
  static void dump(std::ostream& os);

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
  void update(const arp_proxy_binding& obj);

  /**
   * Find or add LLDP binding to the OM
   */
  static std::shared_ptr<arp_proxy_binding> find_or_add(
    const arp_proxy_binding& temp);

  /*
   * It's the OM class that calls singular()
   */
  friend class OM;

  /**
   * It's the singular_db class that calls replay()
   */
  friend class singular_db<interface::key_t, arp_proxy_binding>;

  /**
   * Sweep/reap the object if still stale
   */
  void sweep(void);

  /**
   * replay the object to create it in hardware
   */
  void replay(void);

  /**
   * A reference counting pointer to the interface on which LLDP config
   * resides. By holding the reference here, we can guarantee that
   * this object will outlive the interface
   */
  const std::shared_ptr<interface> m_itf;

  /**
   * A reference counting pointer to the prxy config.
   */
  const std::shared_ptr<arp_proxy_config> m_arp_proxy_cfg;

  /**
   * HW configuration for the binding. The bool representing the
   * do/don't bind.
   */
  HW::item<bool> m_binding;

  /**
   * A map of all ArpProxy bindings keyed against the interface.
   */
  static singular_db<interface::key_t, arp_proxy_binding> m_db;
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
