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

#ifndef __VOM_LLDP_GLOBAL_H__
#define __VOM_LLDP_GLOBAL_H__

#include "vom/hw.hpp"
#include "vom/inspect.hpp"
#include "vom/interface.hpp"
#include "vom/object_base.hpp"
#include "vom/om.hpp"
#include "vom/singular_db.hpp"
#include "vom/sub_interface.hpp"

#include <vapi/lldp.api.vapi.hpp>

namespace VOM {
/**
 * A representation of LLDP global configuration
 */
class lldp_global : public object_base
{
public:
  /**
   * Construct a new object matching the desried state
   */
  lldp_global(const std::string& system_name,
              uint32_t tx_hold,
              uint32_t tx_interval);

  /**
   * Copy Constructor
   */
  lldp_global(const lldp_global& o);

  /**
   * Destructor
   */
  ~lldp_global();

  /**
   * Return the 'singular' of the LLDP global that matches this object
   */
  std::shared_ptr<lldp_global> singular() const;

  /**
   * convert to string format for debug purposes
   */
  std::string to_string() const;

  /**
   * Dump all LLDP globals into the stream provided
   */
  static void dump(std::ostream& os);

  /**
   * A command class that binds the LLDP global to the interface
   */
  class config_cmd : public rpc_cmd<HW::item<bool>, rc_t, vapi::Lldp_config>
  {
  public:
    /**
     * Constructor
     */
    config_cmd(HW::item<bool>& item,
               const std::string& system_name,
               uint32_t tx_hold,
               uint32_t tx_interval);

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
    bool operator==(const config_cmd& i) const;

  private:
    /**
     * The system name
     */
    const std::string m_system_name;

    /**
     * TX timer configs
     */
    uint32_t m_tx_hold;
    uint32_t m_tx_interval;
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
  void update(const lldp_global& obj);

  /**
   * Find or add LLDP global to the OM
   */
  static std::shared_ptr<lldp_global> find_or_add(const lldp_global& temp);

  /*
   * It's the OM class that calls singular()
   */
  friend class OM;

  /**
   * It's the singular_db class that calls replay()
   */
  friend class singular_db<interface::key_type, lldp_global>;

  /**
   * Sweep/reap the object if still stale
   */
  void sweep(void);

  /**
   * replay the object to create it in hardware
   */
  void replay(void);

  /**
   * The system name
   */
  const std::string m_system_name;

  /**
   * TX timer configs
   */
  uint32_t m_tx_hold;
  uint32_t m_tx_interval;

  /**
   * HW globaluration for the binding. The bool representing the
   * do/don't bind.
   */
  HW::item<bool> m_binding;

  /**
   * A map of all Lldp globals keyed against the system name.
   *  there needs to be some sort of key, that will do.
   */
  static singular_db<std::string, lldp_global> m_db;
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
