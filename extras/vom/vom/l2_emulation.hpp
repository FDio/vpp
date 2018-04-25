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

#ifndef __VOM_L2_EMULATION_H__
#define __VOM_L2_EMULATION_H__

#include "vom/bridge_domain.hpp"
#include "vom/hw.hpp"
#include "vom/inspect.hpp"
#include "vom/interface.hpp"
#include "vom/object_base.hpp"
#include "vom/om.hpp"
#include "vom/singular_db.hpp"

namespace VOM {
/**
 * A Clas representing the binding of an L2 interface to a bridge-domain
 * and the properties of that binding.
 */
class l2_emulation : public object_base
{
public:
  /**
   * Key type for an L2 emulation in the singular DB
   */
  typedef interface::key_t key_t;

  /**
   * Construct a new object matching the desried state
   */
  l2_emulation(const interface& itf);

  /**
   * Copy Constructor
   */
  l2_emulation(const l2_emulation& o);

  /**
   * Destructor
   */
  ~l2_emulation();

  /**
   * Return the binding's key
   */
  const key_t& key() const;

  /**
   * Comparison operator - for UT
   */
  bool operator==(const l2_emulation& l) const;

  /**
   * Return the 'singular instance' of the L2 config that matches this
   * object
   */
  std::shared_ptr<l2_emulation> singular() const;

  /**
   * convert to string format for debug purposes
   */
  std::string to_string() const;

  /**
   * Dump all l2_emulations into the stream provided
   */
  static void dump(std::ostream& os);

  /**
   * Static function to find the bridge_domain in the model
   */
  static std::shared_ptr<l2_emulation> find(const key_t& key);

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
  void update(const l2_emulation& obj);

  /**
   * Find or Add the singular instance in the DB
   */
  static std::shared_ptr<l2_emulation> find_or_add(const l2_emulation& temp);

  /*
   * It's the OM class that calls singular()
   */
  friend class OM;

  /**
   * It's the singular_db class that calls replay()
   */
  friend class singular_db<key_t, l2_emulation>;

  /**
   * Sweep/reap the object if still stale
   */
  void sweep(void);

  /**
   * replay the object to create it in hardware
   */
  void replay(void);

  /**
   * A reference counting pointer the interface that this L2 layer
   * represents. By holding the reference here, we can guarantee that
   * this object will outlive the interface
   */
  const std::shared_ptr<interface> m_itf;

  /**
   * HW configuration for the emulation. The bool representing the
   * enable/disable.
   */
  HW::item<bool> m_emulation;

  /**
   * A map of all L2 emulation configurations
   */
  static singular_db<key_t, l2_emulation> m_db;
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
