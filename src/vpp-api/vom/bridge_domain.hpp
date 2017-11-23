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

#ifndef __VOM_BRIDGE_DOMAIN_H__
#define __VOM_BRIDGE_DOMAIN_H__

#include "vom/enum_base.hpp"
#include "vom/hw.hpp"
#include "vom/inspect.hpp"
#include "vom/object_base.hpp"
#include "vom/om.hpp"
#include "vom/singular_db.hpp"

namespace VOM {
/**
 * A base class for all object_base in the VPP object_base-Model.
 *  provides the abstract interface.
 */
class bridge_domain : public object_base
{
public:
  /**
   * Key Type for Bridge Domains in the sigular DB
   */
  typedef uint32_t key_t;

  /**
   * Bridge Domain Learning mode
   */
  struct learning_mode_t : enum_base<learning_mode_t>
  {
    const static learning_mode_t ON;
    const static learning_mode_t OFF;

  private:
    /**
     * Private constructor taking the value and the string name
     */
    learning_mode_t(int v, const std::string& s);
  };

  /**
   * The value of the defaultbridge domain
   */
  const static uint32_t DEFAULT_TABLE = 0;

  /**
   * Construct a new object matching the desried state
   */
  bridge_domain(uint32_t id,
                const learning_mode_t& lmode = learning_mode_t::ON);

  /**
   * Copy Constructor
   */
  bridge_domain(const bridge_domain& o);

  /**
   * Destructor
   */
  ~bridge_domain();

  /**
   * Comparison operator - for UT
   */
  bool operator==(const bridge_domain& b) const;

  /**
   * Return the bridge domain's VPP ID
   */
  uint32_t id() const;

  /**
   * Return the bridge domain's key
   */
  const key_t& key() const;

  /**
   * Return the matchin 'singular' instance of the bridge-domain
   */
  std::shared_ptr<bridge_domain> singular() const;

  /**
   * convert to string format for debug purposes
   */
  std::string to_string(void) const;

  /**
   * Static function to find the bridge_domain in the model
   */
  static std::shared_ptr<bridge_domain> find(const key_t& key);

  /**
   * Dump all bridge-doamin into the stream provided
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
   * Instance of the event handler to register with OM
   */
  static event_handler m_evh;

  /**
   * Commit the acculmulated changes into VPP. i.e. to a 'HW" write.
   */
  void update(const bridge_domain& obj);

  /**
   * Find or add an singular of a Bridge-Domain in the object_base Model
   */
  static std::shared_ptr<bridge_domain> find_or_add(const bridge_domain& temp);

  /*
   * It's the OM class that calls singular()
   */
  friend class OM;

  /**
   * It's the singular_db class that calls replay()
   */
  friend class singular_db<key_t, bridge_domain>;

  /**
   * Sweep/reap the object if still stale
   */
  void sweep(void);

  /**
   * replay the object to create it in hardware
   */
  void replay(void);

  /**
   * The ID we assign to this BD and the HW result in VPP
   */
  HW::item<uint32_t> m_id;

  /**
   * The leanring mode of the bridge
   */
  learning_mode_t m_learning_mode;

  /**
   * A map of all interfaces key against the interface's name
   */
  static singular_db<key_t, bridge_domain> m_db;
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
