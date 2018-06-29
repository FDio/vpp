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

#ifndef __VOM_L2_XCONNECT_H__
#define __VOM_L2_XCONNECT_H__

#include "vom/hw.hpp"
#include "vom/inspect.hpp"
#include "vom/interface.hpp"
#include "vom/object_base.hpp"
#include "vom/om.hpp"
#include "vom/singular_db.hpp"

namespace VOM {
/**
 * A Class representing the cross connnect of an L2 interface with another
 * l2 interface
 */
class l2_xconnect : public object_base
{
public:
  /**
   * Key type for an L2 xconnect in the singular DB
   */
  typedef std::pair<interface::key_t, interface::key_t> key_t;

  /**
   * Construct a new object matching the desried state
   */
  l2_xconnect(const interface& east_itf, const interface& west_itf);

  /**
   * Copy Constructor
   */
  l2_xconnect(const l2_xconnect& o);

  /**
   * Destructor
   */
  ~l2_xconnect();

  /**
   * Return the xconnect's key
   */
  const key_t key() const;

  /**
   * Comparison operator - for UT
   */
  bool operator==(const l2_xconnect& l) const;

  /**
   * Return the 'singular instance' of the L2 config that matches this
   * object
   */
  std::shared_ptr<l2_xconnect> singular() const;

  /**
   * convert to string format for debug purposes
   */
  std::string to_string() const;

  /**
   * Dump all l2_xconnects into the stream provided
   */
  static void dump(std::ostream& os);

  /**
   * Static function to find the bridge_domain in the model
   */
  static std::shared_ptr<l2_xconnect> find(const key_t& key);

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
   * Enque commands to the VPP command Q for the update
   */
  void update(const l2_xconnect& obj);

  /**
   * Find or Add the singular instance in the DB
   */
  static std::shared_ptr<l2_xconnect> find_or_add(const l2_xconnect& temp);

  /*
   * It's the OM class that calls singular()
   */
  friend class OM;

  /**
   * It's the singular_db class that calls replay()
   */
  friend class singular_db<key_t, l2_xconnect>;

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
  const std::shared_ptr<interface> m_east_itf;

  /**
   * A reference counting pointer the Bridge-Domain that this L2
   * interface is bound to. By holding the reference here, we can
   * guarantee that this object will outlive the BD.
   */
  const std::shared_ptr<interface> m_west_itf;

  /**
   * HW configuration for the xconnect. The bool representing the
   * do/don't bind.
   */
  HW::item<bool> m_xconnect_east;

  /**
   * HW configuration for the xconnect. The bool representing the
   * do/don't bind.
   */
  HW::item<bool> m_xconnect_west;

  /**
   * A map of all L2 interfaces key against the interface's handle_t
   */
  static singular_db<key_t, l2_xconnect> m_db;
};

std::ostream& operator<<(std::ostream& os, const l2_xconnect::key_t& key);
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */

#endif
