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

#ifndef __VOM_IP_UNNUMBERED_H__
#define __VOM_IP_UNNUMBERED_H__

#include "vom/hw.hpp"
#include "vom/inspect.hpp"
#include "vom/interface.hpp"
#include "vom/object_base.hpp"
#include "vom/om.hpp"
#include "vom/singular_db.hpp"

namespace VOM {
/**
 * A representation of IP unnumbered configuration on an interface
 */
class ip_unnumbered : public object_base
{
public:
  /**
   * Construct a new object matching the desried state
   *
   * @param itf - The interface with no IP address
   * @param l3_itf - The interface that has the IP address we wish to
   * share.
   */
  ip_unnumbered(const interface& itf, const interface& l3_itf);

  /**
   * Copy Constructor
   */
  ip_unnumbered(const ip_unnumbered& o);

  /**
   * Destructor
   */
  ~ip_unnumbered();

  /**
   * Return the 'singular instance' of the L3-Config that matches this
   * object
   */
  std::shared_ptr<ip_unnumbered> singular() const;

  /**
   * convert to string format for debug purposes
   */
  std::string to_string() const;

  /**
   * Dump all ip_unnumbereds into the stream provided
   */
  static void dump(std::ostream& os);

  /**
   * The key type for ip_unnumbereds
   */
  typedef interface::key_t key_t;

  /**
   * Find an singular instance in the DB for the interface passed
   */
  static std::shared_ptr<ip_unnumbered> find(const interface& i);

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
  void update(const ip_unnumbered& obj);

  /**
   * Find or add the singular instance in the DB
   */
  static std::shared_ptr<ip_unnumbered> find_or_add(const ip_unnumbered& temp);

  /*
   * It's the VPPHW class that updates the objects in HW
   */
  friend class OM;

  /**
   * It's the singular_db class that calls replay
   */
  friend class singular_db<key_t, ip_unnumbered>;

  /**
   * Sweep/reap the object if still stale
   */
  void sweep(void);

  /**
   * replay the object to create it in hardware
   */
  void replay(void);

  /**
   * A reference counting pointer the interface that requires an address.
   */
  const std::shared_ptr<interface> m_itf;
  /**
   * A reference counting pointer the interface that has an address.
   */
  const std::shared_ptr<interface> m_l3_itf;

  /**
   * HW configuration for the binding. The bool representing the
   * do/don't bind.
   */
  HW::item<bool> m_config;

  /**
   * A map of all L3 configs keyed against a combination of the interface
   * and subnet's keys.
   */
  static singular_db<key_t, ip_unnumbered> m_db;
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
