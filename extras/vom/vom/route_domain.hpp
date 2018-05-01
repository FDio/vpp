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

#ifndef __VOM_ROUTE_DOMAIN_H__
#define __VOM_ROUTE_DOMAIN_H__

#include "vom/inspect.hpp"
#include "vom/object_base.hpp"
#include "vom/om.hpp"
#include "vom/prefix.hpp"
#include "vom/singular_db.hpp"

#include <vapi/ip.api.vapi.hpp>

namespace VOM {
/**
 * A route-domain is a VRF.
 *  creating a route-domain object will construct both an IPv4
 *  and IPv6 table.
 */
class route_domain : public object_base
{
public:
  /**
   * The Key for a route-domain
   */
  typedef route::table_id_t key_t;

  /**
   * The iterator type
   */
  typedef singular_db<const key_t, route_domain>::const_iterator
    const_iterator_t;

  static const_iterator_t cbegin();
  static const_iterator_t cend();

  /**
   * Construct a new object matching the desried state
   */
  route_domain(route::table_id_t id);

  /**
   * Copy Constructor
   */
  route_domain(const route_domain& o);

  /**
   * Destructor
   */
  ~route_domain();

  /**
   * comparison operator - for UT
   */
  bool operator==(const route_domain& r) const;

  /**
   * Return the matching 'singular instance'
   */
  std::shared_ptr<route_domain> singular() const;

  /**
   * Debug print function
   */
  std::string to_string() const;

  /**
   * Get the table ID
   */
  route::table_id_t table_id() const;

  /**
   * Get the route-domain's key
   */
  key_t key() const;

  /**
   * Find the instnace of the route domain in the OM
   */
  static std::shared_ptr<route_domain> find(const key_t& temp);

  /**
   * Dump all route-doamin into the stream provided
   */
  static void dump(std::ostream& os);

  /**
   * Return the sigular instance for the default table
   */
  static std::shared_ptr<route_domain> get_default();

  /**
   * replay the object to create it in hardware
   */
  void replay(void);

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
  void update(const route_domain& obj);

  /**
   * Find or add the instnace of the route domain in the OM
   */
  static std::shared_ptr<route_domain> find_or_add(const route_domain& temp);

  /*
   * It's the OM class that updates the objects in HW
   */
  friend class OM;

  /**
   * It's the singular_db class that calls replay()
   */
  friend class singular_db<route::table_id_t, route_domain>;

  /**
   * Sweep/reap the object if still stale
   */
  void sweep(void);

  /**
   * HW configuration for the result of creating the v4 table
   */
  HW::item<bool> m_hw_v4;

  /**
   * HW configuration for the result of creating the v6 table
   */
  HW::item<bool> m_hw_v6;

  /**
   * VPP understands Table-IDs not table names.
   *  The table IDs for V4 and V6 are the same.
   */
  route::table_id_t m_table_id;

  /**
   * A map of all interfaces key against the interface's name
   */
  static singular_db<route::table_id_t, route_domain> m_db;
};
}; // namespace VOM

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */

#endif
