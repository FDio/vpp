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

#ifndef __VOM_NAT_STATIC_H__
#define __VOM_NAT_STATIC_H__

#include "vom/route.hpp"
#include "vom/singular_db.hpp"
#include "vom/types.hpp"

namespace VOM {
/**
 * A entry in the ARP termination table of a Bridge Domain
 */
class nat_static : public object_base
{
public:
  /**
   * The key for a NAT static mapping.
   *  So far only model the address only case. The address
   * is the outside.
   */
  typedef std::pair<route::table_id_t, boost::asio::ip::address> key_t;

  /**
   * Construct an NAT Static binding with the outside address in default
   * table
   */
  nat_static(const boost::asio::ip::address& inside,
             const boost::asio::ip::address_v4& outside);

  /**
   * Construct an NAT Static binding with the outside address in
   * route-domain specified
   */
  nat_static(const route_domain& rd,
             const boost::asio::ip::address& inside,
             const boost::asio::ip::address_v4& outside);

  /**
   * Copy Construct
   */
  nat_static(const nat_static& r);

  /**
   * Destructor
   */
  ~nat_static();

  /**
   * Return the matching 'singular instance'
   */
  std::shared_ptr<nat_static> singular() const;

  /**
   * Find the instnace of the bridge_domain domain in the OM
   */
  static std::shared_ptr<nat_static> find(const nat_static& temp);

  /**
   * Dump all bridge_domain-doamin into the stream provided
   */
  static void dump(std::ostream& os);

  /**
   * replay the object to create it in hardware
   */
  void replay(void);

  /**
   * Convert to string for debugging
   */
  std::string to_string() const;

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
   * Commit the acculmulated changes into VPP. i.e. to a 'HW" write.
   */
  void update(const nat_static& obj);

  /**
   * Find or add the instnace of the bridge_domain domain in the OM
   */
  static std::shared_ptr<nat_static> find_or_add(const nat_static& temp);

  /*
   * It's the VPPHW class that updates the objects in HW
   */
  friend class OM;

  /**
   * It's the singular_db class that calls replay()
   */
  friend class singular_db<key_t, nat_static>;

  /**
   * Sweep/reap the object if still stale
   */
  void sweep(void);

  /**
   * HW configuration for the result of creating the bridge_domain
   */
  HW::item<bool> m_hw;

  /**
   * The table-ID the outside address resides in
   */
  std::shared_ptr<route_domain> m_rd;

  /**
   * The 'inside' IP address, could be v4 or v6
   */
  const boost::asio::ip::address& m_inside;

  /**
   * The 'outside' IP address - always v4
   */
  const boost::asio::ip::address_v4& m_outside;

  /**
   * A map of all NAT statics
   */
  static singular_db<key_t, nat_static> m_db;
};

std::ostream& operator<<(std::ostream& os, const nat_static::key_t& key);
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */

#endif
