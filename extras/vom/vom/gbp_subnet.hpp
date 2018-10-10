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

#ifndef __VOM_GBP_SUBNET_H__
#define __VOM_GBP_SUBNET_H__

#include <ostream>

#include "vom/gbp_endpoint_group.hpp"
#include "vom/gbp_recirc.hpp"
#include "vom/gbp_route_domain.hpp"
#include "vom/singular_db.hpp"

namespace VOM {
/**
 * A GBP Enpoint (i.e. a VM)
 */
class gbp_subnet : public object_base
{
public:
  /**
   * The key for a GBP subnet; table and prefix
   */
  typedef std::pair<gbp_route_domain::key_t, route::prefix_t> key_t;

  struct type_t : public enum_base<type_t>
  {
    /**
     * Internal subnet is reachable through the source EPG's
     * uplink interface.
     */
    const static type_t STITCHED_INTERNAL;

    /**
     * External subnet requires NAT translation before egress.
     */
    const static type_t STITCHED_EXTERNAL;

    /**
     * A transport subnet, sent via the RD's UU-fwd interface
     */
    const static type_t TRANSPORT;

  private:
    type_t(int v, const std::string s);
  };

  /**
  * Construct an internal GBP subnet
  */
  gbp_subnet(const gbp_route_domain& rd,
             const route::prefix_t& prefix,
             const type_t& type);

  /**
   * Construct an external GBP subnet
   */
  gbp_subnet(const gbp_route_domain& rd,
             const route::prefix_t& prefix,
             const gbp_recirc& recirc,
             const gbp_endpoint_group& epg);

  /**
   * Copy Construct
   */
  gbp_subnet(const gbp_subnet& r);

  /**
   * Destructor
   */
  ~gbp_subnet();

  /**
   * Return the object's key
   */
  const key_t key() const;

  /**
   * comparison operator
   */
  bool operator==(const gbp_subnet& bdae) const;

  /**
   * Return the matching 'singular instance'
   */
  std::shared_ptr<gbp_subnet> singular() const;

  /**
   * Find the instnace of the bridge_domain domain in the OM
   */
  static std::shared_ptr<gbp_subnet> find(const key_t& k);

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
  void update(const gbp_subnet& obj);

  /**
   * Find or add the instnace of the bridge_domain domain in the OM
   */
  static std::shared_ptr<gbp_subnet> find_or_add(const gbp_subnet& temp);

  /*
   * It's the VPPHW class that updates the objects in HW
   */
  friend class OM;

  /**
   * It's the singular_db class that calls replay()
   */
  friend class singular_db<key_t, gbp_subnet>;

  /**
   * Sweep/reap the object if still stale
   */
  void sweep(void);

  /**
   * HW configuration for the result of creating the subnet
   */
  HW::item<bool> m_hw;

  /**
   * the route domain the prefix is in
   */
  const std::shared_ptr<gbp_route_domain> m_rd;

  /**
   * prefix to match
   */
  const route::prefix_t m_prefix;

  /*
   * Subnet type
   */
  type_t m_type;

  /**
   * The interface the prefix is reachable through
   */
  std::shared_ptr<gbp_recirc> m_recirc;

  /**
   * The EPG the subnet is in
   */
  std::shared_ptr<gbp_endpoint_group> m_epg;

  /**
   * A map of all bridge_domains
   */
  static singular_db<key_t, gbp_subnet> m_db;
};

std::ostream& operator<<(std::ostream& os, const gbp_subnet::key_t& key);

}; // namespace

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */

#endif
