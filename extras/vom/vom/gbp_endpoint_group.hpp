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

#ifndef __VOM_GBP_ENDPOINT_GROUP_H__
#define __VOM_GBP_ENDPOINT_GROUP_H__

#include "vom/interface.hpp"
#include "vom/singular_db.hpp"
#include "vom/types.hpp"

#include "vom/gbp_bridge_domain.hpp"
#include "vom/gbp_route_domain.hpp"

namespace VOM {

/**
 * EPG IDs are 32 bit integers
 */
typedef uint32_t epg_id_t;

/**
 * A entry in the ARP termination table of a Bridge Domain
 */
class gbp_endpoint_group : public object_base
{
public:
  /**
   * The key for a GBP endpoint group is its ID
   */
  typedef epg_id_t key_t;

  /**
   * Construct a GBP endpoint_group
   */
  gbp_endpoint_group(epg_id_t epg_id,
                     const interface& itf,
                     const gbp_route_domain& rd,
                     const gbp_bridge_domain& bd);
  gbp_endpoint_group(epg_id_t epg_id,
                     const gbp_route_domain& rd,
                     const gbp_bridge_domain& bd);

  /**
   * Copy Construct
   */
  gbp_endpoint_group(const gbp_endpoint_group& r);

  /**
   * Destructor
   */
  ~gbp_endpoint_group();

  /**
   * Return the object's key
   */
  const key_t key() const;

  /**
   * comparison operator
   */
  bool operator==(const gbp_endpoint_group& bdae) const;

  /**
   * Return the matching 'singular instance'
   */
  std::shared_ptr<gbp_endpoint_group> singular() const;

  /**
   * Find the instnace of the bridge_domain domain in the OM
   */
  static std::shared_ptr<gbp_endpoint_group> find(const key_t& k);

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

  /**
   * Get the ID of the EPG
   */
  epg_id_t id() const;

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
  void update(const gbp_endpoint_group& obj);

  /**
   * Find or add the instnace of the bridge_domain domain in the OM
   */
  static std::shared_ptr<gbp_endpoint_group> find_or_add(
    const gbp_endpoint_group& temp);

  /*
   * It's the VPPHW class that updates the objects in HW
   */
  friend class OM;

  /**
   * It's the singular_db class that calls replay()
   */
  friend class singular_db<key_t, gbp_endpoint_group>;

  /**
   * Sweep/reap the object if still stale
   */
  void sweep(void);

  /**
   * HW configuration for the result of creating the endpoint_group
   */
  HW::item<bool> m_hw;

  /**
   * The EPG ID
   */
  epg_id_t m_epg_id;

  /**
   * The uplink interface for the endpoint group
   */
  std::shared_ptr<interface> m_itf;

  /**
   * The route-domain the EPG uses
   */
  std::shared_ptr<gbp_route_domain> m_rd;

  /**
   * The bridge-domain the EPG uses
   */
  std::shared_ptr<gbp_bridge_domain> m_bd;

  /**
   * A map of all bridge_domains
   */
  static singular_db<key_t, gbp_endpoint_group> m_db;
};

}; // namespace

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */

#endif
