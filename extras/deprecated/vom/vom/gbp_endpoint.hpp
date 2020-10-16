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

#ifndef __VOM_GBP_ENDPOINT_H__
#define __VOM_GBP_ENDPOINT_H__

#include <ostream>
#include <vector>

#include "vom/gbp_endpoint_group.hpp"
#include "vom/interface.hpp"
#include "vom/singular_db.hpp"

namespace VOM {
/**
 * A GBP Enpoint (i.e. a VM)
 */
class gbp_endpoint : public object_base
{
public:
  /**
   * Endpoint flags
   */
  struct flags_t : enum_base<flags_t>
  {
    const static flags_t NONE;
    const static flags_t BOUNCE;
    const static flags_t REMOTE;
    const static flags_t LEARNT;
    const static flags_t EXTERNAL;

  private:
    /**
     * Private constructor taking the value and the string name
     */
    flags_t(int v, const std::string& s);
  };

  /**
   * The key for a GBP endpoint; interface and IP
   */
  typedef std::pair<interface::key_t, mac_address_t> key_t;

  /**
   * Construct a GBP endpoint
   */
  gbp_endpoint(const interface& itf,
               const std::vector<boost::asio::ip::address>& ip_addr,
               const mac_address_t& mac,
               const gbp_endpoint_group& epg,
               const flags_t& flags = flags_t::NONE);

  /**
   * Copy Construct
   */
  gbp_endpoint(const gbp_endpoint& r);

  /**
   * Destructor
   */
  ~gbp_endpoint();

  /**
   * Return the object's key
   */
  const key_t key() const;

  /**
   * comparison operator
   */
  bool operator==(const gbp_endpoint& bdae) const;

  /**
   * Return the matching 'singular instance'
   */
  std::shared_ptr<gbp_endpoint> singular() const;

  /**
   * Find the instnace of the bridge_domain domain in the OM
   */
  static std::shared_ptr<gbp_endpoint> find(const key_t& k);

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
  void update(const gbp_endpoint& obj);

  /**
   * Find or add the instnace of the bridge_domain domain in the OM
   */
  static std::shared_ptr<gbp_endpoint> find_or_add(const gbp_endpoint& temp);

  /*
   * It's the VPPHW class that updates the objects in HW
   */
  friend class OM;

  /**
   * It's the singular_db class that calls replay()
   */
  friend class singular_db<key_t, gbp_endpoint>;

  /**
   * Sweep/reap the object if still stale
   */
  void sweep(void);

  /**
   * HW configuration for the result of creating the endpoint
   */
  HW::item<handle_t> m_hdl;

  /**
   * The interface the endpoint is attached to.
   */
  std::shared_ptr<interface> m_itf;

  /**
   * The IP address of the endpoint
   */
  std::vector<boost::asio::ip::address> m_ips;

  /**
   * The MAC address of the endpoint
   */
  mac_address_t m_mac;

  /**
   * The EPG the endpoint is in
   */
  std::shared_ptr<gbp_endpoint_group> m_epg;

  /**
   * Endpoint flags
   */
  flags_t m_flags;

  /**
   * A map of all bridge_domains
   */
  static singular_db<key_t, gbp_endpoint> m_db;
};

std::ostream& operator<<(std::ostream& os, const gbp_endpoint::key_t& key);
}; // namespace

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */

#endif
