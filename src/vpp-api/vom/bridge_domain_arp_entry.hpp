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

#ifndef __VOM_BRIDGE_DOMAIN_ARP_ENTRY_H__
#define __VOM_BRIDGE_DOMAIN_ARP_ENTRY_H__

#include "vom/bridge_domain.hpp"
#include "vom/interface.hpp"
#include "vom/singular_db.hpp"
#include "vom/types.hpp"

namespace VOM {
/**
 * A entry in the ARP termination table of a Bridge Domain
 */
class bridge_domain_arp_entry : public object_base
{
public:
  /**
   * The key for a bridge_domain ARP entry;
   *  the BD, IP address and MAC address
   */
  typedef std::tuple<uint32_t, mac_address_t, boost::asio::ip::address> key_t;

  /**
   * Construct a bridge_domain in the given bridge domain
   */
  bridge_domain_arp_entry(const bridge_domain& bd,
                          const mac_address_t& mac,
                          const boost::asio::ip::address& ip_addr);

  /**
   * Construct a bridge_domain in the default table
   */
  bridge_domain_arp_entry(const mac_address_t& mac,
                          const boost::asio::ip::address& ip_addr);

  /**
   * Copy Construct
   */
  bridge_domain_arp_entry(const bridge_domain_arp_entry& r);

  /**
   * Destructor
   */
  ~bridge_domain_arp_entry();

  /**
   * Return the matching 'singular instance'
   */
  std::shared_ptr<bridge_domain_arp_entry> singular() const;

  /**
   * Find the instnace of the bridge_domain domain in the OM
   */
  static std::shared_ptr<bridge_domain_arp_entry> find(
    const bridge_domain_arp_entry& temp);

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
  void update(const bridge_domain_arp_entry& obj);

  /**
   * Find or add the instnace of the bridge_domain domain in the OM
   */
  static std::shared_ptr<bridge_domain_arp_entry> find_or_add(
    const bridge_domain_arp_entry& temp);

  /*
   * It's the VPPHW class that updates the objects in HW
   */
  friend class OM;

  /**
   * It's the singular_db class that calls replay()
   */
  friend class singular_db<key_t, bridge_domain_arp_entry>;

  /**
   * Sweep/reap the object if still stale
   */
  void sweep(void);

  /**
   * HW configuration for the result of creating the bridge_domain
   */
  HW::item<bool> m_hw;

  /**
   * The bridge_domain domain the bridge_domain is in.
   */
  std::shared_ptr<bridge_domain> m_bd;

  /**
   * The mac to match
   */
  mac_address_t m_mac;

  /**
   * The IP address
   */
  boost::asio::ip::address m_ip_addr;

  /**
   * A map of all bridge_domains
   */
  static singular_db<key_t, bridge_domain_arp_entry> m_db;
};

std::ostream& operator<<(std::ostream& os,
                         const bridge_domain_arp_entry::key_t& key);
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */

#endif
