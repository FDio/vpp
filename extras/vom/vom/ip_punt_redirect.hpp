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

#ifndef __VOM_IP_PUNT_REDIRECT_H__
#define __VOM_IP_PUNT_REDIRECT_H__

#include "vom/hw.hpp"
#include "vom/inspect.hpp"
#include "vom/interface.hpp"
#include "vom/object_base.hpp"
#include "vom/om.hpp"
#include "vom/singular_db.hpp"

namespace VOM {
/**
 * A representation of IP punt_redirect configuration on an interface
 */
class ip_punt_redirect : public object_base
{
public:
  /**
   * Construct a new object matching the desried state
   *
   * @param rx_itf - The interface from where the punt traffic should come.
   * @param tx_itf - The interface to which traffic should be redirected.
   * @param addr - The next hop ip address to redirect the traffic.
   */
  ip_punt_redirect(const interface& rx_itf,
                   const interface& tx_itf,
                   const boost::asio::ip::address& addr);

  /**
   * Construct a new object matching the desried state
   *
   * @param tx_itf - The interface to which traffic should be redirected.
   * @param addr - The next hop ip address to redirect the traffic.
   */
  ip_punt_redirect(const interface& tx_itf,
                   const boost::asio::ip::address& addr);

  /**
   * Copy Constructor
   */
  ip_punt_redirect(const ip_punt_redirect& o);

  /**
   * Destructor
   */
  ~ip_punt_redirect();

  /**
   * Return the 'singular instance' of the ip_punt_redirect that matches this
   * object
   */
  std::shared_ptr<ip_punt_redirect> singular() const;

  /**
   * convert to string format for debug purposes
   */
  std::string to_string() const;

  /**
   * Dump all ip_punt_redirects into the stream provided
   */
  static void dump(std::ostream& os);

  /**
   * The key type for ip_punt_redirects
   */
  typedef interface::key_t key_t;

  /**
   * return the object's key
   */
  const key_t key() const;

  /**
 * Find an singular instance in the DB for the interface passed
 */
  static std::shared_ptr<ip_punt_redirect> find(const interface& i);

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
  void update(const ip_punt_redirect& obj);

  /**
   * Find or add the singular instance in the DB
   */
  static std::shared_ptr<ip_punt_redirect> find_or_add(
    const ip_punt_redirect& temp);

  /*
   * It's the VPPHW class that updates the objects in HW
   */
  friend class OM;

  /**
   * It's the singular_db class that calls replay
   */
  friend class singular_db<key_t, ip_punt_redirect>;

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
  const std::shared_ptr<interface> m_rx_itf;
  /**
   * A reference counting pointer the interface that has an address.
   */
  const std::shared_ptr<interface> m_tx_itf;

  /**
   * host Ip Prefix to redirect traffic to
   */
  const boost::asio::ip::address m_addr;

  /**
   * HW configuration for the binding. The bool representing the
   * do/don't bind.
   */
  HW::item<bool> m_config;

  /**
   * A map of all ip punt redirect keyed against a combination of the interface.
   */
  static singular_db<key_t, ip_punt_redirect> m_db;
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
