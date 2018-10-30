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

#ifndef __VOM_IGMP_LISTEN_H__
#define __VOM_IGMP_LISTEN_H__

#include "vom/hw.hpp"
#include "vom/igmp_binding.hpp"
#include "vom/inspect.hpp"
#include "vom/interface.hpp"
#include "vom/object_base.hpp"
#include "vom/om.hpp"
#include "vom/singular_db.hpp"

namespace VOM {
/**
 * A representation of igmp configuration on an interface
 */
class igmp_listen : public object_base
{
public:
  typedef std::set<boost::asio::ip::address> src_addrs_t;

  /**
   * The key type for igmp_listens
   */
  typedef std::pair<interface::key_t, boost::asio::ip::address> key_t;

  /**
   * Construct a new object matching the desried state
   */
  igmp_listen(const igmp_binding& igmp_bind,
              const boost::asio::ip::address& gaddr,
              const src_addrs_t& saddrs);

  /**
   * Copy Constructor
   */
  igmp_listen(const igmp_listen& o);

  /**
   * Destructor
   */
  ~igmp_listen();

  /**
   * Comparison operator
   */
  bool operator==(const igmp_listen& l) const;

  /**
   * Get the object's key
   */
  const key_t key() const;

  /**
   * Return the 'singular instance' of the IGMP that matches this
   * object
   */
  std::shared_ptr<igmp_listen> singular() const;

  /**
   * convert to string format for debug purposes
   */
  std::string to_string() const;

  /**
   * Dump all igmp_listens into the stream provided
   */
  static void dump(std::ostream& os);

  /**
   * Find a listen from its key
   */
  static std::shared_ptr<igmp_listen> find(const key_t& k);

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
  void update(const igmp_listen& obj);

  /**
   * Find or add the singular instance in the DB
   */
  static std::shared_ptr<igmp_listen> find_or_add(const igmp_listen& temp);

  /*
   * It's the VPPHW class that updates the objects in HW
   */
  friend class OM;

  /**
   * It's the singular_db class that calls replay()
   */
  friend class singular_db<key_t, igmp_listen>;

  /**
   * Sweep/reap the object if still stale
   */
  void sweep(void);

  /**
   * replay the object to create it in hardware
   */
  void replay(void);

  /**
   * A reference counting pointer the igmp_binding that this 'igmp listen'
   * represents. By holding the reference here, we can guarantee that
   * this object will outlive the igmp_binding
   */
  const std::shared_ptr<igmp_binding> m_igmp_bind;

  /**
   * The group address for igmp configuration
   */
  const boost::asio::ip::address m_gaddr;

  /**
   * The set of src addresses to listen for
   */
  const src_addrs_t m_saddrs;

  /**
   * HW configuration for the listen. The bool representing the
   * do/don't bind.
   */
  HW::item<bool> m_listen;

  /**
   * A map of all igmp listen keyed against a combination of the interface
   * and group addr keys.
   */
  static singular_db<key_t, igmp_listen> m_db;
};

/**
 * Ostream output for the key
 */
std::ostream& operator<<(std::ostream& os, const igmp_listen::key_t& key);
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */

#endif
