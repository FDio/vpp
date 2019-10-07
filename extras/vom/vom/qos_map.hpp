/*
 * Copyright (c) 2019 Cisco and/or its affiliates.
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

#ifndef __VOM_QOS_MAP_H__
#define __VOM_QOS_MAP_H__

#include <ostream>

#include "vom/interface.hpp"
#include "vom/qos_types.hpp"
#include "vom/singular_db.hpp"

namespace VOM {
/**
 * Types belonging to QoS
 */
namespace QoS {

/**
 * A QoS map determines how value from one source are translated to
 * values of another source
 */
class map : public object_base
{
public:
  typedef std::array<std::array<bits_t, 256>, 4> outputs_t;

  map(uint32_t id, const outputs_t& o);
  map(const map& r);

  ~map();

  typedef uint32_t key_t;

  /**
   * Return the object's key
   */
  const key_t key() const;

  /**
   * Return the object's ID
   */
  const key_t id() const;

  /**
   * comparison operator
   */
  bool operator==(const map& bdae) const;

  /**
   * Return the matching 'singular instance'
   */
  std::shared_ptr<map> singular() const;

  /**
   * Find the instnace of the bridge_domain domain in the OM
   */
  static std::shared_ptr<map> find(const key_t& k);

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
  void update(const map& obj);

  /**
   * Find or add the instnace of the bridge_domain domain in the OM
   */
  static std::shared_ptr<map> find_or_add(const map& temp);

  /*
   * It's the VPPHW class that updates the objects in HW
   */
  friend class VOM::OM;

  /**
   * It's the singular_db class that calls replay()
   */
  friend class singular_db<key_t, map>;

  /**
   * Sweep/reap the object if still stale
   */
  void sweep(void);

  /**
   * HW configuration for the config. The bool representing the
   * do/don't configured/unconfigured.
   */
  HW::item<bool> m_config;

  /**
   * unique ID of the MAP.
   */
  uint32_t m_id;

  /**
   * outputs from the translation
   */
  outputs_t m_outputs;

  /**
   * A map of all bridge_domains
   */
  static singular_db<key_t, map> m_db;
};

}; // namesapce QoS

}; // namespace VOM

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */

#endif
