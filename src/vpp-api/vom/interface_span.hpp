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

#ifndef __VOM_INTERFACE_SPAN_H__
#define __VOM_INTERFACE_SPAN_H__

#include "vom/hw.hpp"
#include "vom/inspect.hpp"
#include "vom/interface.hpp"
#include "vom/object_base.hpp"
#include "vom/om.hpp"
#include "vom/singular_db.hpp"

namespace VOM {
/**
 * A representation of interface span configuration
 */
class interface_span : public object_base
{
public:
  /**
   * The state of the interface - rx/tx or both to be mirrored
   */
  struct state_t : enum_base<state_t>
  {
    /**
     * DISABLED state
     */
    const static state_t DISABLED;
    /**
     * RX enable state
     */
    const static state_t RX_ENABLED;
    /**
     * TX enable state
     */
    const static state_t TX_ENABLED;
    /**
     * TX and RX enable state
     */
    const static state_t TX_RX_ENABLED;

    /**
     * Convert VPP's numerical value to enum type
     */
    static state_t from_int(uint8_t val);

  private:
    /**
     * Private constructor taking the value and the string name
     */
    state_t(int v, const std::string& s);
  };

  /**
   * Construct a new object matching the desried state
   *
   * @param itf_from - The interface to be mirrored
   * @param itf_to - The interface where the traffic is mirrored
   */
  interface_span(const interface& itf_from,
                 const interface& itf_to,
                 state_t state);

  /**
   * Copy Constructor
   */
  interface_span(const interface_span& o);

  /**
   * Destructor
   */
  ~interface_span();

  /**
   * Return the 'singular instance' of the interface_span that matches
   * this object
   */
  std::shared_ptr<interface_span> singular() const;

  /**
   * convert to string format for debug purposes
   */
  std::string to_string() const;

  /**
   * Dump all interface_spans into the stream provided
   */
  static void dump(std::ostream& os);

  /**
   * The key type for interface_spans
   */
  typedef std::pair<interface::key_type, interface::key_type> key_type_t;

  /**
   * Find a singular instance in the DB for the interface passed
   */
  static std::shared_ptr<interface_span> find(const interface& i);

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
  void update(const interface_span& obj);

  /**
   * Find or add the singular instance in the DB
   */
  static std::shared_ptr<interface_span> find_or_add(
    const interface_span& temp);

  /*
   * It's the VPPHW class that updates the objects in HW
   */
  friend class OM;

  /**
     e* It's the singular_db class that calls replay()
  */
  friend class singular_db<key_type_t, interface_span>;

  /**
   * Sweep/reap the object if still stale
   */
  void sweep(void);

  /**
   * replay the object to create it in hardware
   */
  void replay(void);

  /**
   * A reference counting pointer the interface to be mirrored
   */
  const std::shared_ptr<interface> m_itf_from;
  /**
   * A reference counting pointer the interface where the traffic is
   * mirrored
 */
  const std::shared_ptr<interface> m_itf_to;

  /**
   * the state (rx, tx or both) of the interface to be mirrored
   */
  const state_t m_state;

  /**
   * HW configuration for the binding. The bool representing the
   * do/don't bind.
 */
  HW::item<bool> m_config;

  /**
   * A map of all interface span keyed against the interface to be
   * mirrored.
 */
  static singular_db<key_type_t, interface_span> m_db;
};

/**
 * Ostream output for the key
 */
std::ostream& operator<<(std::ostream& os,
                         const interface_span::key_type_t& key);
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */

#endif
