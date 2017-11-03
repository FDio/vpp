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

#ifndef __VOM_NAT_BINDING_H__
#define __VOM_NAT_BINDING_H__

#include "vom/hw.hpp"
#include "vom/interface.hpp"
#include "vom/object_base.hpp"
#include "vom/om.hpp"
#include "vom/singular_db.hpp"

namespace VOM {
/**
 * A Class representing the binding of an L2 interface to a bridge-domain
 * and the properties of that binding.
 */
class nat_binding : public object_base
{
public:
  /**
   * NAT Zoness
   */
  struct zone_t : public enum_base<zone_t>
  {
    /**
     * Constructor
     */
    zone_t(int v, const std::string s);

    /**
     * Destructor
     */
    ~zone_t() = default;

    /**
     * Permit Zone
     */
    const static zone_t INSIDE;

    /**
     * Deny Zone
     */
    const static zone_t OUTSIDE;
  };

  /**
   * The key for a NAT Binding.
   *  The zoe is not included, since the same interface is never inside
   * and outside.
   */
  typedef std::tuple<interface::key_type, direction_t, l3_proto_t> key_t;

  /**
   * Construct a new object matching the desried state
   *  @param itf The interface onto which we bind/apply the feature
   *  @param dir The direction (input/output)
   *  @param proto The L3 proto used inside.
   *  @param zone The NAT zone for the link
   */
  nat_binding(const interface& itf,
              const direction_t& dir,
              const l3_proto_t& proto,
              const zone_t& zone);

  /**
   * Copy Constructor
   */
  nat_binding(const nat_binding& o);

  /**
   * Destructor
   */
  ~nat_binding();

  /**
   * Return the 'singular instance' of the L2 config that matches this
   * object
   */
  std::shared_ptr<nat_binding> singular() const;

  /**
   * convert to string format for debug purposes
   */
  std::string to_string() const;

  /**
   * Dump all nat_bindings into the stream provided
   */
  static void dump(std::ostream& os);

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
  void update(const nat_binding& obj);

  /**
   * Find or Add the singular instance in the DB
   */
  static std::shared_ptr<nat_binding> find_or_add(const nat_binding& temp);

  /*
   * It's the OM class that calls singular()
   */
  friend class OM;

  /**
   * It's the singular_db class that calls replay()
   */
  friend class singular_db<const key_t, nat_binding>;

  /**
   * Sweep/reap the object if still stale
   */
  void sweep(void);

  /**
   * replay the object to create it in hardware
   */
  void replay(void);

  /**
   * HW configuration for the binding. The bool representing the
   * do/don't bind.
   */
  HW::item<bool> m_binding;

  /**
   * A reference counting pointer the interface that this NAT binding
   * represents. By holding the reference here, we can guarantee that
   * this object will outlive the interface
   */
  const std::shared_ptr<interface> m_itf;

  /**
   * The direction in which the feature applies
   */
  direction_t m_dir;

  /**
   * The L3 protocol used on the inside
   */
  l3_proto_t m_proto;

  /**
   * The NAT zone the interface is in
   */
  zone_t m_zone;

  /**
   * A map of all L2 interfaces key against the interface's handle_t
   */
  static singular_db<const key_t, nat_binding> m_db;
};

std::ostream& operator<<(std::ostream& os, const nat_binding::key_t& key);
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */

#endif
