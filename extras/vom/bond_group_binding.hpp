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

#ifndef __VOM_BOND_GROUP_BINDING_H__
#define __VOM_BOND_GROUP_BINDING_H__

#include <set>

#include "vom/bond_interface.hpp"
#include "vom/bond_member.hpp"
#include "vom/hw.hpp"
#include "vom/inspect.hpp"
#include "vom/interface.hpp"
#include "vom/object_base.hpp"
#include "vom/om.hpp"
#include "vom/singular_db.hpp"

namespace VOM {
/**
 * A representation of bond interface binding
 */
class bond_group_binding : public object_base
{
public:
  /**
   * The KEY can be used to uniquely identify the Bond Binding.
   * (other choices for keys, like the summation of the properties
   * of the rules, are rather too cumbersome to use
   */
  typedef std::string key_t;

  /**
   * The container type for enslaved itfs
   */
  typedef std::set<bond_member> enslaved_itf_t;

  /**
   * Construct a new object matching the desried state
   */
  bond_group_binding(const bond_interface& itf, const enslaved_itf_t& mem);

  /**
   * Copy Constructor
   */
  bond_group_binding(const bond_group_binding& o);

  /**
   * Destructor
   */
  ~bond_group_binding();

  /**
   * Return the 'singular' of the bond interface binding that matches this
   * object
   */
  std::shared_ptr<bond_group_binding> singular() const;

  /**
   * convert to string format for debug purposes
   */
  std::string to_string() const;

  /**
   * get the key to this object
   */
  const key_t key() const;

  /**
   * Dump all bond interface bindings into the stream provided
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
   * Enqueue command to the VPP command Q for the update
   */
  void update(const bond_group_binding& obj);

  /**
   * Find or add bond interface binding to the OM
   */
  static std::shared_ptr<bond_group_binding> find_or_add(
    const bond_group_binding& temp);

  /*
   * It's the OM class that calls singular()
   */
  friend class OM;

  /**
   * It's the singular_db class that calls replay()
   */
  friend class singular_db<key_t, bond_group_binding>;

  /**
   * Sweep/reap the object if still stale
   */
  void sweep(void);

  /**
   * replay the object to create it in hardware
   */
  void replay(void);

  /**
   * A reference counting pointer to the bond interface.
   * By holding the reference here, we can guarantee that
   * this object will outlive the interface
   */
  std::shared_ptr<bond_interface> m_itf;

  /**
   * A list of member interfaces.
   */
  const enslaved_itf_t m_mem_itfs;

  /**
   * HW configuration for the binding. The bool representing the
   * do/don't bind.
   */
  HW::item<bool> m_binding;

  /**
   * A map of all bond interface bindings keyed against the interface +
   * "binding".
   */
  static singular_db<key_t, bond_group_binding> m_db;
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
