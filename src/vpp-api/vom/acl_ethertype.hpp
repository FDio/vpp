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

#ifndef __VOM_ACL_ETHERTYPE_H__
#define __VOM_ACL_ETHERTYPE_H__

#include <set>

#include "vom/hw.hpp"
#include "vom/inspect.hpp"
#include "vom/interface.hpp"
#include "vom/object_base.hpp"
#include "vom/om.hpp"
#include "vom/singular_db.hpp"

namespace VOM {
namespace ACL {
/**
 * An ACL ethertype list comprises a set of inbound ether types and out bound
 * ether types
 * to be applied to packets.
 * A list is bound to a given interface.
 */

struct ethertype_t
{
public:
  /**
   * Constructor
   */
  ethertype_t(uint16_t e, const direction_t& dir);

  /**
   * Destructor
   */
  ~ethertype_t() = default;

  std::string to_string() const;

  bool operator<(const ethertype_t& other) const;

  uint16_t getEthertype(void) const;

private:
  uint16_t m_e;
  const direction_t& m_dir;
};

class acl_ethertype : public object_base
{
public:
  /**
   * The KEY can be used to uniquely identify the ACL ethertype.
   * (other choices for keys, like the summation of the properties
   * of the rules, are rather too cumbersome to use
   */
  typedef std::string key_t;

  /**
   * The ethertype container
   */
  typedef std::multiset<ethertype_t> list_ethertype_t;

  /**
   * Construct a new object matching the desried state
   */
  acl_ethertype(const interface& itf, list_ethertype_t le, uint8_t n_input);

  /**
   * Copy Constructor
   */
  acl_ethertype(const acl_ethertype& o);

  /**
   * Destructor
   */
  ~acl_ethertype();

  /**
   * Return the 'singular' of the acl ethertype that matches this object
   */
  std::shared_ptr<acl_ethertype> singular() const;

  /**
   * convert to string format for debug purposes
   */
  std::string to_string() const;

  /**
   * Dump all acl ethertype into the stream provided
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
   * Enque commands to the VPP command Q for the update
   */
  void update(const acl_ethertype& obj);

  /**
   * Find or add acl ethertype to the OM
   */
  static std::shared_ptr<acl_ethertype> find_or_add(const acl_ethertype& temp);

  /*
   * It's the OM class that calls singular()
   */
  friend class VOM::OM;

  /**
   * It's the singular_db class that calls replay()
   */
  friend class singular_db<interface::key_t, acl_ethertype>;

  /**
   * Sweep/reap the object if still stale
   */
  void sweep(void);

  /**
   * replay the object to create it in hardware
   */
  void replay(void);

  /**
   * A reference counting pointer to the interface on which acl ethertype
   * resides. By holding the reference here, we can guarantee that
   * this object will outlive the interface
   */
  const std::shared_ptr<interface> m_itf;

  /**
   * Inbound and outbound ethers list applied on given interface
   */
  list_ethertype_t m_le;

  /**
   * Number of inbound ethers in list of all
   */
  uint8_t m_n_input;

  /**
   * HW configuration for the binding. The bool representing the
   * do/don't bind.
   */
  HW::item<bool> m_binding;

  /**
   * A map of all acl ethertype keyed against the interface.
   */
  static singular_db<interface::key_t, acl_ethertype> m_db;
};
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
