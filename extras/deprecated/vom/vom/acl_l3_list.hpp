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

#ifndef __VOM_ACL_L3_LIST_H__
#define __VOM_ACL_L3_LIST_H__

#include <set>

#include "vom/acl_l3_rule.hpp"
#include "vom/acl_types.hpp"
#include "vom/hw.hpp"
#include "vom/inspect.hpp"
#include "vom/om.hpp"
#include "vom/singular_db.hpp"

namespace VOM {
namespace ACL {
/**
 * An L3 ACL list comprises a set of match actions rules to be applied to
 * packets.
 * A list is bound to a given interface.
 */
class l3_list : public object_base
{
public:
  /**
   * The KEY can be used to uniquely identify the ACL.
   * (other choices for keys, like the summation of the properties
   * of the rules, are rather too cumbersome to use
   */
  typedef std::string key_t;

  /**
   * The rule container type
   */
  typedef std::multiset<l3_rule> rules_t;

  /**
   * Construct a new object matching the desried state
   */
  l3_list(const key_t& key);

  l3_list(const handle_t& hdl, const key_t& key);

  l3_list(const key_t& key, const rules_t& rules);

  /**
   * Copy Constructor
   */
  l3_list(const l3_list& o);

  /**
   * Destructor
   */
  ~l3_list();

  /**
   * Return the 'sigular instance' of the ACL that matches this object
   */
  std::shared_ptr<l3_list> singular() const;

  /**
   * Dump all ACLs into the stream provided
   */
  static void dump(std::ostream& os);

  /**
   * convert to string format for debug purposes
   */
  std::string to_string() const;

  /**
   * Insert priority sorted a rule into the list
   */
  void insert(const l3_rule& rule);

  /**
   * Remove a rule from the list
   */
  void remove(const l3_rule& rule);

  /**
   * Return the VPP assign handle
   */
  const handle_t& handle() const;

  static std::shared_ptr<l3_list> find(const handle_t& handle);

  static std::shared_ptr<l3_list> find(const key_t& key);
  static void add(const key_t& key, const HW::item<handle_t>& item);

  static void remove(const HW::item<handle_t>& item);

  const key_t& key() const;

  const rules_t& rules() const;

  /**
   * Comparison operator - for UT
   */
  bool operator==(const l3_list& l) const;

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
   * Enqueue commands to the VPP command Q for the update
   */
  void update(const l3_list& obj);

  /**
   * HW assigned handle
   */
  HW::item<handle_t> m_hdl;

  /**
   * Find or add the sigular instance in the DB
   */
  static std::shared_ptr<l3_list> find_or_add(const l3_list& temp);

  /**
   * return the acl-list's handle in the singular instance
   */
  const handle_t& handle_i() const;

  /*
   * It's the VOM::OM class that updates call update
   */
  friend class VOM::OM;

  /**
   * It's the VOM::singular_db class that calls replay()
   */
  friend class singular_db<key_t, l3_list>;

  /**
   * Sweep/reap the object if still stale
   */
  void sweep(void);

  /**
   * Replay the objects state to HW
   */
  void replay(void);

  /**
   * A map of all ACL's against the client's key
   */
  static singular_db<key_t, l3_list> m_db;

  /**
   * A map of all ACLs keyed against VPP's handle
   */
  static std::map<handle_t, std::weak_ptr<l3_list>> m_hdl_db;

  /**
   * The Key is a user defined identifer for this ACL
   */
  const key_t m_key;

  /**
   * A sorted list of the rules
   */
  rules_t m_rules;
};

}; // namesace ACL
}; // namespace VOM

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */

#endif
