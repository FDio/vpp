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

#ifndef __VOM_GBP_CONTRACT_H__
#define __VOM_GBP_CONTRACT_H__

#include "vom/acl_list.hpp"
#include "vom/gbp_endpoint.hpp"
#include "vom/gbp_rule.hpp"
#include "vom/interface.hpp"
#include "vom/singular_db.hpp"
#include "vom/types.hpp"

namespace VOM {

/**
 * A entry in the ARP termination table of a Bridge Domain
 */
class gbp_contract : public object_base
{
public:
  /**
   * set of gbp rules
   */
  typedef std::set<gbp_rule> gbp_rules_t;

  /**
   * The key for a contract is the pari of EPG-IDs
   */
  typedef std::pair<epg_id_t, epg_id_t> key_t;

  /**
   * Construct a GBP contract
   */
  gbp_contract(epg_id_t src_epg_id,
               epg_id_t dst_epg_id,
               const ACL::l3_list& acl);

  /**
   * Copy Construct
   */
  gbp_contract(const gbp_contract& r);

  /**
   * Destructor
   */
  ~gbp_contract();

  /**
   * Return the object's key
   */
  const key_t key() const;

  /**
   * comparison operator
   */
  bool operator==(const gbp_contract& bdae) const;

  /**
   * Return the matching 'singular instance'
   */
  std::shared_ptr<gbp_contract> singular() const;

  /**
   * Find the instnace of the bridge_domain domain in the OM
   */
  static std::shared_ptr<gbp_contract> find(const key_t& k);

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

  /**
   * Set gbp_rules in case of Redirect Contract
   */
  void set_gbp_rules(const gbp_rules_t& gbp_rules);

private:
  /**
   * Class definition for listeners to OM events
   */
  class event_handler
    : public OM::listener
    , public inspect::command_handler
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
  void update(const gbp_contract& obj);

  /**
   * Find or add the instance of the contract domain in the OM
   */
  static std::shared_ptr<gbp_contract> find_or_add(const gbp_contract& temp);

  /*
   * It's the VPPHW class that updates the objects in HW
   */
  friend class OM;

  /**
   * It's the singular_db class that calls replay()
   */
  friend class singular_db<key_t, gbp_contract>;

  /**
   * Sweep/reap the object if still stale
   */
  void sweep(void);

  /**
   * HW configuration for the result of creating the endpoint
   */
  HW::item<bool> m_hw;

  /**
   * The source EPG ID
   */
  epg_id_t m_src_epg_id;

  /**
   * The destination EPG ID
   */
  epg_id_t m_dst_epg_id;

  /**
   * The ACL applied to traffic between the gourps
   */
  std::shared_ptr<ACL::l3_list> m_acl;

  /**
   * The gbp rules applied to traffic between the gourps
   */
  gbp_rules_t m_gbp_rules;

  /**
   * A map of all bridge_domains
   */
  static singular_db<key_t, gbp_contract> m_db;
};

std::ostream&
operator<<(std::ostream& os, const gbp_contract::key_t& key);
}; // namespace

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */

#endif
