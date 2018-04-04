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

#ifndef __VOM_GBP_RECIRC_H__
#define __VOM_GBP_RECIRC_H__

#include "vom/gbp_endpoint_group.hpp"
#include "vom/interface.hpp"
#include "vom/singular_db.hpp"

namespace VOM {
/**
 * A recirculation interface for GBP use pre/post NAT
 */
class gbp_recirc : public object_base
{
public:
  /**
   * The key for a GBP recirc interface
   */
  typedef interface::key_t key_t;

  struct type_t : public enum_base<type_t>
  {
    /**
     * Internal recirclation interfaces accept per-NAT translation
     * traffic from the external/NAT EPG and inject into the
     * private/NAT-inside EPG
     */
    const static type_t INTERNAL;

    /**
     * External recirculation interfaces accept post-NAT translation
     * traffic from the internal EPG and inject into the
     * NAT EPG
     */
    const static type_t EXTERNAL;

  private:
    type_t(int v, const std::string s);
  };

  /**
   * Construct a GBP recirc
   */
  gbp_recirc(const interface& itf,
             const type_t& type,
             const gbp_endpoint_group& epg);

  /**
   * Copy Construct
   */
  gbp_recirc(const gbp_recirc& r);

  /**
   * Destructor
   */
  ~gbp_recirc();

  /**
   * Return the object's key
   */
  const key_t key() const;

  /**
   * comparison operator
   */
  bool operator==(const gbp_recirc& bdae) const;

  /**
   * Return the matching 'singular instance'
   */
  std::shared_ptr<gbp_recirc> singular() const;

  /**
   * Find the instnace of the recirc interface in the OM
   */
  static std::shared_ptr<gbp_recirc> find(const key_t& k);

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
   * return the recirculation interface's handle
   */
  const handle_t& handle() const;

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
  void update(const gbp_recirc& obj);

  /**
   * Find or add the instnace of the bridge_domain domain in the OM
   */
  static std::shared_ptr<gbp_recirc> find_or_add(const gbp_recirc& temp);

  /*
   * It's the VPPHW class that updates the objects in HW
   */
  friend class OM;

  /**
   * It's the singular_db class that calls replay()
   */
  friend class singular_db<key_t, gbp_recirc>;

  /**
   * Sweep/reap the object if still stale
   */
  void sweep(void);

  /**
   * HW configuration for the result of creating the recirc
   */
  HW::item<bool> m_hw;

  /**
   * The interface the recirc is attached to.
   */
  std::shared_ptr<interface> m_itf;

  /**
   * Is the reicrc for the external (i.e. post-NAT) or internal
   */
  type_t m_type;

  /**
   * The EPG the recirc is in
   */
  std::shared_ptr<gbp_endpoint_group> m_epg;

  /**
   * A map of all bridge_domains
   */
  static singular_db<key_t, gbp_recirc> m_db;
};

}; // namespace VOM

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */

#endif
