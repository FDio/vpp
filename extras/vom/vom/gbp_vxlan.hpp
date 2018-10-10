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

#ifndef __VOM_GBP_VXLAN_H__
#define __VOM_GBP_VXLAN_H__

#include "vom/gbp_bridge_domain.hpp"
#include "vom/gbp_route_domain.hpp"
#include "vom/hw.hpp"
#include "vom/inspect.hpp"
#include "vom/interface.hpp"
#include "vom/singular_db.hpp"

namespace VOM {
/**
 * A representation of a GBP_VXLAN Tunnel in VPP
 */
class gbp_vxlan : public interface
{
public:
  /**
   * The VNI is the key
   */
  typedef uint32_t key_t;

  /**
   * Construct a new object matching the desried state
   */
  gbp_vxlan(uint32_t vni, const gbp_bridge_domain& gbd);
  gbp_vxlan(uint32_t vni, const gbp_route_domain& grd);

  /*
   * Destructor
   */
  ~gbp_vxlan();

  /**
   * Copy constructor
   */
  gbp_vxlan(const gbp_vxlan& o);

  bool operator==(const gbp_vxlan& vt) const;

  /**
     * Return the matching 'singular instance'
     */
  std::shared_ptr<gbp_vxlan> singular() const;

  /**
   * Return the object's key
   */
  const key_t key() const;

  /**
   * Debug rpint function
   */
  virtual std::string to_string() const;

  /**
   * Return VPP's handle to this object
   */
  const handle_t& handle() const;

  /**
   * Dump all L3Configs into the stream provided
   */
  static void dump(std::ostream& os);

  /**
   * Find the GBP_VXLAN tunnel in the OM
   */
  static std::shared_ptr<gbp_vxlan> find(const key_t k);

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
   * Event handle to register with OM
   */
  static event_handler m_evh;

  /**
   * Commit the acculmulated changes into VPP. i.e. to a 'HW" write.
   */
  void update(const gbp_vxlan& obj);

  /**
   * Return the matching 'instance' of the sub-interface
   *  over-ride from the base class
   */
  std::shared_ptr<interface> singular_i() const;

  /**
   * Find the GBP_VXLAN tunnel in the OM
   */
  static std::shared_ptr<gbp_vxlan> find_or_add(const gbp_vxlan& temp);

  /*
   * It's the VPPHW class that updates the objects in HW
   */
  friend class OM;

  /**
   * It's the singular_db class that calls replay()
   */
  friend class singular_db<key_t, gbp_vxlan>;

  /**
   * Sweep/reap the object if still stale
   */
  void sweep(void);

  /**
   * replay the object to create it in hardware
   */
  void replay(void);

  /**
   * Tunnel VNI/key
   */
  uint32_t m_vni;
  std::shared_ptr<gbp_bridge_domain> m_gbd;
  std::shared_ptr<gbp_route_domain> m_grd;

  /**
   * A map of all VLAN tunnela against thier key
   */
  static singular_db<key_t, gbp_vxlan> m_db;

  /**
   * Construct a unique name for the tunnel
   */
  static std::string mk_name(uint32_t vni);
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
