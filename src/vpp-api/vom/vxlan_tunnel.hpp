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

#ifndef __VOM_VXLAN_TUNNEL_H__
#define __VOM_VXLAN_TUNNEL_H__

#include "vom/hw.hpp"
#include "vom/inspect.hpp"
#include "vom/interface.hpp"
#include "vom/object_base.hpp"
#include "vom/om.hpp"
#include "vom/prefix.hpp"
#include "vom/route_domain.hpp"
#include "vom/singular_db.hpp"

namespace VOM {
/**
 * A representation of a VXLAN Tunnel in VPP
 */
class vxlan_tunnel : public interface
{
public:
  /**
   * Combaintion of attributes that are a unique key
   * for a VXLAN tunnel
   */
  struct endpoint_t
  {
    /**
     * Default constructor
     */
    endpoint_t();
    /**
     * Constructor taking endpoint values
     */
    endpoint_t(const boost::asio::ip::address& src,
               const boost::asio::ip::address& dst,
               uint32_t vni);

    /**
     * less-than operator for map storage
     */
    bool operator<(const endpoint_t& o) const;

    /**
     * Comparison operator
     */
    bool operator==(const endpoint_t& o) const;

    /**
     * Debug print function
     */
    std::string to_string() const;

    /**
     * The src IP address of the endpoint
     */
    boost::asio::ip::address src;

    /**
     * The destination IP address of the endpoint
     */
    boost::asio::ip::address dst;

    /**
     * The VNI of the endpoint
     */
    uint32_t vni;
  };

  /**
   * Construct a new object matching the desried state
   */
  vxlan_tunnel(const boost::asio::ip::address& src,
               const boost::asio::ip::address& dst,
               uint32_t vni);

  /**
   * Construct a new object matching the desried state with a handle
   * read from VPP
   */
  vxlan_tunnel(const handle_t& hdl,
               const boost::asio::ip::address& src,
               const boost::asio::ip::address& dst,
               uint32_t vni);

  /*
   * Destructor
   */
  ~vxlan_tunnel();

  /**
   * Copy constructor
   */
  vxlan_tunnel(const vxlan_tunnel& o);

  /**
   * Return the matching 'singular instance'
   */
  std::shared_ptr<vxlan_tunnel> singular() const;

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
  void update(const vxlan_tunnel& obj);

  /**
   * Return the matching 'instance' of the sub-interface
   *  over-ride from the base class
   */
  std::shared_ptr<interface> singular_i() const;

  /**
   * Find the VXLAN tunnel in the OM
   */
  static std::shared_ptr<vxlan_tunnel> find_or_add(const vxlan_tunnel& temp);

  /*
   * It's the VPPHW class that updates the objects in HW
   */
  friend class OM;

  /**
   * It's the singular_db class that calls replay()
   */
  friend class singular_db<endpoint_t, vxlan_tunnel>;

  /**
   * Sweep/reap the object if still stale
   */
  void sweep(void);

  /**
   * replay the object to create it in hardware
   */
  void replay(void);

  /**
   * Tunnel enpoint/key
   */
  endpoint_t m_tep;

  /**
   * A map of all VLAN tunnela against thier key
   */
  static singular_db<endpoint_t, vxlan_tunnel> m_db;

  /**
   * Construct a unique name for the tunnel
   */
  static std::string mk_name(const boost::asio::ip::address& src,
                             const boost::asio::ip::address& dst,
                             uint32_t vni);
};

/**
 * Ostream output for a tunnel endpoint
 */
std::ostream& operator<<(std::ostream& os, const vxlan_tunnel::endpoint_t& ep);

}; // namespace VOM

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */

#endif
