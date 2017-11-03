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

#ifndef __VOM_ROUTE_H__
#define __VOM_ROUTE_H__

#include "vom/interface.hpp"
#include "vom/prefix.hpp"
#include "vom/route_domain.hpp"
#include "vom/singular_db.hpp"

namespace VOM {
/**
 * Types belonging to Routing
 */
namespace route {
/**
 * A path for IP or MPLS routes
 */
class path
{
public:
  /**
   * Special path types
   */
  class special_t : public enum_base<special_t>
  {
  public:
    /**
     * A standard path type. this includes path types
     * that use the next-hop and interface
     */
    const static special_t STANDARD;

    /**
     * A local/for-us/recieve
     */
    const static special_t LOCAL;

    /**
     * drop path
     */
    const static special_t DROP;

    /**
     * a path will return ICMP unreachables
     */
    const static special_t UNREACH;

    /**
     * a path will return ICMP prohibit
     */
    const static special_t PROHIBIT;

  private:
    /**
     * Private constructor taking the value and the string name
     */
    special_t(int v, const std::string& s);
  };

  /**
   * constructor for special paths
   */
  path(special_t special);

  /**
   * Constructor for standard non-recursive paths
   */
  path(const boost::asio::ip::address& nh,
       const interface& interface,
       uint8_t weight = 1,
       uint8_t preference = 0);

  /**
   * Constructor for standard recursive paths
   */
  path(const route_domain& rd,
       const boost::asio::ip::address& nh,
       uint8_t weight = 1,
       uint8_t preference = 0);

  /**
   * Constructor for DVR paths or attached paths.
   */
  path(const interface& interface,
       const nh_proto_t& proto,
       uint8_t weight = 1,
       uint8_t preference = 0);

  /**
   * Copy Constructor
   */
  path(const path& p);

  /**
   * Convert the path into the VPP API representation
   */
  void to_vpp(vapi_payload_ip_add_del_route& payload) const;

  /**
   * Less than operator for set insertion
   */
  bool operator<(const path& p) const;

  /**
   * convert to string format for debug purposes
   */
  std::string to_string() const;

  /**
   * Getters
   */
  special_t type() const;
  nh_proto_t nh_proto() const;
  const boost::asio::ip::address& nh() const;
  std::shared_ptr<route_domain> rd() const;
  std::shared_ptr<interface> itf() const;
  uint8_t weight() const;
  uint8_t preference() const;

private:
  /**
   * The special path tpye
   */
  special_t m_type;

  /**
   * The next-hop protocol
   */
  nh_proto_t m_nh_proto;

  /**
   * The next-hop
   */
  boost::asio::ip::address m_nh;

  /**
   * For recursive routes, this is the table in which the
   * the next-hop exists.
   */
  std::shared_ptr<route_domain> m_rd;

  /**
   * The next-hop interface [if present].
   */
  std::shared_ptr<interface> m_interface;

  /**
   * UCMP weight
   */
  uint8_t m_weight;

  /**
   * Path preference
   */
  uint8_t m_preference;
};

/**
 * A path-list is a set of paths
 */
typedef std::set<path> path_list_t;

/**
 * ostream output for iterator
 */
std::ostream& operator<<(std::ostream& os, const path_list_t& path_list);

/**
 * A IP route
 */
class ip_route : public object_base
{
public:
  /**
   * The key for a route
   */
  typedef std::pair<route::table_id_t, prefix_t> key_t;

  /**
   * Construct a route in the default table
   */
  ip_route(const prefix_t& prefix);

  /**
   * Copy Construct
   */
  ip_route(const ip_route& r);

  /**
   * Construct a route in the given route domain
   */
  ip_route(const route_domain& rd, const prefix_t& prefix);

  /**
   * Destructor
   */
  ~ip_route();

  /**
   * Return the matching 'singular instance'
   */
  std::shared_ptr<ip_route> singular() const;

  /**
   * Add a path.
   */
  void add(const path& path);

  /**
   * remove a path.
   */
  void remove(const path& path);

  /**
   * Find the instnace of the route domain in the OM
   */
  static std::shared_ptr<ip_route> find(const ip_route& temp);

  /**
   * Dump all route-doamin into the stream provided
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
   * Find or add the instnace of the route domain in the OM
   */
  static std::shared_ptr<ip_route> find_or_add(const ip_route& temp);

  /*
   * It's the OM class that updates the objects in HW
   */
  friend class VOM::OM;

  /**
   * It's the singular_db class that calls replay()
   */
  friend class singular_db<key_t, ip_route>;

  /**
   * Commit the acculmulated changes into VPP. i.e. to a 'HW" write.
   */
  void update(const ip_route& obj);

  /**
   * Sweep/reap the object if still stale
   */
  void sweep(void);

  /**
   * HW configuration for the result of creating the route
   */
  HW::item<bool> m_hw;

  /**
   * The route domain the route is in.
   */
  std::shared_ptr<route_domain> m_rd;

  /**
   * The prefix to match
   */
  prefix_t m_prefix;

  /**
   * The set of paths
   */
  path_list_t m_paths;

  /**
   * A map of all routes
   */
  static singular_db<key_t, ip_route> m_db;
};

std::ostream& operator<<(std::ostream& os, const ip_route::key_t& key);
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
