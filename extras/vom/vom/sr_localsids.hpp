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

#ifndef __VOM_SR_LOCALSID_H__
#define __VOM_SR_LOCALSID_H__

#include <memory>

#include "vom/om.hpp"
#include "vom/types.hpp"
#include "vom/singular_db.hpp"
#include "vom/route.hpp"
#include "vom/interface.hpp"
#include "vom/route_domain.hpp"

namespace VOM {

class localsid : public object_base
{
public:
  struct sr_behavior_t : public enum_base<sr_behavior_t>
  {
    /* Unknown behavior */
    const static sr_behavior_t UNKNOWN;

    /* FIB lookup and forward according to matched entry */
    const static sr_behavior_t END;

    /* Forward to L3 adjacency */
    const static sr_behavior_t END_X;

    /* Look for next segment in IPv6 table and forward via matched path */
    const static sr_behavior_t END_T;

    /* Pop IPv6 & extension header and forward via outgoing interface (OIF) */
    const static sr_behavior_t END_DX2;

    /* Pop IPv6 & extension header and forward to L3 adjacency */
    const static sr_behavior_t END_DX6;

    /* Pop IPv6 header and its extension and forward to L3 adjacency */
    const static sr_behavior_t END_DX4;

    /* Pop IPv6 & extension header. Lookup in IPv6 table and forward
     * via matched entry. */
    const static sr_behavior_t END_DT6;

    /* Pop IPv6 & extension header. Lookup in IPv6 table and forward
     * via matched entry */
    const static sr_behavior_t END_DT4;

    /* Get beavior associated with value v */
    static sr_behavior_t from_int(int v);

  private:
    /**
     * private constructor taking the value and the string
     */
    sr_behavior_t(int v, const std::string &s);
  };
  /**
   * Constructor for End
   */
  localsid(const sr_behavior_t &be, const boost::asio::ip::address_v6 &sid);
  /**
   * Constructor for END.DX2
   */
  localsid(const sr_behavior_t &be, const boost::asio::ip::address_v6 &sid,
           const interface &intf);
  /**
   * Constructor for End.T, END.DT4, END.DT6
   */
  localsid(const sr_behavior_t &be, const boost::asio::ip::address_v6 &sid,
           const route_domain &rd);

  /**
   * Constructor for End.X, End.DX6, End.DX4
   */
  localsid(const sr_behavior_t &be, const boost::asio::ip::address_v6 &sid,
           const route::path &path);

  /**
   * Copy Constructor
  */
  localsid(const localsid &l);

  /**
   * Destructor
   */
  ~localsid();

  typedef boost::asio::ip::address_v6 key_t;

  /**
   * Return the object's key
   */
  const key_t& key() const;

  /**
   * Return the matching 'singular instance'
   */
  std::shared_ptr<localsid> singular() const;

  /**
   * Dump localsid into the stream provided
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
   * Commit the acculmulated changes into VPP. i.e. to a 'HW" write.
   */
  void update(const localsid& obj);

  /*
   * Release from singular db
   */
  void release();

  /**
   * The singular instance of the localsid in the DB by key
   */
  static std::shared_ptr<localsid> find(const key_t &k);


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
   * construct a localsid create command
   */
  std::queue<cmd*>& mk_create_cmd(std::queue<cmd*>& cmds);

  /**
   * A map of all localsids
   */
  static singular_db<key_t, localsid> m_db;

  /**
   * Sweep/reap the object if still stale
   */
  void sweep(void);

  /*
   * Find or add the instance of localsid in the table
   */
  static std::shared_ptr<localsid> find_or_add(const localsid &temp);

  /**
   * HW configuration for the result of creating the localsid
   */
  HW::item<bool> m_hw;

  /*
   * Behavior
   */
  const sr_behavior_t m_behavior;

  /**
   * local SID
   */
  const boost::asio::ip::address_v6 m_localsid;

  /*
   * reference to an interface for End.X, End.DX2, End.DX4, End.DX6
   */
  std::shared_ptr<interface> m_intf;

  /*
   * reference to a VRF (i.e. route_domain) for End.DT4, End.DT6, End.T
   */
  std::shared_ptr<route_domain> m_rd;

  /*
   * Next-hop
   */
  const boost::asio::ip::address m_nh;

  /*
   * Only OM class can enable/disable HW, if we remove it we would get
   * Msg_unavailable exceptions
   */
  friend class OM;

  /*
   * It's the singular_db class that calls replay
   */
  friend class singular_db<key_t, localsid>;
};

};

#endif // __VOM_SR_LOCALSID_H__
