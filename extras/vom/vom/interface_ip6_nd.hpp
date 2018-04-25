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

#ifndef __VOM_INTERFACE_IP6_ND_H__
#define __VOM_INTERFACE_IP6_ND_H__

#include "vom/dump_cmd.hpp"
#include "vom/hw.hpp"
#include "vom/inspect.hpp"
#include "vom/interface.hpp"
#include "vom/object_base.hpp"
#include "vom/om.hpp"
#include "vom/ra_config.hpp"
#include "vom/ra_prefix.hpp"
#include "vom/rpc_cmd.hpp"
#include "vom/singular_db.hpp"

namespace VOM {
/**
 * A representation of L3 configuration on an interface
 */
template <typename CLASS, typename CMD>
class interface_ip6_nd : public object_base
{
public:
  typedef CLASS class_t;
  /**
   * Construct a new object matching the desried state
   */
  interface_ip6_nd(const interface& itf, const class_t cls)
    : m_itf(itf.singular())
    , m_cls(cls)
    , m_config(true)
  {
  }

  /**
   * Copy Constructor
   */
  interface_ip6_nd(const interface_ip6_nd& o)
    : m_itf(o.m_itf)
    , m_cls(o.m_cls)
    , m_config(o.m_config)
  {
  }

  /**
   * Destructor
   */
  ~interface_ip6_nd()
  {
    sweep();
    m_db.release(m_itf->key(), this);
  }

  /**
   * Return the 'singular instance' of the interface ip6nd that matches
   * this object
 */
  std::shared_ptr<interface_ip6_nd> singular() const
  {
    return find_or_add(*this);
  }

  /**
   * convert to string format for debug purposes
   */
  std::string to_string() const
  {
    std::ostringstream s;
    s << "interface-ip6-nd:["
      << " itf:" << m_itf->to_string() << " " << m_cls.to_string() << " "
      << m_config.to_string() << "]";

    return (s.str());
  }

  /**
   * Dump all config into the stream provided
   */
  static void dump(std::ostream& os) { m_db.dump(os); }

  /**
   * The key type for interface ip6 nd
   */
  typedef interface::key_t key_t;

  /**
   * Find an singular instance in the DB for the interface passed
   */
  static std::shared_ptr<interface_ip6_nd> find(const interface& i)
  {
    /*
     * Loop throught the entire map looking for matching interface.
     * not the most efficient algorithm, but it will do for now. The
     * number of ra configs is low.
     */
    std::deque<std::shared_ptr<interface_ip6_nd>> rac;

    auto it = m_db.cbegin();

    while (it != m_db.cend()) {
      /*
       * The key in the DB is a pair of the interface's name.
       * If the keys match, save the ra-config
       */
      auto key = it->first;

      if (i.key() == key.first) {
        rac.push_back(it->second.lock());
      }

      ++it;
    }

    return (rac);
  }

  /**
   * A functor class that binds the ra config to the interface
   */
  class config_cmd : public rpc_cmd<HW::item<bool>, rc_t, CMD>
  {
  public:
    /**
     * Constructor
     */
    config_cmd(HW::item<bool>& item, const handle_t& itf, const class_t& cls)
      : rpc_cmd<HW::item<bool>, rc_t, CMD>(item)
      , m_itf(itf)
      , m_cls(cls)
    {
    }

    /**
     * Issue the command to VPP/HW
     */
    rc_t issue(connection& con);

    /**
     * convert to string format for debug purposes
     */
    std::string to_string() const
    {
      std::ostringstream s;
      s << "interface-ip6-nd: " << this->item().to_string()
        << " itf:" << m_itf.to_string() << " " << m_cls.to_string();

      return (s.str());
    }

    /**
     * Comparison operator - only used for UT
     */
    bool operator==(const config_cmd& other) const
    {
      return ((m_itf == other.m_itf) && (m_cls == other.m_cls));
    }

  private:
    /**
     * Reference to the interface to bind to
     */
    const handle_t& m_itf;

    /**
     * Reference to the config class
     */
    const class_t& m_cls;
  };

  /**
   * A cmd class that Unbinds L3 Config from an interface
   */
  class unconfig_cmd : public rpc_cmd<HW::item<bool>, rc_t, CMD>
  {
  public:
    /**
     * Constructor
     */
    unconfig_cmd(HW::item<bool>& item, const handle_t& itf, const class_t& cls)
      : rpc_cmd<HW::item<bool>, rc_t, CMD>(item)
      , m_itf(itf)
      , m_cls(cls)
    {
    }

    /**
     * Issue the command to VPP/HW
     */
    rc_t issue(connection& con);

    /**
     * convert to string format for debug purposes
     */
    std::string to_string() const
    {
      std::ostringstream s;
      s << "interface-ip6-nd: " << this->item().to_string()
        << " itf:" << m_itf.to_string() << " " << m_cls.to_string();

      return (s.str());
    }

    /**
     * Comparison operator - only used for UT
     */
    bool operator==(const unconfig_cmd& other) const
    {
      return ((m_itf == other.m_itf) && (m_cls == other.m_cls));
    }

  private:
    /**
     * Reference to the interface to unbind fomr
     */
    const handle_t& m_itf;

    /**
     * Reference to the config class to undo configurations
     */
    const class_t& m_cls;
  };

private:
  /**
   * Class definition for listeners to OM events
   */
  class event_handler : public OM::listener, public inspect::command_handler
  {
  public:
    event_handler()
    {
      OM::register_listener(this);
      inspect::register_handler({ "ip6_nd " }, "interface ip6 nd", this);
    }

    virtual ~event_handler() = default;

    /**
     * Handle a populate event
     */
    void handle_populate(const client_db::key_t& key)
    {
      /**
       * VPP provides no dump for ra config
       */
    }

    /**
     * Handle a replay event
     */
    void handle_replay() { m_db.replay(); }

    /**
     * Show the object in the Singular DB
     */
    void show(std::ostream& os) { m_db.dump(os); }

    /**
     * Get the sortable Id of the listener
     */
    dependency_t order() const { return (dependency_t::BINDING); }
  };

  /**
   * event_handler to register with OM
   */
  static event_handler m_evh;

  /**
   * Enqueue commands to the VPP for the update
   */
  void update(const interface_ip6_nd& obj)
  {
    if (!m_config) {
      HW::enqueue(new config_cmd(m_config, m_itf->handle(), m_cls));
    }
  }

  void sweep()
  {
    if (m_config) {
      HW::enqueue(new unconfig_cmd(m_config, m_itf->handle(), m_cls));
    }
    HW::write();
  }

  /**
   * Replay the objects state to HW
   */
  void replay(void)
  {
    if (m_config) {
      HW::enqueue(new config_cmd(m_config, m_itf->handle(), m_cls));
    }
  }

  /**
   * Find or add the singular instance in the DB
   */
  static std::shared_ptr<interface_ip6_nd> find_or_add(
    const interface_ip6_nd& temp)
  {
    return (m_db.find_or_add(temp.m_itf->key(), temp));
  }

  /*
   * It's the VPPHW class that updates the objects in HW
   */
  friend class OM;

  /**
   * It's the singular_db class that calls replay()
   */
  friend class singular_db<key_t, interface_ip6_nd>;

  const std::shared_ptr<interface> m_itf;

  const class_t m_cls;

  const key_t m_key;

  /**
   * HW configuration for the binding. The bool representing the
   * do/don't bind.
 */
  HW::item<bool> m_config;

  /**
   * A map of all interface ip6 nd keyed against a combination of the
   * interface and subnet's keys.
   */
  static singular_db<key_t, interface_ip6_nd> m_db;
};

/**
 * Typedef the ip6nd_ra_config
 */
typedef interface_ip6_nd<ra_config, vapi::Sw_interface_ip6nd_ra_config>
  ip6nd_ra_config;

/**
 * Typedef the ip6nd_ra_prefix
 */
typedef interface_ip6_nd<ra_prefix, vapi::Sw_interface_ip6nd_ra_prefix>
  ip6nd_ra_prefix;

/**
 * Definition of the static singular_db for ACL Lists
 */
template <typename CLASS, typename CMD>
singular_db<typename interface_ip6_nd<CLASS, CMD>::key_t,
            interface_ip6_nd<CLASS, CMD>>
  interface_ip6_nd<CLASS, CMD>::m_db;

template <typename CLASS, typename CMD>
typename interface_ip6_nd<CLASS, CMD>::event_handler
  interface_ip6_nd<CLASS, CMD>::m_evh;
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */

#endif
