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

#ifndef __VOM_ACL_BINDING_H__
#define __VOM_ACL_BINDING_H__

#include <ostream>

#include "vom/acl_list.hpp"
#include "vom/acl_types.hpp"
#include "vom/hw.hpp"
#include "vom/inspect.hpp"
#include "vom/interface.hpp"
#include "vom/object_base.hpp"
#include "vom/om.hpp"
#include "vom/singular_db.hpp"

namespace VOM {
namespace ACL {
/**
 * A binding between an ACL and an interface.
 * A representation of the application of the ACL to the interface.
 */
template <typename LIST>
class binding : public object_base
{
public:
  /**
   * The key for a binding is the direction and the interface
   */
  typedef std::pair<direction_t, interface::key_type> key_t;

  /**
   * Construct a new object matching the desried state
   */
  binding(const direction_t& direction, const interface& itf, const LIST& acl)
    : m_direction(direction)
    , m_itf(itf.singular())
    , m_acl(acl.singular())
    , m_binding(0)
  {
    m_evh.order();
  }

  /**
   * Copy Constructor
   */
  binding(const binding& o)
    : m_direction(o.m_direction)
    , m_itf(o.m_itf)
    , m_acl(o.m_acl)
    , m_binding(0)
  {
  }

  /**
   * Destructor
   */
  ~binding()
  {
    sweep();
    m_db.release(std::make_pair(m_direction, m_itf->key()), this);
  }

  /**
   * Return the 'singular instance' of the L2 config that matches this
   * object
   */
  std::shared_ptr<binding> singular() const { return find_or_add(*this); }

  /**
   * convert to string format for debug purposes
   */
  std::string to_string() const
  {
    std::ostringstream s;
    s << "acl-binding:[" << m_direction.to_string() << " " << m_itf->to_string()
      << " " << m_acl->to_string() << " " << m_binding.to_string() << "]";

    return (s.str());
  }

  /**
   * Dump all bindings into the stream provided
   */
  static void dump(std::ostream& os) { m_db.dump(os); }

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
      inspect::register_handler({ "acl-binding" }, "ACL bindings", this);
    }
    virtual ~event_handler() = default;

    /**
     * Handle a populate event
     */
    void handle_populate(const client_db::key_t& key);

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
   * Enquue commonds to the VPP command Q for the update
   */
  void update(const binding& obj);

  /**
   * Find or Add the instance in the DB
   */
  static std::shared_ptr<binding> find_or_add(const binding& temp)
  {
    return (m_db.find_or_add(
      std::make_pair(temp.m_direction, temp.m_itf->key()), temp));
  }

  /*
   * It's the OM class that calls singular()
   */
  friend class VOM::OM;

  /**
   * It's the singular_db class that calls replay()
   */
  friend class singular_db<key_t, binding>;

  /**
   * Sweep/reap the object if still stale
   */
  void sweep(void);

  /**
   * Replay the objects state to HW
   */
  void replay(void);

  /**
   * The direction the of the packets on which to apply the ACL
   * input or output
   */
  const direction_t m_direction;

  /**
   * A reference counting pointer the interface that this L3 layer
   * represents. By holding the reference here, we can guarantee that
   * this object will outlive the interface
   */
  const std::shared_ptr<interface> m_itf;

  /**
   * A reference counting pointer the ACL that this
   * interface is bound to. By holding the reference here, we can
   * guarantee that this object will outlive the BD.
   */
  const std::shared_ptr<LIST> m_acl;

  /**
   * HW configuration for the binding. The bool representing the
   * do/don't bind.
   */
  HW::item<bool> m_binding;

  /**
   * A map of all L2 interfaces key against the interface's handle_t
   */
  static singular_db<key_t, binding> m_db;
};

/**
 * Typedef the L3 binding type
 */
typedef binding<l3_list> l3_binding;

/**
 * Typedef the L2 binding type
 */
typedef binding<l2_list> l2_binding;

/**
 * Definition of the static Singular DB for ACL bindings
 */
template <typename LIST>
singular_db<typename ACL::binding<LIST>::key_t, ACL::binding<LIST>>
  binding<LIST>::m_db;

template <typename LIST>
typename ACL::binding<LIST>::event_handler binding<LIST>::m_evh;
};

std::ostream& operator<<(
  std::ostream& os,
  const std::pair<direction_t, interface::key_type>& key);
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */

#endif
