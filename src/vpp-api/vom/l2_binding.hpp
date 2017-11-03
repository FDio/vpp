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

#ifndef __VOM_L2_BINDING_H__
#define __VOM_L2_BINDING_H__

#include "vom/bridge_domain.hpp"
#include "vom/hw.hpp"
#include "vom/inspect.hpp"
#include "vom/interface.hpp"
#include "vom/object_base.hpp"
#include "vom/om.hpp"
#include "vom/singular_db.hpp"

namespace VOM {
/**
 * A Clas representing the binding of an L2 interface to a bridge-domain
 * and the properties of that binding.
 */
class l2_binding : public object_base
{
public:
  struct l2_vtr_op_t : public enum_base<l2_vtr_op_t>
  {
    l2_vtr_op_t(const l2_vtr_op_t& l) = default;
    ~l2_vtr_op_t() = default;

    const static l2_vtr_op_t L2_VTR_DISABLED;
    const static l2_vtr_op_t L2_VTR_PUSH_1;
    const static l2_vtr_op_t L2_VTR_PUSH_2;
    const static l2_vtr_op_t L2_VTR_POP_1;
    const static l2_vtr_op_t L2_VTR_POP_2;
    const static l2_vtr_op_t L2_VTR_TRANSLATE_1_1;
    const static l2_vtr_op_t L2_VTR_TRANSLATE_1_2;
    const static l2_vtr_op_t L2_VTR_TRANSLATE_2_1;
    const static l2_vtr_op_t L2_VTR_TRANSLATE_2_2;

  private:
    l2_vtr_op_t(int v, const std::string s);
  };

  /**
   * Construct a new object matching the desried state
   */
  l2_binding(const interface& itf, const bridge_domain& bd);

  /**
   * Copy Constructor
   */
  l2_binding(const l2_binding& o);

  /**
   * Destructor
   */
  ~l2_binding();

  /**
   * Return the 'singular instance' of the L2 config that matches this
   * object
   */
  std::shared_ptr<l2_binding> singular() const;

  /**
   * convert to string format for debug purposes
   */
  std::string to_string() const;

  /**
   * Dump all l2_bindings into the stream provided
   */
  static void dump(std::ostream& os);

  /**
   * Set the VTR operation on the binding/interface
   */
  void set(const l2_vtr_op_t& op, uint16_t tag);

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
   * Enquue commonds to the VPP command Q for the update
   */
  void update(const l2_binding& obj);

  /**
   * Find or Add the singular instance in the DB
   */
  static std::shared_ptr<l2_binding> find_or_add(const l2_binding& temp);

  /*
   * It's the OM class that calls singular()
   */
  friend class OM;

  /**
   * It's the singular_db class that calls replay()
   */
  friend class singular_db<const handle_t, l2_binding>;

  /**
   * Sweep/reap the object if still stale
   */
  void sweep(void);

  /**
   * replay the object to create it in hardware
   */
  void replay(void);

  /**
   * A reference counting pointer the interface that this L2 layer
   * represents. By holding the reference here, we can guarantee that
   * this object will outlive the interface
   */
  const std::shared_ptr<interface> m_itf;

  /**
   * A reference counting pointer the Bridge-Domain that this L2
   * interface is bound to. By holding the reference here, we can
   * guarantee that this object will outlive the BD.
   */
  const std::shared_ptr<bridge_domain> m_bd;

  /**
   * HW configuration for the binding. The bool representing the
   * do/don't bind.
 */
  HW::item<bool> m_binding;

  /**
   * HW configuration for the VTR option
   */
  HW::item<l2_vtr_op_t> m_vtr_op;

  /**
   * The Dot1q tag for the VTR operation
   */
  uint16_t m_vtr_op_tag;

  /**
   * A map of all L2 interfaces key against the interface's handle_t
   */
  static singular_db<const handle_t, l2_binding> m_db;
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
