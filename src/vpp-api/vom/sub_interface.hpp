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

#ifndef __VOM_SUB_INTERFACE_H__
#define __VOM_SUB_INTERFACE_H__

#include "vom/interface.hpp"

namespace VOM {
/**
 * A Sub-interface. e.g. a VLAN sub-interface on an Ethernet interface
 */
class sub_interface : public interface
{
  /*
   * Typedef for VLAN ID
   */
  typedef uint16_t vlan_id_t;

public:
  /**
   * Construct a new object matching the desried state
   */
  sub_interface(const interface& parent, admin_state_t state, vlan_id_t vlan);
  /**
   * Destructor
   */
  ~sub_interface();
  /**
   * Copy Constructor
   */
  sub_interface(const sub_interface& o);

  /**
   * Return the matching 'singular instance' of the sub-interface
   */
  std::shared_ptr<sub_interface> singular() const;

private:
  /**
   * Construct with handle
   */
  sub_interface(const handle_t& handle,
                const interface& parent,
                admin_state_t state,
                vlan_id_t vlan);
  friend class interface_factory;

  /**
   * The interface class can construct interfaces with handles
   */
  friend class interface;

  /**
   * Return the matching 'instance' of the sub-interface
   *  over-ride from the base class
   */
  std::shared_ptr<interface> singular_i() const;

  /**
   * Virtual functions to construct an interface create commands.
   */
  virtual std::queue<cmd*>& mk_create_cmd(std::queue<cmd*>& cmds);

  /**
   * Virtual functions to construct an interface delete commands.
   */
  virtual std::queue<cmd*>& mk_delete_cmd(std::queue<cmd*>& cmds);

  /**
   * From the name of the parent and the vlan,
   * construct the sub-interface's name
   */
  static std::string mk_name(const interface& parent, vlan_id_t vlan);

  /**
   * Refernece conter lock on the parent
   */
  const std::shared_ptr<interface> m_parent;

  /**
   * VLAN ID
   */
  vlan_id_t m_vlan;
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
