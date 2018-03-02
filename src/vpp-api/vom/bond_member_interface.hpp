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

#ifndef __VOM_BOND_MEMBER_INTERFACE_H__
#define __VOM_BOND_MEMBER_INTERFACE_H__

#include "vom/interface.hpp"

#include <vapi/bond.api.vapi.hpp>

namespace VOM {
/**
 * A bond-member-interface. e.g. a bond_member interface
 */
class bond_member_interface : public interface
{
public:
  /**
   * A member interface mode
   */
  struct mode_t : enum_base<mode_t>
  {
    /**
     * Active member interface mode
     */
    const static mode_t ACTIVE;
    /**
     * Passive member interface mode
     */
    const static mode_t PASSIVE;

    /**
     * Convert VPP's value of the bond to a mode
     */
    static const mode_t from_numeric_val(uint8_t v);

  private:
    /**
     * Private constructor taking the value and the string name
     */
    mode_t(int v, const std::string& s);
  };

  /**
   * A member interface rate
   */
  struct rate_t : enum_base<rate_t>
  {
    /**
     * Fast member interface rate
     */
    const static rate_t FAST;
    /**
     * SLOW member interface rate
     */
    const static rate_t SLOW;

    /**
     * Convert VPP's value of the bond to a mode
     */
    static const rate_t from_numeric_val(uint8_t v);

  private:
    /**
     * Private constructor taking the value and the string name
     */
    rate_t(int v, const std::string& s);
  };

  bond_member_interface(const std::string& name,
                        admin_state_t state,
                        mode_t mode,
                        rate_t rate);

  ~bond_member_interface();
  bond_member_interface(const bond_member_interface& o);

  /**
   * The the singular enslaved instance of the bond interface in the DB by
   * handle
   */
  std::shared_ptr<bond_member_interface> find(const handle_t& hdl);

  /**
   * Return the matching 'singular instance' of the enslaved interface
   */
  std::shared_ptr<bond_member_interface> singular() const;

  /**
   * convert to VPP
   */
  void to_vpp(vapi_payload_bond_enslave& bond_enslave) const;

  /**
   * set the mode
   */
  void set(mode_t mode);

  /**
   * set the rate
   */
  void set(rate_t rate);

  /**
   * convert to string
   */
  std::string to_string(void) const;

  /**
   * less-than operator
   */
  bool operator<(const bond_member_interface& mem_itf) const;

protected:
  /**
   * set the handle
   */
  void set(handle_t& handle);
  friend class interface_factory;

private:
  /**
   * passive vs active member
   */
  mode_t m_mode;

  /**
   * slow 90sec. vs. fast 3sec timeout
   */
  rate_t m_rate;

  /**
   * interface is a friend so it can construct with handles
   */
  friend class interface;

  /**
   * Return the matching 'instance' of the sub-interface
   *  over-ride from the base class
   */
  std::shared_ptr<interface> singular_i() const;

  /*
   * It's the OM class that call singular()
   */
  friend class OM;
};
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */

#endif
