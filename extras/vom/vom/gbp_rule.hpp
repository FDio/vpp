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

#ifndef __VOM_GBP_RULE_H__
#define __VOM_GBP_RULE_H__

#include <set>

#include "vom/types.hpp"
#include <vapi/gbp.api.vapi.h>
namespace VOM {
class gbp_rule
{
public:
  /**
   * Representation of next hop
   */
  struct next_hop_t
  {
    /**
     * Constructor for next_hop_t
     */
    next_hop_t(const boost::asio::ip::address& ip,
               const mac_address_t& mac,
               uint32_t bd_id,
               uint32_t rd_id);

    /**
     * default destructor
     */
    ~next_hop_t() = default;

    /**
     * convert to string
     */
    std::string to_string() const;

    /**
     * less-than operator
     */
    bool operator<(const next_hop_t& nh) const;

    /**
     * comparison operator (for testing)
     */
    bool operator==(const next_hop_t& nh) const;

    /**
     * get the IP address
     */
    const boost::asio::ip::address& getIp(void) const;

    /**
     * get the mac address
     */
    const mac_address_t& getMac(void) const;

    /**
     * get the bridge domain Id
     */
    const uint32_t getBdId(void) const;

    /**
     * get the route domain Id
     */
    const uint32_t getRdId(void) const;

  private:
    /**
     * IP address for next hop
     */
    const boost::asio::ip::address m_ip;

    /**
     * mac address for interface lookup
     */
    const mac_address_t m_mac;

    /**
     * bridge domain in which redirected endpoints exist
     */
    const uint32_t m_bd_id;

    /**
     * route domain in which redirected endpoints exist
     */
    const uint32_t m_rd_id;
  };

  /**
   * hash mode enum
   */
  struct hash_mode_t : public enum_base<hash_mode_t>
  {
    /**
     * Flow Hash is calculated based on SRC IP
     * in case of load balancing
     */
    const static hash_mode_t SRC_IP;

    /**
     * Flow hash is calculated based on DST IP
     */
    const static hash_mode_t DST_IP;

    /**
     * Flow hash is calculated based on SRC IP,
     * DST IP and Protocol. SRC IP and DST IP
     * addresses are sorted before hash such that
     * a same hash is generated in both directions.
     */
    const static hash_mode_t SYMMETRIC;

    /**
     * create the hash mode from int value
     */
    static const hash_mode_t& from_int(vapi_enum_gbp_hash_mode i);

  private:
    hash_mode_t(int v, const std::string s);
  };

  /**
   * unordered set of next hops
   */
  typedef std::set<next_hop_t> next_hops_t;

  /**
   * Representation of set of next hops and
   * associated hash mode profile
   */
  struct next_hop_set_t
  {
    /**
     * Constructor for next_hop_set_t
     */
    next_hop_set_t(const hash_mode_t& hm, next_hops_t& nhs);

    /**
     * Destructor for next_hop_set_t
     */
    ~next_hop_set_t() = default;

    /**
     * convert to string
     */
    std::string to_string() const;

    /**
     * Comparison operator
     */
    bool operator==(const next_hop_set_t& nhs) const;

    /**
     * get the hash mode
     */
    const hash_mode_t& getHashMode(void) const;

    /**
     * get the set of next hops
     */
    const next_hops_t& getNextHops(void) const;

  private:
    /**
     * hash mode for this rule
     */
    const hash_mode_t m_hm;

    /**
     * set of next hops
     */
    const next_hops_t m_nhs;
  };

  /**
   * ACL rule action enum
   */
  struct action_t : public enum_base<action_t>
  {
    /**
     * Permit action
     */
    const static action_t PERMIT;

    /**
     * Deny action
     */
    const static action_t DENY;

    /**
     * Redirect action
     */
    const static action_t REDIRECT;

    /**
     * create the action from int value
     */
    static const action_t& from_int(vapi_enum_gbp_rule_action i);

  private:
    action_t(int v, const std::string s);
  };

  /**
   * Construct a new object matching the desried state
   */
  gbp_rule(uint32_t priority, const next_hop_set_t& nhs, const action_t& a);

  /**
   * Copy Constructor
   */
  gbp_rule(const gbp_rule& o) = default;

  /**
   * Destructor
   */
  ~gbp_rule() = default;

  /**
   * convert to string format for debug purposes
   */
  std::string to_string() const;

  /**
   * less-than operator
   */
  bool operator<(const gbp_rule& rule) const;

  /**
   * comparison operator (for testing)
   */
  bool operator==(const gbp_rule& rule) const;

  /**
   * Getters
   */
  uint32_t priority() const;
  const next_hop_set_t& nhs() const;
  const action_t& action() const;

private:
  /**
   * Priority. Used to sort the rules in a list in the order
   * in which they are applied
   */
  uint32_t m_priority;

  /**
   * set of next hops along with hash mode profile
   */
  const next_hop_set_t m_nhs;

  /**
   * Action on match
   */
  const action_t m_action;
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
