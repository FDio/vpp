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

#include <unordered_set>

namespace VOM {
class gbp_rule
{
public:
  struct next_hop_t
  {
    next_hop_t(const boost::asio::ip::address& ip,
               const mac_address_t& mac,
               uint32_t bd_id,
               uint32_t rd_id);
    ~next_hop_t() = default;
    /**
     * convert to string
     */
    std::string to_string() const;
    /**
     * get the ether value
     */
    const boost::asio::ip::address& getIp(void) const;

    /**
     * get the direction
     */
    const mac_address_t& getMac(void) const;
    const uint32_t& getBdId(void) const;
    const uint32_t& getRdId(void) const;

  private:
    /**
     * ethertype for this rule
     */
    const boost::asio::ip::address m_ip;

    /**
     * direction in which ethertype will be applied w.r.t. intf
     */
    const mac_address_t m_mac;

    const uint32_t m_bd_id;
    const uint32_t m_rd_id;
  };

  struct hash_mode_t : public enum_base<hash_mode_t>
  {
    const static hash_mode_t SRC_IP;
    const static hash_mode_t DST_IP;

  private:
    hash_mode_t(int v, const std::string s);
  }

  typedef unordered_set<next_hop_t>
    next_hops_t;

  struct next_hop_set_t
  {
    next_hop_set_t(const hash_mode_t& hm, next_hops_t& nhs);
    ~next_hop_set_t() = default;
    /**
     * convert to string
     */
    std::string to_string() const;
    /**
     * get the ether value
     */
    const hash_mode_t& getHashMode(void) const;

    /**
     * get the direction
     */
    const next_hops_t& getNextHops(void) const;

  private:
    /**
     * ethertype for this rule
     */
    const hash_mode_t m_hm;

    /**
     * direction in which ethertype will be applied w.r.t. intf
     */
    const next_hops_t m_nhs;
  };

  struct action_t : public enum_base<action_t>
  {
    /**
     * Internal subnet is reachable through the source EPG's
     * uplink interface.
     */
    const static action_t PERMIT;

    /**
     * External subnet requires NAT translation before egress.
     */
    const static action_t DENY;

    /**
     * A transport subnet, sent via the RD's UU-fwd interface
     */
    const static action_t REDIRECT;

  private:
    action_t(int v, const std::string s);
  };

  /**
   * Construct a new object matching the desried state
   */
  gbp_rule(uint32_t priority,
           const hash_mode_t& hm,
           const next_hops_t& nhs,
           const action_t& a);

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
  const hash_mode_t& getHM() const;
  next_hops_t& nhs() const;
  const action_t& action() const;

private:
  /**
   * Priority. Used to sort the rules in a list in the order
   * in which they are applied
   */
  const hash_mode_t hm;
  const next_hops_t nhs;
  /**
   * Action on match
   */
  const action_t a;
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
