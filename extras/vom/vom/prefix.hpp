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

#ifndef __VOM_PREFIX_H__
#define __VOM_PREFIX_H__

#include "vom/enum_base.hpp"
#include <boost/asio/ip/address.hpp>

namespace VOM {
/**
 * Types belonging to Routing
 */

/**
 * A next-hop protocol describes the protocol of a peer to which packets
 * are sent after matching a route.
 */
class nh_proto_t : public enum_base<nh_proto_t>
{
public:
  const static nh_proto_t IPV4;
  const static nh_proto_t IPV6;
  const static nh_proto_t MPLS;
  const static nh_proto_t ETHERNET;

  static const nh_proto_t& from_address(const boost::asio::ip::address& addr);

private:
  /**
   * Private constructor taking the value and the string name
   */
  nh_proto_t(int v, const std::string& s);
};

/**
 * An L3 protocol can be used to construct a prefix that is used
 * to match packets are part of a route.
 */
class l3_proto_t : public enum_base<l3_proto_t>
{
public:
  const static l3_proto_t IPV4;
  const static l3_proto_t IPV6;
  const static l3_proto_t MPLS;

  bool is_ipv4();
  bool is_ipv6();

  static const l3_proto_t& from_address(const boost::asio::ip::address& addr);

  const nh_proto_t& to_nh_proto() const;

private:
  /**
   * Private constructor taking the value and the string name
   */
  l3_proto_t(int v, const std::string& s);
};

/**
 * Ostream output for l3_proto_t
 */
std::ostream& operator<<(std::ostream& os, const l3_proto_t& l3p);

namespace route {
/**
 * type def the table-id
 */
typedef uint32_t table_id_t;

/**
 * The table-id for the default table
 */
const static table_id_t DEFAULT_TABLE = 0;

/**
 * A prefix defintion. Address + length
 */
class prefix_t
{
public:
  /**
   * Default Constructor - creates ::/0
   */
  prefix_t();
  /**
   * Constructor with address and length
   */
  prefix_t(const boost::asio::ip::address& addr, uint8_t len);
  /**
   * Constructor with just the address, this creates a
   * host prefix
   */
  prefix_t(const boost::asio::ip::address& addr);

  /**
   * Constructor with string and length
   */
  prefix_t(const std::string& s, uint8_t len);

  /**
   * Copy Constructor
   */
  prefix_t(const prefix_t&);

  /**
   * Constructor with VPP API prefix representation
   */
  prefix_t(uint8_t is_ip6, uint8_t* addr, uint8_t len);
  /**
   * Destructor
   */
  ~prefix_t();

  /**
   * Get the address
   */
  const boost::asio::ip::address& address() const;

  /**
   * Get the network mask width
   */
  uint8_t mask_width() const;

  /**
   * Assignement
   */
  prefix_t& operator=(const prefix_t&);

  /**
   * Less than operator
   */
  bool operator<(const prefix_t& o) const;

  /**
   * equals operator
   */
  bool operator==(const prefix_t& o) const;

  /**
   * not equal opartor
   */
  bool operator!=(const prefix_t& o) const;

  /**
   * convert to string format for debug purposes
   */
  std::string to_string() const;

  /**
   * The all Zeros prefix
   */
  const static prefix_t ZERO;

  /**
   * The all Zeros v6 prefix
   */
  const static prefix_t ZEROv6;

  /**
  * Convert the prefix into VPP API parameters
  */
  void to_vpp(uint8_t* is_ip6, uint8_t* addr, uint8_t* len) const;

  /**
   * Return a address representation of the mask, e.g. 255.255.0.0
   */
  boost::asio::ip::address mask() const;

  /**
   * get the lowest address in the prefix
   */
  prefix_t low() const;

  /**
   * Get the highest address in the prefix
   */
  prefix_t high() const;

  /**
   * Get the L3 protocol
   */
  l3_proto_t l3_proto() const;

private:
  /**
   * The address
   */
  boost::asio::ip::address m_addr;

  /**
   * The prefix length
   */
  uint8_t m_len;
};

/**
* A prefix defintion. Address + length
*/
class mprefix_t
{
public:
  /**
   * Default Constructor - creates ::/0
   */
  mprefix_t();
  /**
   * Constructor for (S,G)
   */
  mprefix_t(const boost::asio::ip::address& saddr,
            const boost::asio::ip::address& gaddr);
  /*
   * Constructor for (*,G)
   */
  mprefix_t(const boost::asio::ip::address& gaddr);

  /*
   * Constructor for (*,G/n)
   */
  mprefix_t(const boost::asio::ip::address& gaddr, uint8_t len);

  /**
*Constructor for (S,G)
*/
  mprefix_t(const boost::asio::ip::address& saddr,
            const boost::asio::ip::address& gaddr,
            uint16_t len);

  /**
   * Copy Constructor
   */
  mprefix_t(const mprefix_t&);

  /**
   * Destructor
   */
  ~mprefix_t();

  /**
   * Get the address
   */
  const boost::asio::ip::address& grp_address() const;
  const boost::asio::ip::address& src_address() const;

  /**
   * Get the network mask width
   */
  uint8_t mask_width() const;

  /**
   * Assignement
   */
  mprefix_t& operator=(const mprefix_t&);

  /**
   * Less than operator
   */
  bool operator<(const mprefix_t& o) const;

  /**
   * equals operator
   */
  bool operator==(const mprefix_t& o) const;

  /**
   * not equal opartor
   */
  bool operator!=(const mprefix_t& o) const;

  /**
   * convert to string format for debug purposes
   */
  std::string to_string() const;

  /**
   * The all Zeros prefix
   */
  const static mprefix_t ZERO;

  /**
   * The all Zeros v6 prefix
   */
  const static mprefix_t ZEROv6;

  /**
   * Get the L3 protocol
   */
  l3_proto_t l3_proto() const;

  void to_vpp(uint8_t* is_ip6,
              uint8_t* saddr,
              uint8_t* gaddr,
              uint16_t* len) const;

private:
  /**
   * The address
   */
  boost::asio::ip::address m_gaddr;
  boost::asio::ip::address m_saddr;

  /**
   * The prefix length
   */
  uint8_t m_len;
};

}; // namespace route

boost::asio::ip::address_v4 operator|(const boost::asio::ip::address_v4& addr1,
                                      const boost::asio::ip::address_v4& addr2);

boost::asio::ip::address_v4 operator&(const boost::asio::ip::address_v4& addr1,
                                      const boost::asio::ip::address_v4& addr2);

boost::asio::ip::address_v4 operator~(const boost::asio::ip::address_v4& addr1);

boost::asio::ip::address_v6 operator|(const boost::asio::ip::address_v6& addr1,
                                      const boost::asio::ip::address_v6& addr2);

boost::asio::ip::address_v6 operator&(const boost::asio::ip::address_v6& addr1,
                                      const boost::asio::ip::address_v6& addr2);

boost::asio::ip::address_v6 operator~(const boost::asio::ip::address_v6& addr1);

boost::asio::ip::address operator|(const boost::asio::ip::address& addr1,
                                   const boost::asio::ip::address& addr2);

boost::asio::ip::address operator&(const boost::asio::ip::address& addr1,
                                   const boost::asio::ip::address& addr2);

boost::asio::ip::address operator~(const boost::asio::ip::address& addr1);

/**
 * Ostream printer for prefix_t
 */
std::ostream& operator<<(std::ostream& os, const route::prefix_t& pfx);

/**
 * Convert a boost address into a VPP bytes string
 */
void to_bytes(const boost::asio::ip::address& addr,
              uint8_t* is_ip6,
              uint8_t* array);
void to_bytes(const boost::asio::ip::address_v4& addr, uint8_t* array);
void to_bytes(const boost::asio::ip::address_v6& addr, uint8_t* array);

/**
 * Get the prefix mask length of a host route from the boost address
 */
uint32_t mask_width(const boost::asio::ip::address& addr);

/**
 * Convert a VPP byte stinrg into a boost addresss
 */
boost::asio::ip::address from_bytes(uint8_t is_ip6, const uint8_t* array);
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */

#endif
