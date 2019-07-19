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

#include <boost/algorithm/string.hpp>
#include <sstream>

#include "vom/prefix.hpp"

namespace VOM {
/*
 * Keep this in sync with VPP's fib_protocol_t
 */
const l3_proto_t l3_proto_t::IPV4(0, "ipv4");
const l3_proto_t l3_proto_t::IPV6(1, "ipv6");
const l3_proto_t l3_proto_t::MPLS(2, "mpls");

l3_proto_t::l3_proto_t(int v, const std::string& s)
  : enum_base<l3_proto_t>(v, s)
{
}

bool
l3_proto_t::is_ipv6() const
{
  return (*this == IPV6);
}

bool
l3_proto_t::is_ipv4() const
{
  return (*this == IPV4);
}

const l3_proto_t&
l3_proto_t::from_address(const boost::asio::ip::address& addr)
{
  if (addr.is_v6()) {
    return IPV6;
  }

  return IPV4;
}

const nh_proto_t&
l3_proto_t::to_nh_proto() const
{
  if (*this == IPV4)
    return nh_proto_t::IPV4;
  else if (*this == IPV6)
    return nh_proto_t::IPV6;
  else if (*this == MPLS)
    return nh_proto_t::MPLS;

  return nh_proto_t::IPV4;
}

std::ostream&
operator<<(std::ostream& os, const l3_proto_t& l3p)
{
  os << l3p.to_string();
  return os;
}

/*
 * Keep this in sync with VPP's dpo_proto_t
 */
const nh_proto_t nh_proto_t::IPV4(0, "ipv4");
const nh_proto_t nh_proto_t::IPV6(1, "ipv6");
const nh_proto_t nh_proto_t::MPLS(2, "mpls");
const nh_proto_t nh_proto_t::ETHERNET(3, "ethernet");

nh_proto_t::nh_proto_t(int v, const std::string& s)
  : enum_base<nh_proto_t>(v, s)
{
}

const nh_proto_t&
nh_proto_t::from_address(const boost::asio::ip::address& addr)
{
  if (addr.is_v6()) {
    return IPV6;
  }

  return IPV4;
}

const ip_dscp_t ip_dscp_t::DSCP_CS0(0, "CS0");
const ip_dscp_t ip_dscp_t::DSCP_CS1(8, "CS1");
const ip_dscp_t ip_dscp_t::DSCP_CS2(16, "CS2");
const ip_dscp_t ip_dscp_t::DSCP_CS3(24, "CS3");
const ip_dscp_t ip_dscp_t::DSCP_CS4(32, "CS4");
const ip_dscp_t ip_dscp_t::DSCP_CS5(40, "CS5");
const ip_dscp_t ip_dscp_t::DSCP_CS6(48, "CS6");
const ip_dscp_t ip_dscp_t::DSCP_CS7(50, "CS7");
const ip_dscp_t ip_dscp_t::DSCP_AF11(10, "AF11");
const ip_dscp_t ip_dscp_t::DSCP_AF12(12, "AF12");
const ip_dscp_t ip_dscp_t::DSCP_AF13(14, "AF13");
const ip_dscp_t ip_dscp_t::DSCP_AF21(18, "AF21");
const ip_dscp_t ip_dscp_t::DSCP_AF22(20, "AF22");
const ip_dscp_t ip_dscp_t::DSCP_AF23(22, "AF23");
const ip_dscp_t ip_dscp_t::DSCP_AF31(26, "AF31");
const ip_dscp_t ip_dscp_t::DSCP_AF32(28, "AF32");
const ip_dscp_t ip_dscp_t::DSCP_AF33(30, "AF33");
const ip_dscp_t ip_dscp_t::DSCP_AF41(34, "AF41");
const ip_dscp_t ip_dscp_t::DSCP_AF42(36, "AF42");
const ip_dscp_t ip_dscp_t::DSCP_AF43(38, "AF43");
const ip_dscp_t ip_dscp_t::DSCP_EF(46, "EF");

ip_dscp_t::ip_dscp_t(int v, const std::string& s)
  : enum_base<ip_dscp_t>(v, s)
{
}
ip_dscp_t::ip_dscp_t(int v)
  : enum_base<ip_dscp_t>(v, std::to_string(v))
{
}

/**
 * The all Zeros prefix
 */
const route::prefix_t route::prefix_t::ZERO("0.0.0.0", 0);
const route::prefix_t route::prefix_t::ZEROv6("::", 0);

route::prefix_t::prefix_t(const boost::asio::ip::address& addr, uint8_t len)
  : m_addr(addr)
  , m_len(len)
{
}

route::prefix_t::prefix_t(const boost::asio::ip::address& addr)
  : m_addr(addr)
  , m_len(VOM::mask_width(addr))
{
}

route::prefix_t::prefix_t(const std::string& s, uint8_t len)
  : m_addr(boost::asio::ip::address::from_string(s))
  , m_len(len)
{
}

route::prefix_t::prefix_t(const prefix_t& o)
  : m_addr(o.m_addr)
  , m_len(o.m_len)
{
}

route::prefix_t::prefix_t()
  : m_addr()
  , m_len(0)
{
}

route::prefix_t::~prefix_t()
{
}

route::prefix_t&
route::prefix_t::operator=(const route::prefix_t& o)
{
  m_addr = o.m_addr;
  m_len = o.m_len;

  return (*this);
}

const boost::asio::ip::address&
route::prefix_t::address() const
{
  return (m_addr);
}

uint8_t
route::prefix_t::mask_width() const
{
  return (m_len);
}

bool
route::prefix_t::operator<(const route::prefix_t& o) const
{
  if (m_len == o.m_len) {
    return (m_addr < o.m_addr);
  } else {
    return (m_len < o.m_len);
  }
}

bool
route::prefix_t::operator==(const route::prefix_t& o) const
{
  return (m_len == o.m_len && m_addr == o.m_addr);
}

bool
route::prefix_t::operator!=(const route::prefix_t& o) const
{
  return (!(*this == o));
}

std::string
route::prefix_t::to_string() const
{
  std::ostringstream s;

  s << m_addr.to_string() << "/" << std::to_string(m_len);

  return (s.str());
}

boost::asio::ip::address
from_bytes(uint8_t is_ip6, const uint8_t* bytes)
{
  boost::asio::ip::address addr;

  if (is_ip6) {
    std::array<uint8_t, 16> a;
    std::copy(bytes, bytes + 16, std::begin(a));
    boost::asio::ip::address_v6 v6(a);
    addr = v6;
  } else {
    std::array<uint8_t, 4> a;
    std::copy(bytes, bytes + 4, std::begin(a));
    boost::asio::ip::address_v4 v4(a);
    addr = v4;
  }

  return (addr);
}

route::prefix_t::prefix_t(uint8_t is_ip6, uint8_t* addr, uint8_t len)
  : m_addr(from_bytes(is_ip6, addr))
  , m_len(len)
{
}
void
to_bytes(const boost::asio::ip::address_v6& addr, uint8_t* array)
{
  memcpy(array, addr.to_bytes().data(), 16);
}

void
to_bytes(const boost::asio::ip::address_v4& addr, uint8_t* array)
{
  memcpy(array, addr.to_bytes().data(), 4);
}

void
to_bytes(const boost::asio::ip::address& addr, uint8_t* is_ip6, uint8_t* array)
{
  if (addr.is_v6()) {
    *is_ip6 = 1;
    to_bytes(addr.to_v6(), array);
  } else {
    *is_ip6 = 0;
    to_bytes(addr.to_v4(), array);
  }
}

uint32_t
mask_width(const boost::asio::ip::address& addr)
{
  if (addr.is_v6()) {
    return 128;
  }
  return 32;
}

void
route::prefix_t::to_vpp(uint8_t* is_ip6, uint8_t* addr, uint8_t* len) const
{
  *len = m_len;
  to_bytes(m_addr, is_ip6, addr);
}

l3_proto_t
route::prefix_t::l3_proto() const
{
  if (m_addr.is_v6()) {
    return (l3_proto_t::IPV6);
  } else {
    return (l3_proto_t::IPV4);
  }

  return (l3_proto_t::IPV4);
}

std::ostream&
operator<<(std::ostream& os, const route::prefix_t& pfx)
{
  os << pfx.to_string();

  return (os);
}

boost::asio::ip::address_v4
operator|(const boost::asio::ip::address_v4& addr1,
          const boost::asio::ip::address_v4& addr2)
{
  uint32_t a;
  a = addr1.to_ulong() | addr2.to_ulong();
  boost::asio::ip::address_v4 addr(a);
  return (addr);
}

boost::asio::ip::address_v4 operator&(const boost::asio::ip::address_v4& addr1,
                                      const boost::asio::ip::address_v4& addr2)
{
  uint32_t a;
  a = addr1.to_ulong() & addr2.to_ulong();
  boost::asio::ip::address_v4 addr(a);
  return (addr);
}

boost::asio::ip::address_v4 operator~(const boost::asio::ip::address_v4& addr1)
{
  uint32_t a;
  a = ~addr1.to_ulong();
  boost::asio::ip::address_v4 addr(a);
  return (addr);
}

boost::asio::ip::address_v6
operator|(const boost::asio::ip::address_v6& addr1,
          const boost::asio::ip::address_v6& addr2)
{
  boost::asio::ip::address_v6::bytes_type b1 = addr1.to_bytes();
  boost::asio::ip::address_v6::bytes_type b2 = addr2.to_bytes();

  for (boost::asio::ip::address_v6::bytes_type::size_type ii = 0;
       ii < b1.max_size(); ii++) {
    b1[ii] |= b2[ii];
  }

  boost::asio::ip::address_v6 addr(b1);
  return (addr);
}

boost::asio::ip::address_v6 operator&(const boost::asio::ip::address_v6& addr1,
                                      const boost::asio::ip::address_v6& addr2)
{
  boost::asio::ip::address_v6::bytes_type b1 = addr1.to_bytes();
  boost::asio::ip::address_v6::bytes_type b2 = addr2.to_bytes();

  for (boost::asio::ip::address_v6::bytes_type::size_type ii = 0;
       ii < b1.max_size(); ii++) {
    b1[ii] &= b2[ii];
  }

  boost::asio::ip::address_v6 addr(b1);
  return (addr);
}

boost::asio::ip::address_v6 operator~(const boost::asio::ip::address_v6& addr1)
{
  boost::asio::ip::address_v6::bytes_type b1 = addr1.to_bytes();

  for (boost::asio::ip::address_v6::bytes_type::size_type ii = 0;
       ii < b1.max_size(); ii++) {
    b1[ii] = ~b1[ii];
  }

  boost::asio::ip::address_v6 addr(b1);
  return (addr);
}
boost::asio::ip::address
operator|(const boost::asio::ip::address& addr1,
          const boost::asio::ip::address& addr2)
{
  if (addr1.is_v6())
    return (addr1.to_v6() | addr2.to_v6());
  else
    return (addr1.to_v4() | addr2.to_v4());
}

boost::asio::ip::address operator&(const boost::asio::ip::address& addr1,
                                   const boost::asio::ip::address& addr2)
{
  if (addr1.is_v6())
    return (addr1.to_v6() & addr2.to_v6());
  else
    return (addr1.to_v4() & addr2.to_v4());
}

boost::asio::ip::address operator~(const boost::asio::ip::address& addr1)
{
  if (addr1.is_v6())
    return ~(addr1.to_v6());
  else
    return ~(addr1.to_v4());
}

boost::asio::ip::address
route::prefix_t::mask() const
{
  if (m_addr.is_v6()) {
    boost::asio::ip::address_v6::bytes_type b =
      boost::asio::ip::address_v6::any().to_bytes();

    uint8_t n_bits = mask_width();

    for (boost::asio::ip::address_v6::bytes_type::size_type ii = 0;
         ii < b.max_size(); ii++) {
      for (int8_t bit = 7; bit >= 0 && n_bits; bit--) {
        b[ii] |= (1 << bit);
        n_bits--;
      }
      if (!n_bits)
        break;
    }

    return (boost::asio::ip::address_v6(b));
  } else {
    uint32_t a;

    a = ~((1 << (32 - mask_width())) - 1);

    return (boost::asio::ip::address_v4(a));
  }
}

route::prefix_t
route::prefix_t::low() const
{
  prefix_t pfx(*this);

  pfx.m_addr = pfx.m_addr & pfx.mask();

  return (pfx);
}

route::prefix_t
route::prefix_t::high() const
{
  prefix_t pfx(*this);

  pfx.m_addr = pfx.m_addr | ~pfx.mask();

  return (pfx);
}

/**
 * The all Zeros prefix
 */
const route::mprefix_t route::mprefix_t::ZERO;
const route::mprefix_t route::mprefix_t::ZEROv6;

route::mprefix_t::mprefix_t(const boost::asio::ip::address& gaddr, uint8_t len)
  : m_gaddr(gaddr)
  , m_saddr()
  , m_len(len)
{
}

route::mprefix_t::mprefix_t(const boost::asio::ip::address& gaddr)
  : m_gaddr(gaddr)
  , m_saddr()
  , m_len(VOM::mask_width(gaddr))
{
}

route::mprefix_t::mprefix_t(const boost::asio::ip::address& saddr,
                            const boost::asio::ip::address& gaddr)
  : m_gaddr(gaddr)
  , m_saddr(saddr)
  , m_len(2 * VOM::mask_width(gaddr))
{
}

route::mprefix_t::mprefix_t(const boost::asio::ip::address& saddr,
                            const boost::asio::ip::address& gaddr,
                            uint16_t len)
  : m_gaddr(gaddr)
  , m_saddr(saddr)
  , m_len(len)
{
}

route::mprefix_t::mprefix_t(const mprefix_t& o)
  : m_gaddr(o.m_gaddr)
  , m_saddr(o.m_saddr)
  , m_len(o.m_len)
{
}
route::mprefix_t::mprefix_t()
  : m_gaddr()
  , m_saddr()
  , m_len(0)
{
}

route::mprefix_t::~mprefix_t()
{
}

const boost::asio::ip::address&
route::mprefix_t::grp_address() const
{
  return (m_gaddr);
}

const boost::asio::ip::address&
route::mprefix_t::src_address() const
{
  return (m_saddr);
}

uint8_t
route::mprefix_t::mask_width() const
{
  return (m_len);
}

l3_proto_t
route::mprefix_t::l3_proto() const
{
  if (m_gaddr.is_v6()) {
    return (l3_proto_t::IPV6);
  } else {
    return (l3_proto_t::IPV4);
  }

  return (l3_proto_t::IPV4);
}

route::mprefix_t&
route::mprefix_t::operator=(const route::mprefix_t& o)
{
  m_gaddr = o.m_gaddr;
  m_saddr = o.m_saddr;
  m_len = o.m_len;

  return (*this);
}

bool
route::mprefix_t::operator<(const route::mprefix_t& o) const
{
  if (m_len == o.m_len) {
    if (m_saddr == o.m_saddr)
      return (m_gaddr < o.m_gaddr);
    else
      return (m_saddr < o.m_saddr);
  } else {
    return (m_len < o.m_len);
  }
}

bool
route::mprefix_t::operator==(const route::mprefix_t& o) const
{
  return (m_len == o.m_len && m_gaddr == o.m_gaddr && m_saddr == o.m_saddr);
}

bool
route::mprefix_t::operator!=(const route::mprefix_t& o) const
{
  return (!(*this == o));
}

std::string
route::mprefix_t::to_string() const
{
  std::ostringstream s;

  s << "(" << m_saddr.to_string() << "," << m_gaddr.to_string() << "/"
    << std::to_string(m_len) << ")";

  return (s.str());
}

}; // namespace VOM

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */
