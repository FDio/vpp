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

#include "vom/nat_binding.hpp"
#include "vom/cmd.hpp"
#include "vom/nat_binding_cmds.hpp"
#include "vom/singular_db_funcs.hpp"

namespace VOM {
singular_db<const nat_binding::key_t, nat_binding> nat_binding::m_db;

nat_binding::event_handler nat_binding::m_evh;

const nat_binding::zone_t nat_binding::zone_t::INSIDE(0, "inside");
const nat_binding::zone_t nat_binding::zone_t::OUTSIDE(0, "outside");

nat_binding::zone_t::zone_t(int v, const std::string s)
  : enum_base(v, s)
{
}
const nat_binding::zone_t&
nat_binding::zone_t::from_vpp(u8 is_inside)
{
  if (is_inside)
    return zone_t::INSIDE;
  return zone_t::OUTSIDE;
}

/**
 * Construct a new object matching the desried state
 */
nat_binding::nat_binding(const interface& itf,
                         const direction_t& dir,
                         const l3_proto_t& proto,
                         const zone_t& zone)
  : m_binding(false)
  , m_itf(itf.singular())
  , m_dir(dir)
  , m_proto(proto)
  , m_zone(zone)
{
}

nat_binding::nat_binding(const nat_binding& o)
  : m_binding(o.m_binding)
  , m_itf(o.m_itf)
  , m_dir(o.m_dir)
  , m_proto(o.m_proto)
  , m_zone(o.m_zone)
{
}

nat_binding::~nat_binding()
{
  sweep();
  m_db.release(key(), this);
}

const nat_binding::key_t
nat_binding::key() const
{
  return (make_tuple(m_itf->key(), m_dir, m_proto));
}

bool
nat_binding::operator==(const nat_binding& n) const
{
  return ((key() == n.key()) && (m_zone == n.m_zone));
}

void
nat_binding::sweep()
{
  if (m_binding) {
    if (direction_t::INPUT == m_dir) {
      if (l3_proto_t::IPV4 == m_proto) {
        HW::enqueue(new nat_binding_cmds::unbind_44_input_cmd(
          m_binding, m_itf->handle(), m_zone));
      } else {
        HW::enqueue(new nat_binding_cmds::unbind_66_input_cmd(
          m_binding, m_itf->handle(), m_zone));
      }
    } else {
      if (l3_proto_t::IPV4 == m_proto) {
        HW::enqueue(new nat_binding_cmds::unbind_44_output_cmd(
          m_binding, m_itf->handle(), m_zone));
      } else {
        VOM_LOG(log_level_t::ERROR) << "NAT 66 output feature not supported";
      }
    }
  }
  HW::write();
}

void
nat_binding::replay()
{
  if (m_binding) {
    if (direction_t::INPUT == m_dir) {
      if (l3_proto_t::IPV4 == m_proto) {
        HW::enqueue(new nat_binding_cmds::bind_44_input_cmd(
          m_binding, m_itf->handle(), m_zone));
      } else {
        HW::enqueue(new nat_binding_cmds::bind_66_input_cmd(
          m_binding, m_itf->handle(), m_zone));
      }
    } else {
      if (l3_proto_t::IPV4 == m_proto) {
        HW::enqueue(new nat_binding_cmds::bind_44_output_cmd(
          m_binding, m_itf->handle(), m_zone));
      } else {
        VOM_LOG(log_level_t::ERROR) << "NAT 66 output feature not supported";
      }
    }
  }
}

void
nat_binding::update(const nat_binding& desired)
{
  /*
 * the desired state is always that the interface should be created
 */
  if (!m_binding) {
    if (direction_t::INPUT == m_dir) {
      if (l3_proto_t::IPV4 == m_proto) {
        HW::enqueue(new nat_binding_cmds::bind_44_input_cmd(
          m_binding, m_itf->handle(), m_zone));
      } else {
        HW::enqueue(new nat_binding_cmds::bind_66_input_cmd(
          m_binding, m_itf->handle(), m_zone));
      }
    } else {
      if (l3_proto_t::IPV4 == m_proto) {
        HW::enqueue(new nat_binding_cmds::bind_44_output_cmd(
          m_binding, m_itf->handle(), m_zone));
      } else {
        VOM_LOG(log_level_t::ERROR) << "NAT 66 output feature not supported";
      }
    }
  }
}

std::string
nat_binding::to_string() const
{
  std::ostringstream s;
  s << "nat-binding:[" << m_itf->to_string()
    << " direction:" << m_dir.to_string() << " proto:" << m_proto.to_string()
    << " zone:" << m_zone.to_string() << "]";

  return (s.str());
}

std::shared_ptr<nat_binding>
nat_binding::find_or_add(const nat_binding& temp)
{
  return (m_db.find_or_add(temp.key(), temp));
}

std::shared_ptr<nat_binding>
nat_binding::find(const key_t& key)
{
  return (m_db.find(key));
}

std::shared_ptr<nat_binding>
nat_binding::singular() const
{
  return find_or_add(*this);
}

void
nat_binding::dump(std::ostream& os)
{
  db_dump(m_db, os);
}

std::ostream&
operator<<(std::ostream& os, const nat_binding::key_t& key)
{
  os << "[" << std::get<0>(key) << ", " << std::get<1>(key) << ", "
     << std::get<2>(key) << "]";

  return (os);
}

nat_binding::event_handler::event_handler()
{
  OM::register_listener(this);
  inspect::register_handler({ "nat-binding" }, "NAT bindings", this);
}

void
nat_binding::event_handler::handle_replay()
{
  m_db.replay();
}

void
nat_binding::event_handler::handle_populate(const client_db::key_t& key)
{
  std::shared_ptr<nat_binding_cmds::dump_input_44_cmd> icmd =
    std::make_shared<nat_binding_cmds::dump_input_44_cmd>();

  HW::enqueue(icmd);
  HW::write();

  for (auto& record : *icmd) {
    auto& payload = record.get_payload();

    std::shared_ptr<interface> itf = interface::find(payload.sw_if_index);

    if (itf) {
      nat_binding nb(*itf, direction_t::INPUT, l3_proto_t::IPV4,
                     zone_t::from_vpp(payload.flags & NAT_IS_INSIDE));
      OM::commit(key, nb);
    } else {
      VOM_LOG(log_level_t::ERROR) << "nat-binding-input-44 no sw_if_index: "
                                  << payload.sw_if_index;
    }
  }

  std::shared_ptr<nat_binding_cmds::dump_output_44_cmd> ocmd =
    std::make_shared<nat_binding_cmds::dump_output_44_cmd>();

  HW::enqueue(ocmd);
  HW::write();

  for (auto& record : *ocmd) {
    auto& payload = record.get_payload();

    std::shared_ptr<interface> itf = interface::find(payload.sw_if_index);
    if (itf) {
      nat_binding nb(*itf, direction_t::OUTPUT, l3_proto_t::IPV4,
                     zone_t::from_vpp(payload.flags & NAT_IS_INSIDE));
      OM::commit(key, nb);
    } else {
      VOM_LOG(log_level_t::ERROR) << "nat-binding-output-44 no sw_if_index: "
                                  << payload.sw_if_index;
    }
  }

  std::shared_ptr<nat_binding_cmds::dump_input_66_cmd> i6cmd =
    std::make_shared<nat_binding_cmds::dump_input_66_cmd>();

  HW::enqueue(i6cmd);
  HW::write();

  for (auto& record : *i6cmd) {
    auto& payload = record.get_payload();

    std::shared_ptr<interface> itf = interface::find(payload.sw_if_index);
    if (itf) {
      nat_binding nb(*itf, direction_t::INPUT, l3_proto_t::IPV6,
                     zone_t::from_vpp(payload.flags & NAT_IS_INSIDE));
      OM::commit(key, nb);
    } else {
      VOM_LOG(log_level_t::ERROR) << "nat-binding-input-66 no sw_if_index: "
                                  << payload.sw_if_index;
    }
  }
}

dependency_t
nat_binding::event_handler::order() const
{
  return (dependency_t::BINDING);
}

void
nat_binding::event_handler::show(std::ostream& os)
{
  db_dump(m_db, os);
}
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */
