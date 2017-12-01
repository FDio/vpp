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

#include "vom/interface.hpp"
#include "vom/interface_cmds.hpp"
#include "vom/interface_factory.hpp"
#include "vom/l3_binding_cmds.hpp"
#include "vom/logger.hpp"
#include "vom/prefix.hpp"

namespace VOM {
/**
 * A DB of all the interfaces, key on the name
 */
singular_db<interface::key_t, interface> interface::m_db;

/**
 * A DB of all the interfaces, key on VPP's handle
 */
std::map<handle_t, std::weak_ptr<interface>> interface::m_hdl_db;

interface::event_handler interface::m_evh;

/**
 * Construct a new object matching the desried state
 */
interface::interface(const std::string& name,
                     interface::type_t itf_type,
                     interface::admin_state_t itf_state)
  : m_hdl(handle_t::INVALID)
  , m_name(name)
  , m_type(itf_type)
  , m_state(itf_state)
  , m_table_id(route::DEFAULT_TABLE)
  , m_l2_address(l2_address_t::ZERO, rc_t::UNSET)
  , m_oper(oper_state_t::DOWN)
{
}

interface::interface(const std::string& name,
                     interface::type_t itf_type,
                     interface::admin_state_t itf_state,
                     const route_domain& rd)
  : m_hdl(handle_t::INVALID)
  , m_name(name)
  , m_type(itf_type)
  , m_rd(rd.singular())
  , m_state(itf_state)
  , m_table_id(m_rd->table_id())
  , m_l2_address(l2_address_t::ZERO, rc_t::UNSET)
  , m_oper(oper_state_t::DOWN)
{
}

interface::interface(const interface& o)
  : m_hdl(o.m_hdl)
  , m_name(o.m_name)
  , m_type(o.m_type)
  , m_rd(o.m_rd)
  , m_state(o.m_state)
  , m_table_id(o.m_table_id)
  , m_l2_address(o.m_l2_address)
  , m_oper(o.m_oper)
{
}

bool
interface::operator==(const interface& i) const
{
  return ((key() == i.key()) &&
          (m_l2_address.data() == i.m_l2_address.data()) &&
          (m_state == i.m_state) && (m_rd == i.m_rd) && (m_type == i.m_type) &&
          (m_oper == i.m_oper));
}

interface::event_listener::event_listener()
  : m_status(rc_t::NOOP)
{
}

HW::item<bool>&
interface::event_listener::status()
{
  return (m_status);
}

interface::stat_listener::stat_listener()
  : m_status(rc_t::NOOP)
{
}

HW::item<bool>&
interface::stat_listener::status()
{
  return (m_status);
}

/**
 * Return the interface type
 */
const interface::type_t&
interface::type() const
{
  return (m_type);
}

const handle_t&
interface::handle() const
{
  return (singular()->handle_i());
}

const handle_t&
interface::handle_i() const
{
  return (m_hdl.data());
}

const l2_address_t&
interface::l2_address() const
{
  return (m_l2_address.data());
}

interface::const_iterator_t
interface::cbegin()
{
  return m_db.cbegin();
}

interface::const_iterator_t
interface::cend()
{
  return m_db.cend();
}

void
interface::sweep()
{
  if (m_table_id && (m_table_id.data() != route::DEFAULT_TABLE)) {
    m_table_id.data() = route::DEFAULT_TABLE;
    HW::enqueue(
      new interface_cmds::set_table_cmd(m_table_id, l3_proto_t::IPV4, m_hdl));
    HW::enqueue(
      new interface_cmds::set_table_cmd(m_table_id, l3_proto_t::IPV6, m_hdl));
  }

  if (m_stats) {
    HW::enqueue(new interface_cmds::stats_disable_cmd(m_hdl.data()));
    m_stats.reset();
  }

  // If the interface is up, bring it down
  if (m_state && interface::admin_state_t::UP == m_state.data()) {
    m_state.data() = interface::admin_state_t::DOWN;
    HW::enqueue(new interface_cmds::state_change_cmd(m_state, m_hdl));
  }

  if (m_hdl) {
    std::queue<cmd*> cmds;
    HW::enqueue(mk_delete_cmd(cmds));
  }
  HW::write();
}

void
interface::replay()
{
  if (m_hdl) {
    std::queue<cmd*> cmds;
    HW::enqueue(mk_create_cmd(cmds));
  }

  if (m_state && interface::admin_state_t::UP == m_state.data()) {
    HW::enqueue(new interface_cmds::state_change_cmd(m_state, m_hdl));
  }

  if (m_table_id && (m_table_id.data() != route::DEFAULT_TABLE)) {
    HW::enqueue(
      new interface_cmds::set_table_cmd(m_table_id, l3_proto_t::IPV4, m_hdl));
    HW::enqueue(
      new interface_cmds::set_table_cmd(m_table_id, l3_proto_t::IPV6, m_hdl));
  }
}

interface::~interface()
{
  sweep();
  release();
}

void
interface::release()
{
  // not in the DB anymore.
  m_db.release(m_name, this);
}

std::string
interface::to_string() const
{
  std::ostringstream s;
  s << "interface:[" << m_name << " type:" << m_type.to_string()
    << " hdl:" << m_hdl.to_string() << " l2-address:["
    << m_l2_address.to_string() << "]";

  if (m_rd) {
    s << " rd:" << m_rd->to_string();
  }

  s << " admin-state:" << m_state.to_string()
    << " oper-state:" << m_oper.to_string() << "]";

  return (s.str());
}

const std::string&
interface::name() const
{
  return (m_name);
}

const interface::key_t&
interface::key() const
{
  return (name());
}

std::queue<cmd*>&
interface::mk_create_cmd(std::queue<cmd*>& q)
{
  if (type_t::LOOPBACK == m_type) {
    q.push(new interface_cmds::loopback_create_cmd(m_hdl, m_name));
  } else if (type_t::BVI == m_type) {
    q.push(new interface_cmds::loopback_create_cmd(m_hdl, m_name));
    q.push(new interface_cmds::set_tag(m_hdl, m_name));
  } else if (type_t::AFPACKET == m_type) {
    q.push(new interface_cmds::af_packet_create_cmd(m_hdl, m_name));
  } else if (type_t::TAP == m_type) {
    q.push(new interface_cmds::tap_create_cmd(m_hdl, m_name));
  } else {
    m_hdl.set(rc_t::OK);
  }

  return (q);
}

std::queue<cmd*>&
interface::mk_delete_cmd(std::queue<cmd*>& q)
{
  if ((type_t::LOOPBACK == m_type) || (type_t::BVI == m_type)) {
    q.push(new interface_cmds::loopback_delete_cmd(m_hdl));
  } else if (type_t::AFPACKET == m_type) {
    q.push(new interface_cmds::af_packet_delete_cmd(m_hdl, m_name));
  } else if (type_t::TAP == m_type) {
    q.push(new interface_cmds::tap_delete_cmd(m_hdl));
  }

  return (q);
}

void
interface::update(const interface& desired)
{
  /*
   * the desired state is always that the interface should be created
   */
  if (rc_t::OK != m_hdl.rc()) {
    std::queue<cmd*> cmds;
    HW::enqueue(mk_create_cmd(cmds));
    /*
     * interface create now, so we can barf early if it fails
     */
    HW::write();
  }

  /*
   * If the interface is not created do other commands should be issued
   */
  if (rc_t::OK != m_hdl.rc())
    return;

  /*
   * change the interface state to that which is deisred
   */
  if (m_state.update(desired.m_state)) {
    HW::enqueue(new interface_cmds::state_change_cmd(m_state, m_hdl));
  }

  /*
   * change the interface state to that which is deisred
   */
  if (m_l2_address.update(desired.m_l2_address)) {
    HW::enqueue(new interface_cmds::set_mac_cmd(m_l2_address, m_hdl));
  }

  /*
   * If the interface is mapped into a route domain, set VPP's
   * table ID
   */
  if (m_rd != desired.m_rd) {
    /*
     * changing route domains. need to remove all L3 bindings, swap the table
     * then reapply the bindings.
     */
    auto it = l3_binding::cbegin();

    while (it != l3_binding::cend()) {
      if (it->second.lock()->itf().key() == key())
        it->second.lock()->sweep();
      ++it;
    }
    m_rd = desired.m_rd;
    m_table_id.update(m_rd ? m_rd->table_id() : route::DEFAULT_TABLE);
    HW::enqueue(
      new interface_cmds::set_table_cmd(m_table_id, l3_proto_t::IPV4, m_hdl));
    HW::enqueue(
      new interface_cmds::set_table_cmd(m_table_id, l3_proto_t::IPV6, m_hdl));
    HW::write();

    it = l3_binding::cbegin();
    while (it != l3_binding::cend()) {
      if (it->second.lock()->itf().key() == key())
        it->second.lock()->replay(); //(*it->second.lock());
      ++it;
    }
  } else if (!m_table_id && m_rd) {
    HW::enqueue(
      new interface_cmds::set_table_cmd(m_table_id, l3_proto_t::IPV4, m_hdl));
    HW::enqueue(
      new interface_cmds::set_table_cmd(m_table_id, l3_proto_t::IPV6, m_hdl));
  }
}

void
interface::set(const l2_address_t& addr)
{
  assert(rc_t::UNSET == m_l2_address.rc());
  m_l2_address.set(rc_t::NOOP);
  m_l2_address.update(addr);
}

void
interface::set(const handle_t& hdl)
{
  m_hdl = hdl;
}

void
interface::set(const oper_state_t& state)
{
  m_oper = state;
}

void
interface::enable_stats_i(interface::stat_listener& el)
{
  if (!m_stats) {
    m_stats.reset(new interface_cmds::stats_enable_cmd(el, handle_i()));
    HW::enqueue(m_stats);
    HW::write();
  }
}

void
interface::enable_stats(interface::stat_listener& el)
{
  singular()->enable_stats_i(el);
}

std::shared_ptr<interface>
interface::singular_i() const
{
  return (m_db.find_or_add(key(), *this));
}

std::shared_ptr<interface>
interface::singular() const
{
  return singular_i();
}

std::shared_ptr<interface>
interface::find(const key_t& k)
{
  return (m_db.find(k));
}

std::shared_ptr<interface>
interface::find(const handle_t& handle)
{
  return (m_hdl_db[handle].lock());
}

void
interface::add(const key_t& key, const HW::item<handle_t>& item)
{
  std::shared_ptr<interface> sp = find(key);

  if (sp && item) {
    m_hdl_db[item.data()] = sp;
  }
}

void
interface::remove(const HW::item<handle_t>& item)
{
  m_hdl_db.erase(item.data());
}

void
interface::dump(std::ostream& os)
{
  m_db.dump(os);
}

void
interface::event_handler::handle_populate(const client_db::key_t& key)
{
  /*
   * dump VPP current states
   */
  std::shared_ptr<interface_cmds::dump_cmd> cmd =
    std::make_shared<interface_cmds::dump_cmd>();

  HW::enqueue(cmd);
  HW::write();

  for (auto& itf_record : *cmd) {
    std::shared_ptr<interface> itf =
      interface_factory::new_interface(itf_record.get_payload());

    if (itf && interface::type_t::LOCAL != itf->type()) {
      VOM_LOG(log_level_t::DEBUG) << "dump: " << itf->to_string();
      /*
       * Write each of the discovered interfaces into the OM,
       * but disable the HW Command q whilst we do, so that no
       * commands are sent to VPP
       */
      OM::commit(key, *itf);

      /**
       * Get the address configured on the interface
       */
      std::shared_ptr<l3_binding_cmds::dump_v4_cmd> dcmd =
        std::make_shared<l3_binding_cmds::dump_v4_cmd>(
          l3_binding_cmds::dump_v4_cmd(itf->handle()));

      HW::enqueue(dcmd);
      HW::write();

      for (auto& l3_record : *dcmd) {
        auto& payload = l3_record.get_payload();
        const route::prefix_t pfx(payload.is_ipv6, payload.ip,
                                  payload.prefix_length);

        VOM_LOG(log_level_t::DEBUG) << "dump: " << pfx.to_string();

        l3_binding l3(*itf, pfx);
        OM::commit(key, l3);
      }
    }
  }
}

interface::event_handler::event_handler()
{
  OM::register_listener(this);
  inspect::register_handler({ "interface", "intf" }, "interfaces", this);
}

void
interface::event_handler::handle_replay()
{
  m_db.replay();
}

dependency_t
interface::event_handler::order() const
{
  return (dependency_t::INTERFACE);
}

void
interface::event_handler::show(std::ostream& os)
{
  m_db.dump(os);
}

} // namespace VOM

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */
