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

#include "vom/acl_ethertype.hpp"
#include "vom/acl_ethertype_cmds.hpp"
#include "vom/singular_db_funcs.hpp"

namespace VOM {
namespace ACL {

ethertype_rule_t::ethertype_rule_t(const ethertype_t& eth,
                                   const direction_t& dir)
  : m_eth(eth)
  , m_dir(dir)
{
}

std::string
ethertype_rule_t::to_string() const
{
  std::ostringstream s;

  s << "["
    << "ethertype:" << m_eth.to_string() << " dir:" << m_dir.to_string()
    << "],";

  return (s.str());
}

bool
ethertype_rule_t::operator<(const ethertype_rule_t& other) const
{
  return (m_dir > other.m_dir);
}

bool
ethertype_rule_t::operator==(const ethertype_rule_t& other) const
{
  return (m_dir == other.m_dir && m_eth == other.m_eth);
}

uint16_t
ethertype_rule_t::getEthertype() const
{
  return m_eth.value();
}

const direction_t&
ethertype_rule_t::getDirection() const
{
  return m_dir;
}

/**
 * A DB of all acl ethertype bindings configs
 */
singular_db<interface::key_t, acl_ethertype> acl_ethertype::m_db;

acl_ethertype::event_handler acl_ethertype::m_evh;

acl_ethertype::acl_ethertype(const interface& itf,
                             const acl_ethertype::ethertype_rules_t& le)
  : m_itf(itf.singular())
  , m_le(le)
  , m_binding(true)
{
}

acl_ethertype::acl_ethertype(const acl_ethertype& o)
  : m_itf(o.m_itf)
  , m_le(o.m_le)
  , m_binding(o.m_binding)
{
}

acl_ethertype::~acl_ethertype()
{
  sweep();

  // not in the DB anymore.
  m_db.release(m_itf->key(), this);
}

void
acl_ethertype::sweep()
{
  if (m_binding) {
    HW::enqueue(new acl_ethertype_cmds::unbind_cmd(m_binding, m_itf->handle()));
  }
  HW::write();
}

const acl_ethertype::key_t&
acl_ethertype::key() const
{
  return (m_itf->key());
}

bool
acl_ethertype::operator==(const acl_ethertype& other) const
{
  return (m_itf->key() == other.m_itf->key() && m_le == other.m_le);
}

std::shared_ptr<acl_ethertype>
acl_ethertype::find(const key_t& key)
{
  return (m_db.find(key));
}

void
acl_ethertype::dump(std::ostream& os)
{
  db_dump(m_db, os);
}

void
acl_ethertype::replay()
{
  if (m_binding) {
    HW::enqueue(
      new acl_ethertype_cmds::bind_cmd(m_binding, m_itf->handle(), m_le));
  }
}

std::string
acl_ethertype::to_string() const
{
  std::ostringstream s;
  s << "Acl-Ethertype:" << m_itf->to_string() << " ethertype-rules:";
  auto it = m_le.cbegin();
  while (it != m_le.cend()) {
    s << it->to_string();
    ++it;
  }
  s << " rules-size:" << m_le.size();

  return (s.str());
}

void
acl_ethertype::update(const acl_ethertype& desired)
{
  /*
   * always update the instance with the latest rules
   */
  if (!m_binding || desired.m_le != m_le) {
    HW::enqueue(
      new acl_ethertype_cmds::bind_cmd(m_binding, m_itf->handle(), m_le));
  }

  m_le = desired.m_le;
}

std::shared_ptr<acl_ethertype>
acl_ethertype::find_or_add(const acl_ethertype& temp)
{
  return (m_db.find_or_add(temp.m_itf->key(), temp));
}

std::shared_ptr<acl_ethertype>
acl_ethertype::singular() const
{
  return find_or_add(*this);
}

acl_ethertype::event_handler::event_handler()
{
  OM::register_listener(this);
  inspect::register_handler({ "acl-ethertype" }, "ACL Ethertype bindings",
                            this);
}

void
acl_ethertype::event_handler::handle_replay()
{
  m_db.replay();
}

void
acl_ethertype::event_handler::handle_populate(const client_db::key_t& key)
{
  /*
   * dump VPP acl ethertypes
   */
  std::shared_ptr<acl_ethertype_cmds::dump_cmd> cmd =
    std::make_shared<acl_ethertype_cmds::dump_cmd>(~0);

  HW::enqueue(cmd);
  HW::write();

  for (auto& record : *cmd) {
    auto& payload = record.get_payload();
    handle_t hdl(payload.sw_if_index);
    std::shared_ptr<interface> itf = interface::find(hdl);
    uint8_t n_input = payload.n_input;
    uint8_t count = payload.count;
    ethertype_rules_t ler;
    if (itf) {
      for (int i = 0; i < count; i++) {
        ethertype_t e = ethertype_t::from_numeric_val(payload.whitelist[i]);
        if (n_input) {
          ethertype_rule_t er(e, direction_t::INPUT);
          ler.insert(er);
          n_input--;
        } else {
          ethertype_rule_t er(e, direction_t::OUTPUT);
          ler.insert(er);
        }
      }
      if (!ler.empty()) {
        acl_ethertype a_e(*itf, ler);
        VOM_LOG(log_level_t::DEBUG) << "ethertype dump: " << a_e.to_string();
        OM::commit(key, a_e);
      }
    }
  }
}

dependency_t
acl_ethertype::event_handler::order() const
{
  return (dependency_t::BINDING);
}

void
acl_ethertype::event_handler::show(std::ostream& os)
{
  db_dump(m_db, os);
}
};
};
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */
