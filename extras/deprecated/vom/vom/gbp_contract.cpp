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

#include "vom/gbp_contract.hpp"
#include "vom/api_types.hpp"
#include "vom/gbp_contract_cmds.hpp"
#include "vom/singular_db_funcs.hpp"

namespace VOM {

singular_db<gbp_contract::key_t, gbp_contract> gbp_contract::m_db;

gbp_contract::event_handler gbp_contract::m_evh;

gbp_contract::gbp_contract(scope_t scope,
                           sclass_t sclass,
                           sclass_t dclass,
                           const ACL::l3_list& acl,
                           const gbp_rules_t& rules,
                           const ethertype_set_t& allowed_ethertypes)
  : m_hw(false)
  , m_scope(scope)
  , m_sclass(sclass)
  , m_dclass(dclass)
  , m_acl(acl.singular())
  , m_gbp_rules(rules)
  , m_allowed_ethertypes(allowed_ethertypes)
{
}

gbp_contract::gbp_contract(const gbp_contract& gbpc)
  : m_hw(gbpc.m_hw)
  , m_scope(gbpc.m_scope)
  , m_sclass(gbpc.m_sclass)
  , m_dclass(gbpc.m_dclass)
  , m_acl(gbpc.m_acl)
  , m_gbp_rules(gbpc.m_gbp_rules)
  , m_allowed_ethertypes(gbpc.m_allowed_ethertypes)
{
}

gbp_contract::~gbp_contract()
{
  sweep();

  // not in the DB anymore.
  m_db.release(key(), this);
}

const gbp_contract::key_t
gbp_contract::key() const
{
  return (std::make_tuple(m_scope, m_sclass, m_dclass));
}

bool
gbp_contract::operator==(const gbp_contract& gbpc) const
{
  return ((key() == gbpc.key()) && (m_acl->handle() == gbpc.m_acl->handle()));
}

void
gbp_contract::sweep()
{
  if (m_hw) {
    HW::enqueue(
      new gbp_contract_cmds::delete_cmd(m_hw, m_scope, m_sclass, m_dclass));
  }
  HW::write();
}

void
gbp_contract::replay()
{
  if (m_hw) {
    HW::enqueue(new gbp_contract_cmds::create_cmd(
      m_hw, m_scope, m_sclass, m_dclass, m_acl->handle(), m_gbp_rules,
      m_allowed_ethertypes));
  }
}

std::string
gbp_contract::to_string() const
{
  std::ostringstream s;
  s << "gbp-contract:[{" << m_scope << ", " << m_sclass << ", " << m_dclass
    << "}, " << m_acl->to_string();
  if (m_gbp_rules.size()) {
    auto it = m_gbp_rules.cbegin();
    while (it != m_gbp_rules.cend()) {
      s << it->to_string();
      ++it;
    }
  }
  s << "[ethertype:";
  for (auto e : m_allowed_ethertypes)
    s << " " << e;
  s << "]]";

  return (s.str());
}

void
gbp_contract::update(const gbp_contract& r)
{
  /*
   * create the table if it is not yet created
   */
  if (rc_t::OK != m_hw.rc()) {
    HW::enqueue(new gbp_contract_cmds::create_cmd(
      m_hw, m_scope, m_sclass, m_dclass, m_acl->handle(), m_gbp_rules,
      m_allowed_ethertypes));
  }
}

std::shared_ptr<gbp_contract>
gbp_contract::find_or_add(const gbp_contract& temp)
{
  return (m_db.find_or_add(temp.key(), temp));
}

std::shared_ptr<gbp_contract>
gbp_contract::find(const key_t& k)
{
  return (m_db.find(k));
}

std::shared_ptr<gbp_contract>
gbp_contract::singular() const
{
  return find_or_add(*this);
}

void
gbp_contract::dump(std::ostream& os)
{
  db_dump(m_db, os);
}

gbp_contract::event_handler::event_handler()
{
  OM::register_listener(this);
  inspect::register_handler({ "gbp-contract" }, "GBP Contract", this);
}

void
gbp_contract::event_handler::handle_replay()
{
  m_db.replay();
}

void
gbp_contract::event_handler::handle_populate(const client_db::key_t& key)
{
  std::shared_ptr<gbp_contract_cmds::dump_cmd> cmd =
    std::make_shared<gbp_contract_cmds::dump_cmd>();

  HW::enqueue(cmd);
  HW::write();

  for (auto& record : *cmd) {
    auto& payload = record.get_payload();

    std::shared_ptr<ACL::l3_list> acl =
      ACL::l3_list::find(payload.contract.acl_index);

    if (acl) {
      gbp_contract::gbp_rules_t rules;

      for (uint8_t i = 0; i < payload.contract.n_rules; i++) {
        const gbp_rule::action_t action =
          gbp_rule::action_t::from_int(payload.contract.rules[i].action);
        const gbp_rule::hash_mode_t hm = gbp_rule::hash_mode_t::from_int(
          payload.contract.rules[i].nh_set.hash_mode);
        gbp_rule::next_hops_t nhs;
        for (u8 j = 0; j < payload.contract.rules[i].nh_set.n_nhs; j++) {
          gbp_rule::next_hop_t nh(
            from_api(payload.contract.rules[i].nh_set.nhs[j].ip),
            from_api(payload.contract.rules[i].nh_set.nhs[j].mac),
            payload.contract.rules[i].nh_set.nhs[j].bd_id,
            payload.contract.rules[i].nh_set.nhs[j].rd_id);
          nhs.insert(nh);
        }
        gbp_rule::next_hop_set_t next_hop_set(hm, nhs);
        gbp_rule gr(i, next_hop_set, action);
        rules.insert(gr);
      }

      ethertype_set_t allowed_ethertypes;
      u8 *data, n_et;
      u16* et;

      data = (((u8*)&payload.contract.n_ether_types) +
              (sizeof(payload.contract.rules[0]) * payload.contract.n_rules));
      n_et = *data;
      et = (u16*)(++data);

      for (uint8_t i = 0; i < n_et; i++) {
        allowed_ethertypes.insert(ethertype_t::from_numeric_val(et[i]));
      }

      gbp_contract gbpc(payload.contract.scope, payload.contract.sclass,
                        payload.contract.dclass, *acl, rules,
                        allowed_ethertypes);
      OM::commit(key, gbpc);
      VOM_LOG(log_level_t::DEBUG) << "read: " << gbpc.to_string();
    } else {
      VOM_LOG(log_level_t::ERROR) << " no ACL:" << payload.contract.acl_index;
    }
  }
}

dependency_t
gbp_contract::event_handler::order() const
{
  return (dependency_t::ENTRY);
}

void
gbp_contract::event_handler::show(std::ostream& os)
{
  db_dump(m_db, os);
}

std::ostream&
operator<<(std::ostream& os, const gbp_contract::key_t& key)
{
  os << "{ " << std::get<0>(key) << "," << std::get<1>(key) << ", "
     << std::get<2>(key) << "}";

  return (os);
}

} // namespace VOM

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */
